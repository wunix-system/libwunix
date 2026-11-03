use crate::time::{clock_realtime, clock_set_realtime, Timespec};
use crate::{close, recvfrom, sendto, socket, SockAddrIn, AF_INET, SOCK_DGRAM};
use super::dns_proto::DnsError;
use super::resolve_host;

/// Стандартный порт протокола NTP/SNTP в сети UDP (RFC 5905)
pub const NTP_PORT: u16 = 123;

/// Размер базового пакета NTPv4 заголовка (ровно 48 байт)
pub const NTP_PACKET_LEN: usize = 48;

/// Разница во времени между эпохой NTP (1 января 1900 года)
/// и Unix Epoch (1 января 1970 года) в секундах.
/// Ровно 70 лет, включая 17 високосных годов: (70 * 365 + 17) * 86400 = 2 208 988 800 сек.
pub const NTP_TO_UNIX_OFFSET: u64 = 2_208_988_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeapIndicator {
    NoWarning = 0,
    LastMinute61Sec = 1,
    LastMinute59Sec = 2,
    Alarm = 3,
}

impl LeapIndicator {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::NoWarning,
            1 => Self::LastMinute61Sec,
            2 => Self::LastMinute59Sec,
            _ => Self::Alarm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpMode {
    Reserved = 0,
    SymmetricActive = 1,
    SymmetricPassive = 2,
    Client = 3,
    Server = 4,
    Broadcast = 5,
    Control = 6,
    Private = 7,
}

impl NtpMode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::SymmetricActive,
            2 => Self::SymmetricPassive,
            3 => Self::Client,
            4 => Self::Server,
            5 => Self::Broadcast,
            6 => Self::Control,
            7 => Self::Private,
            _ => Self::Reserved,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpError {
    IoError,
    Timeout,
    InvalidPacket,
    ServerUnsynchronized,
    StratumZero,
    DnsFailed,
}

impl From<DnsError> for NtpError {
    fn from(_: DnsError) -> Self {
        Self::DnsFailed
    }
}

/// 64-битная временная метка формата NTP:
/// 32 бита целых секунд с 1900-01-01 и 32 бита долей секунды (разрешение ~232 пикосекунды).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NtpTimestamp {
    pub seconds: u32,
    pub fraction: u32,
}

impl NtpTimestamp {
    pub const ZERO: Self = Self { seconds: 0, fraction: 0 };

    pub fn to_timespec(&self) -> Timespec {
        if (self.seconds as u64) < NTP_TO_UNIX_OFFSET {
            Timespec { tv_sec: 0, tv_nsec: 0 }
        } else {
            let unix_sec = (self.seconds as u64 - NTP_TO_UNIX_OFFSET) as i64;
            // Умножение на 1 000 000 000 и деление на 2^32 для перевода долей в наносекунды
            let unix_nsec = (((self.fraction as u64) * 1_000_000_000) >> 32) as i64;
            Timespec {
                tv_sec: unix_sec,
                tv_nsec: unix_nsec,
            }
        }
    }

    pub fn from_timespec(ts: &Timespec) -> Self {
        if ts.tv_sec < 0 {
            Self::ZERO
        } else {
            let ntp_sec = (ts.tv_sec as u64 + NTP_TO_UNIX_OFFSET) as u32;
            let ntp_frac = (((ts.tv_nsec as u64) << 32) / 1_000_000_000) as u32;
            Self {
                seconds: ntp_sec,
                fraction: ntp_frac,
            }
        }
    }
}

/// Распарсенный сетевой пакет протокола NTPv4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpPacket {
    pub leap: LeapIndicator,
    pub version: u8,
    pub mode: NtpMode,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub ref_id: [u8; 4],
    pub ref_timestamp: NtpTimestamp,
    pub orig_timestamp: NtpTimestamp,
    pub recv_timestamp: NtpTimestamp,
    pub trans_timestamp: NtpTimestamp,
}

impl NtpPacket {
    /// Формирует стандартный клиентский запрос SNTP (Mode 3, Version 4)
    pub fn create_client_request(tx_ts: &Timespec) -> [u8; NTP_PACKET_LEN] {
        let mut buf = [0u8; NTP_PACKET_LEN];
        // LI = 0 (без предупреждений), VN = 4 (NTPv4), Mode = 3 (Client)
        // 0b00_100_011 = 0x23
        buf[0] = 0x23;
        // Stratum = 0, Poll = 6 (64 сек), Precision = 0xE7 (-25, ~30 нс)
        buf[2] = 6;
        buf[3] = 0xE7;

        let ntp_tx = NtpTimestamp::from_timespec(tx_ts);
        buf[40..44].copy_from_slice(&ntp_tx.seconds.to_be_bytes());
        buf[44..48].copy_from_slice(&ntp_tx.fraction.to_be_bytes());
        buf
    }

    /// Декодирует сырой буфер входящей дейтаграммы NTP
    pub fn decode(buf: &[u8]) -> Result<Self, NtpError> {
        if buf.len() < NTP_PACKET_LEN {
            return Err(NtpError::InvalidPacket);
        }

        let b0 = buf[0];
        let leap = LeapIndicator::from_u8((b0 >> 6) & 0x03);
        let version = (b0 >> 3) & 0x07;
        let mode = NtpMode::from_u8(b0 & 0x07);

        // Проверяем версию протокола: поддерживаются NTPv3 (3) и NTPv4 (4)
        if version != 3 && version != 4 {
            return Err(NtpError::InvalidPacket);
        }

        // Ответ от валидного сервера должен иметь режим Server (4) или Broadcast (5)
        if mode != NtpMode::Server && mode != NtpMode::Broadcast {
            return Err(NtpError::InvalidPacket);
        }

        let stratum = buf[1];
        // Stratum 0 — специальный пакет KoD (Kiss-o'-Death) или ошибка синхронизации
        if stratum == 0 {
            return Err(NtpError::StratumZero);
        }
        // Stratum 16 означает, что сам сервер не синхронизирован
        if stratum >= 16 {
            return Err(NtpError::ServerUnsynchronized);
        }

        let poll = buf[2] as i8;
        let precision = buf[3] as i8;

        let root_delay = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let root_dispersion = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let ref_id = [buf[12], buf[13], buf[14], buf[15]];

        let parse_ts = |offset: usize| -> NtpTimestamp {
            let sec = u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
            let frac = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
            NtpTimestamp { seconds: sec, fraction: frac }
        };

        let ref_timestamp = parse_ts(16);
        let orig_timestamp = parse_ts(24);
        let recv_timestamp = parse_ts(32);
        let trans_timestamp = parse_ts(40);

        // Поле Transmit Timestamp не может быть нулевым у рабочего сервера
        if trans_timestamp.seconds == 0 {
            return Err(NtpError::InvalidPacket);
        }

        Ok(Self {
            leap,
            version,
            mode,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            ref_id,
            ref_timestamp,
            orig_timestamp,
            recv_timestamp,
            trans_timestamp,
        })
    }
}

/// Результат успешного опроса NTP-сервера с расчетом точного смещения часов
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpResult {
    pub server_ip: [u8; 4],
    pub stratum: u8,
    pub leap: LeapIndicator,
    pub version: u8,
    pub poll: i8,
    pub precision: i8,
    pub ref_id: [u8; 4],
    pub root_delay_ms: u32,
    pub root_disp_ms: u32,
    /// Смещение часов (Offset = ((t2 - t1) + (t3 - t4)) / 2)
    pub offset_sec: i64,
    pub offset_nsec: i64,
    /// Задержка передачи по сети в миллисекундах (Delay = (t4 - t1) - (t3 - t2))
    pub delay_ms: u64,
    /// Время на сервере при передаче ответа (t3)
    pub server_time: Timespec,
    /// Расчетное реальное системное время на момент завершения замера
    pub adjusted_time: Timespec,
}

/// Рассчитывает смещение часов и круговую сетевую задержку согласно RFC 4330 / RFC 5905:
/// t1: клиент отправил запрос
/// t2: сервер принял запрос
/// t3: сервер отправил ответ
/// t4: клиент принял ответ
pub fn calculate_offset_and_delay(
    t1: &Timespec,
    t2: &Timespec,
    t3: &Timespec,
    t4: &Timespec,
) -> (i64, i64, u64) {
    let to_ns = |ts: &Timespec| -> i128 {
        (ts.tv_sec as i128) * 1_000_000_000 + (ts.tv_nsec as i128)
    };

    let n1 = to_ns(t1);
    let n2 = to_ns(t2);
    let n3 = to_ns(t3);
    let n4 = to_ns(t4);

    // Смещение: offset = ((t2 - t1) + (t3 - t4)) / 2
    let offset_ns = ((n2 - n1) + (n3 - n4)) / 2;

    // Круговая задержка: delay = (t4 - t1) - (t3 - n2)
    let roundtrip_ns = (n4 - n1) - (n3 - n2);
    let delay_ms = if roundtrip_ns > 0 {
        (roundtrip_ns / 1_000_000) as u64
    } else {
        0
    };

    let offset_sec = (offset_ns / 1_000_000_000) as i64;
    let offset_nsec = (offset_ns % 1_000_000_000) as i64;

    (offset_sec, offset_nsec, delay_ms)
}

/// Отправляет сетевой запрос SNTP к указанному IPv4 адресу сервера времени на заданный UDP порт.
pub fn query_ntp_server_port(server_ip: [u8; 4], port: u16) -> Result<NtpResult, NtpError> {
    let fd = socket(AF_INET, SOCK_DGRAM, 0);
    if fd < 0 {
        return Err(NtpError::IoError);
    }

    let t1 = clock_realtime();
    let tx_buf = NtpPacket::create_client_request(&t1);
    let target = SockAddrIn::new_v4(server_ip, port);

    let sent = sendto(fd as u64, &tx_buf, 0, Some(&target));
    if sent < 0 {
        close(fd as u64);
        return Err(NtpError::IoError);
    }

    let mut rx_buf = [0u8; 256];
    let mut from_addr = SockAddrIn::default();
    let n = recvfrom(fd as u64, &mut rx_buf, 0, Some(&mut from_addr));
    let t4 = clock_realtime();
    close(fd as u64);

    if n < 0 {
        if n == -110 {
            return Err(NtpError::Timeout);
        }
        return Err(NtpError::IoError);
    }

    let packet = NtpPacket::decode(&rx_buf[..n as usize])?;

    let t2 = packet.recv_timestamp.to_timespec();
    let t3 = packet.trans_timestamp.to_timespec();

    // Если t2 сервер вернул нулевым (некоторые простые SNTP-серверы), используем приближение t2 = t3
    let actual_t2 = if t2.tv_sec == 0 { t3 } else { t2 };

    let (offset_sec, offset_nsec, delay_ms) = calculate_offset_and_delay(&t1, &actual_t2, &t3, &t4);

    // Рассчитываем точное время: t4 + offset
    let mut adj_sec = t4.tv_sec + offset_sec;
    let mut adj_nsec = t4.tv_nsec + offset_nsec;
    if adj_nsec >= 1_000_000_000 {
        adj_sec += 1;
        adj_nsec -= 1_000_000_000;
    } else if adj_nsec < 0 {
        adj_sec -= 1;
        adj_nsec += 1_000_000_000;
    }

    let root_delay_ms = ((packet.root_delay as u64 * 1000) >> 16) as u32;
    let root_disp_ms = ((packet.root_dispersion as u64 * 1000) >> 16) as u32;

    Ok(NtpResult {
        server_ip,
        stratum: packet.stratum,
        leap: packet.leap,
        version: packet.version,
        poll: packet.poll,
        precision: packet.precision,
        ref_id: packet.ref_id,
        root_delay_ms,
        root_disp_ms,
        offset_sec,
        offset_nsec,
        delay_ms,
        server_time: t3,
        adjusted_time: Timespec {
            tv_sec: adj_sec,
            tv_nsec: adj_nsec,
        },
    })
}

/// Отправляет сетевой запрос SNTP к указанному IPv4 адресу сервера времени на стандартный порт 123.
pub fn query_ntp_server(server_ip: [u8; 4]) -> Result<NtpResult, NtpError> {
    query_ntp_server_port(server_ip, NTP_PORT)
}

/// Выполняет синхронизацию с хостом по имени и порту (с предварительным DNS-разрешением).
/// Если строка хоста содержит двоеточие (например, "10.0.2.2:18123"), порт извлекается из адреса.
pub fn query_ntp_host_port(host: &str, default_port: u16) -> Result<NtpResult, NtpError> {
    let (clean_host, port) = if let Some(pos) = host.rfind(':') {
        let h = &host[..pos];
        let p_str = &host[pos + 1..];
        let mut p = 0u16;
        for &b in p_str.as_bytes() {
            if b >= b'0' && b <= b'9' {
                p = p.saturating_mul(10).saturating_add((b - b'0') as u16);
            } else {
                break;
            }
        }
        (h, if p > 0 { p } else { default_port })
    } else {
        (host, default_port)
    };

    let ip = resolve_host(clean_host)?;
    query_ntp_server_port(ip, port)
}

/// Выполняет синхронизацию с хостом по имени (стандартный порт 123 или порт из host:port)
pub fn query_ntp_host(host: &str) -> Result<NtpResult, NtpError> {
    query_ntp_host_port(host, NTP_PORT)
}

/// Применяет полученное от NTP-сервера точное время к системным часам ядра
pub fn sync_system_time(res: &NtpResult) -> Result<(), &'static str> {
    if clock_set_realtime(&res.adjusted_time) == 0 {
        Ok(())
    } else {
        Err("clock_set_realtime: permission denied or failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_timestamp_conversions() {
        // Проверяем известную точку во времени:
        // 2026-10-30 10:00:23 UTC -> Unix timestamp 1793354423
        let ts = Timespec {
            tv_sec: 1793354423,
            tv_nsec: 500_000_000,
        };
        let ntp = NtpTimestamp::from_timespec(&ts);
        assert_eq!(ntp.seconds, (1793354423 + NTP_TO_UNIX_OFFSET) as u32);
        // 0.5 секунды = 2^31 = 0x8000_0000
        assert!((ntp.fraction as i64 - 0x8000_0000i64).abs() < 100);

        let roundtrip = ntp.to_timespec();
        assert_eq!(roundtrip.tv_sec, 1793354423);
        assert!((roundtrip.tv_nsec - 500_000_000).abs() < 1000);
    }

    #[test]
    fn test_client_request_packet() {
        let now = Timespec {
            tv_sec: 1793354423,
            tv_nsec: 123_456_789,
        };
        let pkt = NtpPacket::create_client_request(&now);
        assert_eq!(pkt.len(), 48);
        assert_eq!(pkt[0], 0x23); // LI=0, VN=4, Mode=3 (Client)
        assert_eq!(pkt[2], 6); // Poll 6
        assert_eq!(pkt[3], 0xE7); // Precision

        // Transmit timestamp должен быть записан в конце (байты 40..48)
        let ntp_tx = NtpTimestamp::from_timespec(&now);
        let sec = u32::from_be_bytes([pkt[40], pkt[41], pkt[42], pkt[43]]);
        assert_eq!(sec, ntp_tx.seconds);
    }

    #[test]
    fn test_decode_server_response() {
        let mut buf = [0u8; 48];
        // LI=0, VN=4, Mode=4 (Server): (0 << 6) | (4 << 3) | 4 = 0x24
        buf[0] = 0x24;
        buf[1] = 2; // Stratum 2
        buf[2] = 6; // Poll
        buf[3] = 0xE8; // Precision
        buf[12] = b'G'; buf[13] = b'P'; buf[14] = b'S'; buf[15] = 0; // Ref ID

        let ts = Timespec {
            tv_sec: 1793354423,
            tv_nsec: 0,
        };
        let ntp_ts = NtpTimestamp::from_timespec(&ts);
        buf[40..44].copy_from_slice(&ntp_ts.seconds.to_be_bytes());
        buf[44..48].copy_from_slice(&ntp_ts.fraction.to_be_bytes());

        let decoded = NtpPacket::decode(&buf).expect("decode failed");
        assert_eq!(decoded.leap, LeapIndicator::NoWarning);
        assert_eq!(decoded.version, 4);
        assert_eq!(decoded.mode, NtpMode::Server);
        assert_eq!(decoded.stratum, 2);
        assert_eq!(&decoded.ref_id, b"GPS\0");
        assert_eq!(decoded.trans_timestamp.seconds, ntp_ts.seconds);
    }

    #[test]
    fn test_calculate_offset_and_delay() {
        // t1: 100.000s, t2: 100.010s, t3: 100.012s, t4: 100.024s
        // Задержка сети: (100.024 - 100.000) - (100.012 - 100.010) = 0.024 - 0.002 = 0.022s (22 ms)
        // Смещение: ((100.010 - 100.000) + (100.012 - 100.024)) / 2 = (0.010 - 0.012) / 2 = -0.001s (-1 ms)
        let t1 = Timespec { tv_sec: 100, tv_nsec: 0 };
        let t2 = Timespec { tv_sec: 100, tv_nsec: 10_000_000 };
        let t3 = Timespec { tv_sec: 100, tv_nsec: 12_000_000 };
        let t4 = Timespec { tv_sec: 100, tv_nsec: 24_000_000 };

        let (off_sec, off_nsec, delay_ms) = calculate_offset_and_delay(&t1, &t2, &t3, &t4);
        assert_eq!(off_sec, 0);
        assert_eq!(off_nsec, -1_000_000); // -1 ms
        assert_eq!(delay_ms, 22); // 22 ms
    }
}
