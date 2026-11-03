#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    BufferTooSmall,
    InvalidDomain,
    PacketTooShort,
    InvalidHeader,
    ServerFailure,
    NameError, // NXDOMAIN (домен не существует)
    Refused,
    NoAddresses, // Записей A не найдено в секции Answer
    IoError,
    Timeout,
}

/// Кодирует стандартный DNS-запрос для записи A (IPv4) по стандарту RFC 1035.
pub fn encode_query(domain: &str, query_id: u16, buf: &mut [u8]) -> Result<usize, DnsError> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(DnsError::InvalidDomain);
    }

    // 12 байт заголовка + длина домена + байт 0x00 + 4 байта (QTYPE + QCLASS)
    let needed = 12 + domain.len() + 2 + 4;
    if buf.len() < needed {
        return Err(DnsError::BufferTooSmall);
    }

    // Заголовок DNS (12 байт)
    buf[0] = (query_id >> 8) as u8;
    buf[1] = query_id as u8;
    buf[2] = 0x01; // Флаги: RD = 1 (Recursion Desired / рекурсивный запрос)
    buf[3] = 0x00;
    buf[4] = 0x00; // QDCOUNT: 1 вопрос
    buf[5] = 0x01;
    buf[6] = 0x00; // ANCOUNT: 0
    buf[7] = 0x00;
    buf[8] = 0x00; // NSCOUNT: 0
    buf[9] = 0x00;
    buf[10] = 0x00; // ARCOUNT: 0
    buf[11] = 0x00;

    let mut idx = 12;

    // Кодирование QNAME в виде меток: "ya.ru" -> [2, 'y', 'a', 2, 'r', 'u', 0]
    for label in domain.split('.') {
        if label.is_empty() {
            // Игнорируем завершающую точку (например, "google.com.")
            continue;
        }
        if label.len() > 63 {
            return Err(DnsError::InvalidDomain);
        }
        buf[idx] = label.len() as u8;
        idx += 1;
        for &b in label.as_bytes() {
            buf[idx] = b;
            idx += 1;
        }
    }
    buf[idx] = 0x00; // Нулевой байт - конец последовательности меток
    idx += 1;

    // QTYPE = 0x0001 (A - IPv4 адрес)
    buf[idx] = 0x00;
    buf[idx + 1] = 0x01;
    idx += 2;

    // QCLASS = 0x0001 (IN - Internet)
    buf[idx] = 0x00;
    buf[idx + 1] = 0x01;
    idx += 2;

    Ok(idx)
}

/// Пропускает имя домена в пакете DNS (учитывая сжатие указателями 0xC0xx).
/// Возвращает индекс следующего байта за именем в текущем потоке разбора.
fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    let mut jumped = false;
    let mut next_stream_offset = 0;
    let mut step_count = 0;

    loop {
        if step_count > 128 {
            return Err(DnsError::InvalidHeader); // Защита от зацикливания указателей
        }
        step_count += 1;

        if offset >= packet.len() {
            return Err(DnsError::PacketTooShort);
        }

        let len = packet[offset];
        if len == 0 {
            if !jumped {
                next_stream_offset = offset + 1;
            }
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err(DnsError::PacketTooShort);
            }
            if !jumped {
                next_stream_offset = offset + 2;
                jumped = true;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);
            offset = ptr;
            continue;
        }

        let label_len = len as usize;
        offset += 1 + label_len;
        if !jumped {
            next_stream_offset = offset;
        }
    }

    Ok(next_stream_offset)
}

/// Разбирает DNS-ответ и извлекает первую валидную IPv4-запись (тип A).
pub fn parse_a_response(packet: &[u8], query_id: u16) -> Result<[u8; 4], DnsError> {
    if packet.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }

    let resp_id = u16::from_be_bytes([packet[0], packet[1]]);
    if resp_id != query_id {
        return Err(DnsError::InvalidHeader);
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qr = (flags >> 15) & 1;
    if qr == 0 {
        return Err(DnsError::InvalidHeader); // Не ответ сервера
    }

    let rcode = flags & 0x000F;
    match rcode {
        0 => {} // NoError
        2 => return Err(DnsError::ServerFailure),
        3 => return Err(DnsError::NameError),
        5 => return Err(DnsError::Refused),
        _ => return Err(DnsError::ServerFailure),
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    if ancount == 0 {
        return Err(DnsError::NoAddresses);
    }

    let mut offset = 12;

    // Пропускаем секцию Question (QDCOUNT)
    for _ in 0..qdcount {
        offset = skip_name(packet, offset)?;
        if offset + 4 > packet.len() {
            return Err(DnsError::PacketTooShort);
        }
        offset += 4; // QTYPE (2) + QCLASS (2)
    }

    // Разбираем секцию Answer (ANCOUNT)
    for _ in 0..ancount {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(DnsError::PacketTooShort);
        }

        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        // packet[offset + 4..offset + 8] — TTL
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > packet.len() {
            return Err(DnsError::PacketTooShort);
        }

        // Если это запись A (тип 1, класс IN 1) длиной 4 байта
        if rr_type == 1 && rr_class == 1 && rdlength == 4 {
            let ip = [
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ];
            return Ok(ip);
        }

        offset += rdlength;
    }

    Err(DnsError::NoAddresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_query() {
        let mut buf = [0u8; 512];
        let len = encode_query("ya.ru", 0x1234, &mut buf).unwrap();

        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);
        assert_eq!(buf[2], 0x01); // Flags RD=1
        assert_eq!(buf[3], 0x00);
        assert_eq!(buf[4], 0x00); // QDCOUNT=1
        assert_eq!(buf[5], 0x01);

        // QNAME: 2 'y' 'a' 2 'r' 'u' 0
        assert_eq!(buf[12], 2);
        assert_eq!(buf[13], b'y');
        assert_eq!(buf[14], b'a');
        assert_eq!(buf[15], 2);
        assert_eq!(buf[16], b'r');
        assert_eq!(buf[17], b'u');
        assert_eq!(buf[18], 0);

        // QTYPE=1, QCLASS=1
        assert_eq!(buf[19], 0x00);
        assert_eq!(buf[20], 0x01);
        assert_eq!(buf[21], 0x00);
        assert_eq!(buf[22], 0x01);
        assert_eq!(len, 23);
    }

    #[test]
    fn test_parse_a_response_with_pointer() {
        // Подготавливаем реалистичный DNS-ответ с указателем сжатия 0xC00C
        let resp = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: Response, Recursion Desired, Recursion Available, NoError
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question: ya.ru
            0x02, b'y', b'a', 0x02, b'r', b'u', 0x00,
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
            // Answer:
            0xC0, 0x0C, // Name: pointer to offset 12 ("ya.ru")
            0x00, 0x01, // TYPE: A
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x01, 0x2C, // TTL: 300s
            0x00, 0x04, // RDLENGTH: 4
            87, 250, 250, 242 // IPv4
        ];

        let ip = parse_a_response(&resp, 0x1234).unwrap();
        assert_eq!(ip, [87, 250, 250, 242]);
    }

    #[test]
    fn test_parse_nxdomain() {
        let resp = [
            0x12, 0x34, // ID
            0x81, 0x83, // Flags: Response, RCODE=3 (NXDOMAIN)
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, 0x00, 0x00,
            0x02, b'n', b'o', 0x00,
            0x00, 0x01, 0x00, 0x01
        ];

        let res = parse_a_response(&resp, 0x1234);
        assert_eq!(res, Err(DnsError::NameError));
    }
}
