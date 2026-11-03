use crate::str_utils::starts_with_ci;

/// Парсит IPv4 адрес вида "192.168.1.1" из байтового среза.
pub fn parse_ipv4_bytes(s: &[u8]) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut curr_val = 0u32;
    let mut has_digit = false;

    for &b in s {
        if b == b'.' {
            if !has_digit || octet_idx >= 3 || curr_val > 255 {
                return None;
            }
            octets[octet_idx] = curr_val as u8;
            octet_idx += 1;
            curr_val = 0;
            has_digit = false;
        } else if (b'0'..=b'9').contains(&b) {
            curr_val = curr_val * 10 + (b - b'0') as u32;
            has_digit = true;
        } else {
            return None;
        }
    }

    if !has_digit || octet_idx != 3 || curr_val > 255 {
        return None;
    }
    octets[3] = curr_val as u8;
    Some(octets)
}

/// Ищет сопоставление имени хоста с IP-адресом в содержимом файла hosts.
/// Сравнение имен производится без учета регистра (case-insensitive).
pub fn lookup_in_hosts_text(text: &str, target_host: &str) -> Option<[u8; 4]> {
    for line in text.lines() {
        let clean = match line.find('#') {
            Some(idx) => &line[..idx],
            None => line,
        };
        let trimmed = clean.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_ascii_whitespace();
        let ip_str = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        let ip = match parse_ipv4_bytes(ip_str.as_bytes()) {
            Some(val) => val,
            None => continue, // Пропускаем IPv6 (::1) или некорректные строки
        };

        for alias in parts {
            if alias.len() == target_host.len() && starts_with_ci(alias, target_host) {
                return Some(ip);
            }
        }
    }
    None
}

/// Выполняет поиск по стандартным путям Unix и Windows (/etc/hosts, C:\Windows\System32\drivers\etc\hosts).
pub fn lookup_hosts_file(target_host: &str) -> Option<[u8; 4]> {
    let paths = [
        b"/etc/hosts\0" as &[u8],
        b"/win/drives/c/Windows/System32/drivers/etc/hosts\0" as &[u8],
    ];

    let mut buf = [0u8; 2048];
    for &p in &paths {
        let fd = crate::open(p, 0, 0);
        if fd >= 0 {
            let n = crate::read(fd as u64, &mut buf);
            crate::close(fd as u64);
            if n > 0 {
                if let Ok(text) = core::str::from_utf8(&buf[..n as usize]) {
                    if let Some(ip) = lookup_in_hosts_text(text, target_host) {
                        return Some(ip);
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_bytes() {
        assert_eq!(parse_ipv4_bytes(b"127.0.0.1"), Some([127, 0, 0, 1]));
        assert_eq!(parse_ipv4_bytes(b"10.0.2.15"), Some([10, 0, 2, 15]));
        assert_eq!(parse_ipv4_bytes(b"255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4_bytes(b"256.0.0.1"), None);
        assert_eq!(parse_ipv4_bytes(b"1.2.3"), None);
        assert_eq!(parse_ipv4_bytes(b"1.2.3.4.5"), None);
        assert_eq!(parse_ipv4_bytes(b"abc"), None);
    }

    #[test]
    fn test_lookup_in_hosts_text() {
        let hosts = "\
# Таблица хостов Wunix
127.0.0.1       localhost wunix
::1             localhost
10.0.2.2        gateway host.qemu
10.0.2.3        dns.qemu
8.8.8.8         google-dns
";

        assert_eq!(lookup_in_hosts_text(hosts, "localhost"), Some([127, 0, 0, 1]));
        assert_eq!(lookup_in_hosts_text(hosts, "WUNIX"), Some([127, 0, 0, 1]));
        assert_eq!(lookup_in_hosts_text(hosts, "gateway"), Some([10, 0, 2, 2]));
        assert_eq!(lookup_in_hosts_text(hosts, "host.qemu"), Some([10, 0, 2, 2]));
        assert_eq!(lookup_in_hosts_text(hosts, "dns.qemu"), Some([10, 0, 2, 3]));
        assert_eq!(lookup_in_hosts_text(hosts, "google-dns"), Some([8, 8, 8, 8]));
        assert_eq!(lookup_in_hosts_text(hosts, "unknown.host"), None);
    }
}
