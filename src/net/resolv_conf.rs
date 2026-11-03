use super::hosts::parse_ipv4_bytes;

/// Считывает первый валидный IPv4-адрес DNS-сервера из текста resolv.conf.
pub fn parse_resolv_conf_text(text: &str) -> Option<[u8; 4]> {
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
        if let Some(directive) = parts.next() {
            if directive == "nameserver" {
                if let Some(ip_str) = parts.next() {
                    if let Some(ip) = parse_ipv4_bytes(ip_str.as_bytes()) {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// Считывает активный DNS-сервер из файлов конфигурации ОС.
/// Если файл не найден или не содержит nameserver, возвращает fallback 10.0.2.3.
pub fn get_default_nameserver() -> [u8; 4] {
    let paths = [
        b"/etc/resolv.conf\0" as &[u8],
        b"/win/drives/c/Windows/System32/drivers/etc/resolv.conf\0" as &[u8],
    ];

    let mut buf = [0u8; 1024];
    for &p in &paths {
        let fd = crate::open(p, 0, 0);
        if fd >= 0 {
            let n = crate::read(fd as u64, &mut buf);
            crate::close(fd as u64);
            if n > 0 {
                if let Ok(text) = core::str::from_utf8(&buf[..n as usize]) {
                    if let Some(ip) = parse_resolv_conf_text(text) {
                        return ip;
                    }
                }
            }
        }
    }

    // Публичный резервный DNS-сервер по умолчанию (Cloudflare DNS 1.1.1.1)
    [1, 1, 1, 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolv_conf_text() {
        let conf = "\
# /etc/resolv.conf — Конфигурация DNS-резолвера Wunix
# Основной DNS
nameserver 10.0.2.3
# Резервный
nameserver 8.8.8.8
";
        assert_eq!(parse_resolv_conf_text(conf), Some([10, 0, 2, 3]));

        let conf2 = "\
# Пустой файл без директив
search localdomain
";
        assert_eq!(parse_resolv_conf_text(conf2), None);
    }
}
