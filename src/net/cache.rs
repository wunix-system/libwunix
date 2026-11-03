use super::hosts::parse_ipv4_bytes;
use crate::str_utils::starts_with_ci;
use crate::{close, open, read, write, O_CREAT, O_TRUNC, O_WRONLY};

const CACHE_FILE: &[u8] = b"/tmp/dns_cache\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsCacheEntry<'a> {
    pub domain: &'a str,
    pub ip: [u8; 4],
    pub ttl: u32,
}

/// Ищет доменное имя в кэше резолвера Wunix.
pub fn lookup_cache(target_domain: &str) -> Option<[u8; 4]> {
    let mut buf = [0u8; 4096];
    let fd = open(CACHE_FILE, 0, 0);
    if fd < 0 {
        return None;
    }
    let n = read(fd as u64, &mut buf);
    close(fd as u64);
    if n <= 0 {
        return None;
    }

    let text = core::str::from_utf8(&buf[..n as usize]).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_ascii_whitespace();
        let domain = parts.next()?;
        let ip_str = parts.next()?;
        if domain.len() == target_domain.len()
            && starts_with_ci(domain, target_domain)
        {
            return parse_ipv4_bytes(ip_str.as_bytes());
        }
    }

    None
}

/// Сохраняет разрешенное доменное имя в кэше резолвера.
pub fn store_cache(domain: &str, ip: [u8; 4], ttl: u32) {
    if domain.is_empty() {
        return;
    }

    let mut buf = [0u8; 4096];
    let fd_rd = open(CACHE_FILE, 0, 0);
    let mut len = 0usize;
    if fd_rd >= 0 {
        let n = read(fd_rd as u64, &mut buf);
        close(fd_rd as u64);
        if n > 0 {
            len = n as usize;
        }
    }

    // Проверяем, нет ли уже такой записи
    if let Ok(text) = core::str::from_utf8(&buf[..len]) {
        for line in text.lines() {
            let mut parts = line.split_ascii_whitespace();
            if let Some(d) = parts.next() {
                if d.len() == domain.len() && starts_with_ci(d, domain) {
                    return; // Уже присутствует в кэше
                }
            }
        }
    }

    let fd_wr = open(CACHE_FILE, (O_WRONLY | O_CREAT) as u64, 0o644);
    if fd_wr < 0 {
        return;
    }

    // Перемещаемся в конец или дописываем
    crate::lseek(fd_wr as u64, 0, crate::SEEK_END);

    let mut line_buf = [0u8; 128];
    let mut idx = 0;
    for &b in domain.as_bytes() {
        if idx < line_buf.len() {
            line_buf[idx] = b;
            idx += 1;
        }
    }
    if idx < line_buf.len() {
        line_buf[idx] = b' ';
        idx += 1;
    }

    // IP адрес
    for (i, &oct) in ip.iter().enumerate() {
        if oct >= 100 {
            line_buf[idx] = b'0' + (oct / 100);
            idx += 1;
        }
        if oct >= 10 {
            line_buf[idx] = b'0' + ((oct / 10) % 10);
            idx += 1;
        }
        line_buf[idx] = b'0' + (oct % 10);
        idx += 1;
        if i < 3 {
            line_buf[idx] = b'.';
            idx += 1;
        }
    }

    if idx < line_buf.len() {
        line_buf[idx] = b' ';
        idx += 1;
    }

    // TTL
    let mut ttl_tmp = [0u8; 10];
    let mut t_idx = 0;
    let mut v = ttl;
    if v == 0 {
        ttl_tmp[0] = b'0';
        t_idx = 1;
    } else {
        while v > 0 {
            ttl_tmp[t_idx] = b'0' + (v % 10) as u8;
            t_idx += 1;
            v /= 10;
        }
    }
    for i in (0..t_idx).rev() {
        if idx < line_buf.len() {
            line_buf[idx] = ttl_tmp[i];
            idx += 1;
        }
    }

    if idx < line_buf.len() {
        line_buf[idx] = b'\n';
        idx += 1;
    }

    write(fd_wr as u64, &line_buf[..idx]);
    close(fd_wr as u64);
}

/// Очищает локальный файл кэша записей DNS.
pub fn flush_dns_cache() -> bool {
    let fd = open(CACHE_FILE, (O_WRONLY | O_CREAT | O_TRUNC) as u64, 0o644);
    if fd >= 0 {
        close(fd as u64);
        true
    } else {
        false
    }
}

/// Итерирует по всем записям локального кэша DNS.
pub fn for_each_cache_entry<F>(mut callback: F)
where
    F: FnMut(&str, [u8; 4], u32),
{
    let mut buf = [0u8; 4096];
    let fd = open(CACHE_FILE, 0, 0);
    if fd < 0 {
        return;
    }
    let n = read(fd as u64, &mut buf);
    close(fd as u64);
    if n <= 0 {
        return;
    }

    if let Ok(text) = core::str::from_utf8(&buf[..n as usize]) {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut parts = trimmed.split_ascii_whitespace();
            if let (Some(domain), Some(ip_str), ttl_opt) =
                (parts.next(), parts.next(), parts.next())
            {
                if let Some(ip) = parse_ipv4_bytes(ip_str.as_bytes()) {
                    let ttl = ttl_opt.and_then(|s| s.parse::<u32>().ok()).unwrap_or(300);
                    callback(domain, ip, ttl);
                }
            }
        }
    }
}
