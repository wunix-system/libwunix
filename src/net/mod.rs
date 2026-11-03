pub mod cache;
pub mod client;
pub mod dns_proto;
pub mod hosts;
pub mod ntp;
pub mod resolv_conf;

pub use cache::{flush_dns_cache, for_each_cache_entry};
pub use client::query_dns_server;
pub use dns_proto::DnsError;
pub use hosts::{lookup_hosts_file, parse_ipv4_bytes};
pub use ntp::{
    query_ntp_host, query_ntp_host_port, query_ntp_server, query_ntp_server_port,
    sync_system_time, LeapIndicator, NtpError, NtpMode, NtpPacket, NtpResult, NtpTimestamp,
    NTP_PORT,
};
pub use resolv_conf::get_default_nameserver;

/// Главная функция разрешения доменных имен и хостов в Wunix.
///
/// Последовательность поиска (Name Resolution Pipeline):
/// 1. Числовой IPv4-адрес: если строка уже содержит IP, возвращается немедленно.
/// 2. Локальная база сопоставлений: проверяются `/etc/hosts` и Windows `drivers/etc/hosts`.
/// 3. Локальный кэш резолвера: проверяется файл `/tmp/dns_cache`.
/// 4. Сетевой DNS-запрос: отправляется UDP-пакет на сервер из `/etc/resolv.conf` (по умолч. 10.0.2.3).
pub fn resolve_host(name: &str) -> Result<[u8; 4], DnsError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(DnsError::InvalidDomain);
    }

    // 1. Проверяем, не является ли имя готовым IPv4-адресом
    if let Some(ip) = parse_ipv4_bytes(trimmed.as_bytes()) {
        return Ok(ip);
    }

    // 2. Проверяем файлы статических хостов (/etc/hosts)
    if let Some(ip) = lookup_hosts_file(trimmed) {
        return Ok(ip);
    }

    // 3. Проверяем кэш DNS-резолвера
    if let Some(ip) = cache::lookup_cache(trimmed) {
        return Ok(ip);
    }

    // 4. Запрашиваем активный DNS-сервер
    let nameserver = get_default_nameserver();
    query_dns_server(nameserver, trimmed)
}

/// Разрешает имя хоста с явным указанием целевого DNS-сервера (для утилит nslookup/host).
pub fn resolve_host_with_server(name: &str, server_ip: [u8; 4]) -> Result<[u8; 4], DnsError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(DnsError::InvalidDomain);
    }

    if let Some(ip) = parse_ipv4_bytes(trimmed.as_bytes()) {
        return Ok(ip);
    }

    query_dns_server(server_ip, trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_ip_direct() {
        assert_eq!(resolve_host("127.0.0.1"), Ok([127, 0, 0, 1]));
        assert_eq!(resolve_host("10.0.2.2"), Ok([10, 0, 2, 2]));
    }
}
