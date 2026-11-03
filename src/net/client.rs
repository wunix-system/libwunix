use core::sync::atomic::{AtomicU16, Ordering};
use crate::{close, recvfrom, sendto, socket, SockAddrIn, AF_INET, SOCK_DGRAM};
use super::cache::store_cache;
use super::dns_proto::{encode_query, parse_a_response, DnsError};

static NEXT_DNS_TXID: AtomicU16 = AtomicU16::new(0x2A10);

/// Отправляет сетевой запрос к DNS-серверу по протоколу UDP (порт 53)
/// и возвращает разрешенный IPv4-адрес.
pub fn query_dns_server(server_ip: [u8; 4], domain: &str) -> Result<[u8; 4], DnsError> {
    let fd = socket(AF_INET, SOCK_DGRAM, 0);
    if fd < 0 {
        return Err(DnsError::IoError);
    }

    let query_id = NEXT_DNS_TXID.fetch_add(1, Ordering::Relaxed);
    let mut tx_buf = [0u8; 512];
    let tx_len = match encode_query(domain, query_id, &mut tx_buf) {
        Ok(len) => len,
        Err(e) => {
            close(fd as u64);
            return Err(e);
        }
    };

    let server_addr = SockAddrIn::new_v4(server_ip, 53);
    let sent = sendto(fd as u64, &tx_buf[..tx_len], 0, Some(&server_addr));
    if sent < 0 {
        close(fd as u64);
        return Err(DnsError::IoError);
    }

    let mut rx_buf = [0u8; 1024];
    let mut from_addr = SockAddrIn::default();
    let n = recvfrom(fd as u64, &mut rx_buf, 0, Some(&mut from_addr));
    close(fd as u64);

    if n < 0 {
        if n == -110 {
            return Err(DnsError::Timeout);
        }
        return Err(DnsError::IoError);
    }

    let ip = parse_a_response(&rx_buf[..n as usize], query_id)?;
    store_cache(domain, ip, 300);
    Ok(ip)
}
