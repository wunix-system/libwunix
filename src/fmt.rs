pub fn utoa(mut n: u64, buf: &mut [u8]) -> &str {
    if buf.is_empty() {
        return "";
    }
    if n == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap_or("");
    }

    let mut len = 0;
    let mut temp = n;
    while temp > 0 {
        len += 1;
        temp /= 10;
    }

    if len > buf.len() {
        return "";
    }

    let mut idx = len;
    while n > 0 {
        idx -= 1;
        buf[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }

    core::str::from_utf8(&buf[..len]).unwrap_or("")
}

pub fn itoa(n: i64, buf: &mut [u8]) -> &str {
    if buf.is_empty() {
        return "";
    }
    if n < 0 {
        buf[0] = b'-';
        let unsigned = if n == i64::MIN {
            (i64::MAX as u64) + 1
        } else {
            (-n) as u64
        };
        let rest = utoa(unsigned, &mut buf[1..]);
        let total_len = 1 + rest.len();
        core::str::from_utf8(&buf[..total_len]).unwrap_or("")
    } else {
        utoa(n as u64, buf)
    }
}

pub fn utoa_hex(mut n: u64, buf: &mut [u8]) -> &str {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    if buf.len() < 3 {
        return "";
    }

    buf[0] = b'0';
    buf[1] = b'x';

    if n == 0 {
        buf[2] = b'0';
        return core::str::from_utf8(&buf[..3]).unwrap_or("");
    }

    let mut hex_digits = 0;
    let mut temp = n;
    while temp > 0 {
        hex_digits += 1;
        temp >>= 4;
    }

    let total_len = 2 + hex_digits;
    if total_len > buf.len() {
        return "";
    }

    let mut idx = total_len;
    while n > 0 {
        idx -= 1;
        buf[idx] = HEX_CHARS[(n & 0xF) as usize];
        n >>= 4;
    }

    core::str::from_utf8(&buf[..total_len]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_formatting() {
        let mut buf = [0u8; 32];
        assert_eq!(utoa(0, &mut buf), "0");
        assert_eq!(utoa(12345, &mut buf), "12345");
        assert_eq!(itoa(-999, &mut buf), "-999");
        assert_eq!(utoa_hex(0xABCD, &mut buf), "0xabcd");
    }
}
