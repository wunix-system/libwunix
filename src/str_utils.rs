pub fn strlen(s: *const u8) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

pub fn memcmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    a.cmp(b)
}

pub fn strchr(s: &[u8], c: u8) -> Option<usize> {
    s.iter().position(|&b| b == c)
}

pub fn starts_with_ci(s: &str, prefix: &str) -> bool {
    if s.len() < prefix.len() {
        return false;
    }
    s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

pub fn strtoul(s: &str, mut base: u32) -> Result<u64, ()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(());
    }

    let (content, detected_base) = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        (&trimmed[2..], 16)
    } else if trimmed.starts_with('0') && trimmed.len() > 1 && base == 0 {
        (&trimmed[1..], 8)
    } else {
        (trimmed, if base == 0 { 10 } else { base })
    };

    if base == 0 {
        base = detected_base;
    }

    let mut result: u64 = 0;
    for &b in content.as_bytes() {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'z' => (b - b'a' + 10) as u32,
            b'A'..=b'Z' => (b - b'A' + 10) as u32,
            _ => return Err(()),
        };
        if digit >= base {
            return Err(());
        }
        result = result
            .checked_mul(base as u64)
            .and_then(|r| r.checked_add(digit as u64))
            .ok_or(())?;
    }

    Ok(result)
}

pub fn strtol(s: &str, base: u32) -> Result<i64, ()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(());
    }

    if let Some(rest) = trimmed.strip_prefix('-') {
        let unsigned = strtoul(rest, base)?;
        if unsigned > (i64::MAX as u64 + 1) {
            return Err(());
        }
        Ok(-(unsigned as i64))
    } else if let Some(rest) = trimmed.strip_prefix('+') {
        let unsigned = strtoul(rest, base)?;
        if unsigned > (i64::MAX as u64) {
            return Err(());
        }
        Ok(unsigned as i64)
    } else {
        let unsigned = strtoul(trimmed, base)?;
        if unsigned > (i64::MAX as u64) {
            return Err(());
        }
        Ok(unsigned as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strtoul_parsing() {
        assert_eq!(strtoul("12345", 10).unwrap(), 12345);
        assert_eq!(strtoul("0x1a", 16).unwrap(), 0x1a);
        assert_eq!(strtoul("0XFF", 0).unwrap(), 255);
        assert_eq!(strtoul("0777", 8).unwrap(), 0o777);
    }

    #[test]
    fn test_strtol_parsing() {
        assert_eq!(strtol("42", 10).unwrap(), 42);
        assert_eq!(strtol("-42", 10).unwrap(), -42);
        assert_eq!(strtol("+100", 10).unwrap(), 100);
    }

    #[test]
    fn test_starts_with_ci() {
        assert!(starts_with_ci("SystemRoot", "system"));
        assert!(starts_with_ci("C:\\Windows", "c:\\"));
        assert!(!starts_with_ci("abc", "abcdef"));
    }
}
