// Автономная криптографическая подсистема Wunix на чистом Rust (no_std).
// Реализует стандартный алгоритм хеширования SHA-256 (FIPS 180-4) и схему
// хеширования паролей с солью в модульном формате $5$salt$hash.

pub const SHA256_BLOCK_SIZE: usize = 64;
pub const SHA256_DIGEST_SIZE: usize = 32;

// Таблица констант первых 32 бит дробных частей кубических корней первых 64 простых чисел
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn gamma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn gamma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;

        if self.buf_len > 0 {
            let to_fill = SHA256_BLOCK_SIZE - self.buf_len;
            if data.len() >= to_fill {
                self.buffer[self.buf_len..].copy_from_slice(&data[..to_fill]);
                self.process_block();
                data = &data[to_fill..];
                self.buf_len = 0;
            } else {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
        }

        while data.len() >= SHA256_BLOCK_SIZE {
            self.buffer.copy_from_slice(&data[..SHA256_BLOCK_SIZE]);
            self.process_block();
            data = &data[SHA256_BLOCK_SIZE..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                self.buffer[i * 4],
                self.buffer[i * 4 + 1],
                self.buffer[i * 4 + 2],
                self.buffer[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    pub fn finalize(mut self) -> [u8; SHA256_DIGEST_SIZE] {
        let bit_len = self.total_len * 8;

        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            for b in &mut self.buffer[self.buf_len..] {
                *b = 0;
            }
            self.process_block();
            self.buf_len = 0;
        }

        for b in &mut self.buffer[self.buf_len..56] {
            *b = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.process_block();

        let mut out = [0u8; SHA256_DIGEST_SIZE];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn bytes_to_hex(bytes: &[u8], out: &mut [u8]) -> usize {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let needed = bytes.len() * 2;
    if out.len() < needed {
        return 0;
    }
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX_CHARS[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_CHARS[(b & 0x0F) as usize];
    }
    needed
}

/// Вычисляет хеш пароля с солью в формате `$5$salt$hash`.
/// Соль смешивается с открытым паролем перед вычислением SHA-256.
pub fn hash_password(password: &str, salt: &str, out: &mut [u8]) -> usize {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();

    let prefix = b"$5$";
    let salt_bytes = salt.as_bytes();
    let total_len = prefix.len() + salt_bytes.len() + 1 + 64;
    if out.len() < total_len {
        return 0;
    }

    let mut pos = 0;
    out[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    out[pos..pos + salt_bytes.len()].copy_from_slice(salt_bytes);
    pos += salt_bytes.len();

    out[pos] = b'$';
    pos += 1;

    let hex_len = bytes_to_hex(&digest, &mut out[pos..pos + 64]);
    pos += hex_len;
    pos
}

/// Проверяет совпадение сырого пароля с хешем формата `$5$salt$hash`.
pub fn verify_password_hash(password: &str, formatted_hash: &str) -> bool {
    if !formatted_hash.starts_with("$5$") {
        return false;
    }
    let rest = &formatted_hash[3..];
    let salt_end = match rest.find('$') {
        Some(idx) => idx,
        None => return false,
    };
    let salt = &rest[..salt_end];
    let expected_hex = &rest[salt_end + 1..];

    let mut calc_buf = [0u8; 128];
    let calc_len = hash_password(password, salt, &mut calc_buf);
    if calc_len == 0 {
        return false;
    }

    if let Ok(calc_str) = core::str::from_utf8(&calc_buf[..calc_len]) {
        if let Some(calc_rest) = calc_str.strip_prefix("$5$") {
            if let Some(calc_salt_end) = calc_rest.find('$') {
                let calc_hex = &calc_rest[calc_salt_end + 1..];
                return calc_hex == expected_hex;
            }
        }
    }

    false
}

/// Генерирует псевдослучайную 8-символьную соль из произвольного сида (таймер, PID)
pub fn generate_salt(seed: u64, out: &mut [u8; 8]) {
    const SALT_CHARS: &[u8; 64] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    let mut s = seed;
    for b in out.iter_mut() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let idx = ((s >> 32) as usize) % SALT_CHARS.len();
        *b = SALT_CHARS[idx];
    }
}

// Таблица предвычисленных полиномов IEEE 802.3 (0xEDB88320).
// Генерируется на этапе компиляции через const fn, гарантируя нулевые накладные расходы рантайма.
const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if (c & 1) != 0 {
                c = (c >> 1) ^ 0xEDB88320;
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

pub static CRC32_TABLE: [u32; 256] = make_crc_table();

// Потоковый расчёт контрольной суммы CRC-32 (IEEE 802.3).
// Используется архиваторами ZIP, GZIP, RAR и протоколами передачи данных.
#[derive(Clone, Copy, Debug)]
pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    #[inline]
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let idx = ((self.state ^ (byte as u32)) & 0xFF) as usize;
            self.state = (self.state >> 8) ^ CRC32_TABLE[idx];
        }
    }

    #[inline]
    pub fn finish(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

// Вычисляет CRC-32 для единого среза данных
pub fn crc32(data: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(data);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_standard_vector() {
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b"hello world"), 0x0D4A1185);
    }

    #[test]
    fn test_crc32_streaming_matches_slice() {
        let mut hasher = Crc32::new();
        hasher.update(b"12345");
        hasher.update(b"6789");
        assert_eq!(hasher.finish(), 0xCBF43926);
    }
}



