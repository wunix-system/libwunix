// Компрессор RFC 1951 DEFLATE на чистом Rust (no_std).
// Реализует два режима сжатия:
// 1. Потоковое несжатое обрамление в блоки (Store, BTYPE 00) — надёжно и быстро.
// 2. Сжатие LZ77 с фиксированными кодами Хаффмана (BTYPE 01) — высокая совместимость.

use super::CompressionError;

const HASH_SIZE: usize = 4096;
const WINDOW_SIZE: usize = 32768;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;

// Битовый писатель LSB-first для потока DEFLATE
pub struct BitWriter<'f, F: FnMut(&[u8]) -> Result<(), CompressionError>> {
    writer: &'f mut F,
    bits: u64,
    num_bits: u8,
    bytes_written: usize,
}

impl<'f, F: FnMut(&[u8]) -> Result<(), CompressionError>> BitWriter<'f, F> {
    pub fn new(writer: &'f mut F) -> Self {
        Self {
            writer,
            bits: 0,
            num_bits: 0,
            bytes_written: 0,
        }
    }

    #[inline]
    pub fn write_bits(&mut self, val: u32, n: u8) -> Result<(), CompressionError> {
        self.bits |= (val as u64) << self.num_bits;
        self.num_bits += n;
        while self.num_bits >= 8 {
            let byte = (self.bits & 0xFF) as u8;
            self.bits >>= 8;
            self.num_bits -= 8;
            (self.writer)(&[byte])?;
            self.bytes_written += 1;
        }
        Ok(())
    }

    pub fn flush_byte(&mut self) -> Result<(), CompressionError> {
        if self.num_bits > 0 {
            let byte = (self.bits & 0xFF) as u8;
            self.bits = 0;
            self.num_bits = 0;
            (self.writer)(&[byte])?;
            self.bytes_written += 1;
        }
        Ok(())
    }

    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }
}

// Записывает один фиксированный символ Хаффмана в битовый поток
fn write_fixed_literal<F: FnMut(&[u8]) -> Result<(), CompressionError>>(
    writer: &mut BitWriter<F>,
    sym: u16,
) -> Result<(), CompressionError> {
    // Таблица фиксированных кодов Хаффмана по RFC 1951, раздел 3.2.6.
    // Коды Хаффмана передаются старшим битом вперед, но в DEFLATE биты
    // пакуются LSB-first, поэтому зеркалим битность кода.
    let (code, len) = match sym {
        0..=143 => (0x30 + sym, 8),
        144..=255 => (0x190 + (sym - 144), 9),
        256..=279 => (sym - 256, 7),
        280..=287 => (0xC0 + (sym - 280), 8),
        _ => return Err(CompressionError::CorruptedData),
    };

    let mut reversed = 0u32;
    for i in 0..len {
        if ((code >> (len - 1 - i)) & 1) != 0 {
            reversed |= 1 << i;
        }
    }
    writer.write_bits(reversed, len)
}

// Записывает дистанционный код Хаффмана (5 бит, фиксированный)
fn write_fixed_distance<F: FnMut(&[u8]) -> Result<(), CompressionError>>(
    writer: &mut BitWriter<F>,
    dist_code: u8,
) -> Result<(), CompressionError> {
    let mut reversed = 0u32;
    for i in 0..5 {
        if ((dist_code >> (4 - i)) & 1) != 0 {
            reversed |= 1 << i;
        }
    }
    writer.write_bits(reversed, 5)
}

// Находит код длины и экстра-биты
fn encode_length(len: usize) -> (u16, u32, u8) {
    match len {
        3 => (257, 0, 0),
        4 => (258, 0, 0),
        5 => (259, 0, 0),
        6 => (260, 0, 0),
        7 => (261, 0, 0),
        8 => (262, 0, 0),
        9 => (263, 0, 0),
        10 => (264, 0, 0),
        11..=12 => (265, (len - 11) as u32, 1),
        13..=14 => (266, (len - 13) as u32, 1),
        15..=16 => (267, (len - 15) as u32, 1),
        17..=18 => (268, (len - 17) as u32, 1),
        19..=22 => (269, (len - 19) as u32, 2),
        23..=26 => (270, (len - 23) as u32, 2),
        27..=30 => (271, (len - 27) as u32, 2),
        31..=34 => (272, (len - 31) as u32, 2),
        35..=42 => (273, (len - 35) as u32, 3),
        43..=50 => (274, (len - 43) as u32, 3),
        51..=58 => (275, (len - 51) as u32, 3),
        59..=66 => (276, (len - 59) as u32, 3),
        67..=82 => (277, (len - 67) as u32, 4),
        83..=98 => (278, (len - 83) as u32, 4),
        99..=114 => (279, (len - 99) as u32, 4),
        115..=130 => (280, (len - 115) as u32, 4),
        131..=162 => (281, (len - 131) as u32, 5),
        163..=194 => (282, (len - 163) as u32, 5),
        195..=226 => (283, (len - 195) as u32, 5),
        227..=257 => (284, (len - 227) as u32, 5),
        _ => (285, 0, 0),
    }
}

// Находит код дистанции и экстра-биты
fn encode_distance(dist: usize) -> (u8, u32, u8) {
    match dist {
        1 => (0, 0, 0),
        2 => (1, 0, 0),
        3 => (2, 0, 0),
        4 => (3, 0, 0),
        5..=6 => (4, (dist - 5) as u32, 1),
        7..=8 => (5, (dist - 7) as u32, 1),
        9..=12 => (6, (dist - 9) as u32, 2),
        13..=16 => (7, (dist - 13) as u32, 2),
        17..=24 => (8, (dist - 17) as u32, 3),
        25..=32 => (9, (dist - 25) as u32, 3),
        33..=48 => (10, (dist - 33) as u32, 4),
        49..=64 => (11, (dist - 49) as u32, 4),
        65..=96 => (12, (dist - 65) as u32, 5),
        97..=128 => (13, (dist - 97) as u32, 5),
        129..=192 => (14, (dist - 129) as u32, 6),
        193..=256 => (15, (dist - 193) as u32, 6),
        257..=384 => (16, (dist - 257) as u32, 7),
        385..=512 => (17, (dist - 385) as u32, 7),
        513..=768 => (18, (dist - 513) as u32, 8),
        769..=1024 => (19, (dist - 769) as u32, 8),
        1025..=1536 => (20, (dist - 1025) as u32, 9),
        1537..=2048 => (21, (dist - 1537) as u32, 9),
        2049..=3072 => (22, (dist - 2049) as u32, 10),
        3073..=4096 => (23, (dist - 3073) as u32, 10),
        4097..=6144 => (24, (dist - 4097) as u32, 11),
        6145..=8192 => (25, (dist - 6145) as u32, 11),
        8193..=12288 => (26, (dist - 8193) as u32, 12),
        12289..=16384 => (27, (dist - 12289) as u32, 12),
        16385..=24576 => (28, (dist - 16385) as u32, 13),
        _ => (29, (dist - 24577) as u32, 13),
    }
}

// Сжатие потока методом RFC 1951 (Fixed Huffman + LZ77)
pub fn deflate_fixed<F: FnMut(&[u8]) -> Result<(), CompressionError>>(
    input: &[u8],
    mut output_fn: F,
) -> Result<usize, CompressionError> {
    let mut writer = BitWriter::new(&mut output_fn);

    // Заголовок блока: BFINAL=1, BTYPE=01 (Fixed Huffman)
    writer.write_bits(1, 1)?; // BFINAL = 1
    writer.write_bits(1, 2)?; // BTYPE = 01

    if input.is_empty() {
        write_fixed_literal(&mut writer, 256)?; // Конец блока
        writer.flush_byte()?;
        return Ok(writer.bytes_written());
    }

    let mut head = [0u32; HASH_SIZE];
    let mut prev = [0u32; WINDOW_SIZE];

    let mut pos = 0usize;
    let len = input.len();

    while pos < len {
        // Ищем совпадение в предыдущем окне
        let mut match_len = 0usize;
        let mut match_dist = 0usize;

        if pos + MIN_MATCH <= len {
            let h = ((input[pos] as usize) << 8
                ^ (input[pos + 1] as usize) << 4
                ^ (input[pos + 2] as usize))
                % HASH_SIZE;

            let mut cur_candidate = head[h] as usize;
            head[h] = (pos + 1) as u32;

            let mut chain_len = 0;
            while cur_candidate > 0 && chain_len < 32 {
                let cand_pos = cur_candidate - 1;
                let dist = pos - cand_pos;
                if dist >= WINDOW_SIZE {
                    break;
                }

                // Сравниваем байты
                let max_avail = (len - pos).min(MAX_MATCH);
                let mut match_count = 0usize;
                while match_count < max_avail && input[pos + match_count] == input[cand_pos + match_count] {
                    match_count += 1;
                }

                if match_count > match_len && match_count >= MIN_MATCH {
                    match_len = match_count;
                    match_dist = dist;
                    if match_len >= 32 {
                        break;
                    }
                }

                cur_candidate = prev[cand_pos & (WINDOW_SIZE - 1)] as usize;
                chain_len += 1;
            }

            prev[pos & (WINDOW_SIZE - 1)] = (head[h]) as u32;
        }

        if match_len >= MIN_MATCH {
            // Записываем пару length/distance
            let (len_sym, len_extra, len_bits) = encode_length(match_len);
            write_fixed_literal(&mut writer, len_sym)?;
            if len_bits > 0 {
                writer.write_bits(len_extra, len_bits)?;
            }

            let (dist_sym, dist_extra, dist_bits) = encode_distance(match_dist);
            write_fixed_distance(&mut writer, dist_sym)?;
            if dist_bits > 0 {
                writer.write_bits(dist_extra, dist_bits)?;
            }

            pos += match_len;
        } else {
            // Записываем один литеральный байт
            write_fixed_literal(&mut writer, input[pos] as u16)?;
            pos += 1;
        }
    }

    // Конец блока (символ 256)
    write_fixed_literal(&mut writer, 256)?;
    writer.flush_byte()?;

    Ok(writer.bytes_written())
}

// Запись потока в несжатые блоки (Store, BTYPE 00)
pub fn deflate_store<F: FnMut(&[u8]) -> Result<(), CompressionError>>(
    input: &[u8],
    mut output_fn: F,
) -> Result<usize, CompressionError> {
    let mut offset = 0usize;
    let mut written = 0usize;

    if input.is_empty() {
        // Пустой последний блок Store: bfinal=1, btype=00 -> байт 0x01, LEN=0, NLEN=0xFFFF
        let empty_block = [0x01, 0x00, 0x00, 0xFF, 0xFF];
        output_fn(&empty_block)?;
        return Ok(empty_block.len());
    }

    while offset < input.len() {
        let chunk_size = (input.len() - offset).min(65535);
        let is_last = offset + chunk_size == input.len();

        let header_byte = if is_last { 0x01 } else { 0x00 };
        let len_u16 = chunk_size as u16;
        let nlen_u16 = !len_u16;

        let block_header = [
            header_byte,
            (len_u16 & 0xFF) as u8,
            ((len_u16 >> 8) & 0xFF) as u8,
            (nlen_u16 & 0xFF) as u8,
            ((nlen_u16 >> 8) & 0xFF) as u8,
        ];
        output_fn(&block_header)?;
        written += block_header.len();

        output_fn(&input[offset..offset + chunk_size])?;
        written += chunk_size;
        offset += chunk_size;
    }

    Ok(written)
}
