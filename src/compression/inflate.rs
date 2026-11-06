// Декомпрессор RFC 1951 DEFLATE на чистом Rust (no_std).
// Поддерживает все три типа блоков:
// - BTYPE 00: Uncompressed (Store)
// - BTYPE 01: Fixed Huffman codes
// - BTYPE 10: Dynamic Huffman codes
// Обеспечивает потоковую декомпрессию без динамических аллокаций.

use super::CompressionError;

const WINDOW_SIZE: usize = 32768;
const MAX_BITS: usize = 15;
const MAX_LITERAL_CODES: usize = 288;
const MAX_DISTANCE_CODES: usize = 32;
const MAX_TREE_NODES: usize = 600;

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
];
const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

// Побитовый ридер LSB-first для потока DEFLATE
pub struct BitReader<'a> {
    data: &'a [u8],
    offset: usize,
    bits: u64,
    num_bits: u8,
}

impl<'a> BitReader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            bits: 0,
            num_bits: 0,
        }
    }

    #[inline]
    fn fill(&mut self, n: u8) -> Result<(), CompressionError> {
        while self.num_bits < n {
            if self.offset >= self.data.len() {
                return Err(CompressionError::UnexpectedEof);
            }
            self.bits |= (self.data[self.offset] as u64) << self.num_bits;
            self.offset += 1;
            self.num_bits += 8;
        }
        Ok(())
    }

    #[inline]
    pub fn read_bits(&mut self, n: u8) -> Result<u32, CompressionError> {
        if n == 0 {
            return Ok(0);
        }
        self.fill(n)?;
        let mask = (1u64 << n) - 1;
        let val = (self.bits & mask) as u32;
        self.bits >>= n;
        self.num_bits -= n;
        Ok(val)
    }

    #[inline]
    pub fn align_byte(&mut self) {
        let discard = self.num_bits % 8;
        self.bits >>= discard;
        self.num_bits -= discard;
    }

    pub fn read_u16_le(&mut self) -> Result<u16, CompressionError> {
        self.align_byte();
        let b0 = self.read_bits(8)? as u16;
        let b1 = self.read_bits(8)? as u16;
        Ok(b0 | (b1 << 8))
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CompressionError> {
        self.align_byte();
        for b in buf.iter_mut() {
            *b = self.read_bits(8)? as u8;
        }
        Ok(())
    }
}

// Бинарное дерево Хаффмана в виде статического массива индексов
#[derive(Clone, Copy)]
struct HuffmanTree {
    // Каждая запись: left_child и right_child.
    // Если старший бит (0x8000) установлен — это лист, содержащий символ в младших 15 битах.
    nodes: [[u16; 2]; MAX_TREE_NODES],
    node_count: usize,
}

impl HuffmanTree {
    const fn empty() -> Self {
        Self {
            nodes: [[0, 0]; MAX_TREE_NODES],
            node_count: 1, // Корень с индексом 0
        }
    }

    // Строит каноническое дерево Хаффмана из длин кодов по RFC 1951 (Section 3.2.2)
    fn build(lengths: &[u8]) -> Result<Self, CompressionError> {
        let mut tree = Self::empty();
        let mut bl_count = [0u16; MAX_BITS + 1];
        let mut max_len = 0usize;

        for &len in lengths {
            let l = len as usize;
            if l > MAX_BITS {
                return Err(CompressionError::CorruptedData);
            }
            if l > 0 {
                bl_count[l] += 1;
                if l > max_len {
                    max_len = l;
                }
            }
        }

        if max_len == 0 {
            return Ok(tree);
        }

        // Вычисляем минимальное числовое значение кода для каждой длины
        let mut next_code = [0u16; MAX_BITS + 1];
        let mut code = 0u16;
        let mut bits = 1;
        while bits <= MAX_BITS {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
            bits += 1;
        }

        // Присваиваем коды и вставляем их в бинарное дерево
        for (sym, &len) in lengths.iter().enumerate() {
            let l = len as usize;
            if l == 0 {
                continue;
            }
            let c = next_code[l];
            next_code[l] += 1;
            tree.insert_code(c, l as u8, sym as u16)?;
        }

        Ok(tree)
    }

    fn insert_code(&mut self, code: u16, len: u8, symbol: u16) -> Result<(), CompressionError> {
        let mut curr_node = 0usize;
        for bit_idx in (0..len).rev() {
            let bit = ((code >> bit_idx) & 1) as usize;
            let next = self.nodes[curr_node][bit];
            if bit_idx == 0 {
                // Лист: помечаем флагом 0x8000
                self.nodes[curr_node][bit] = symbol | 0x8000;
            } else if next == 0 {
                if self.node_count >= MAX_TREE_NODES {
                    return Err(CompressionError::CorruptedData);
                }
                let new_idx = self.node_count as u16;
                self.node_count += 1;
                self.nodes[curr_node][bit] = new_idx;
                curr_node = new_idx as usize;
            } else {
                if (next & 0x8000) != 0 {
                    return Err(CompressionError::CorruptedData);
                }
                curr_node = next as usize;
            }
        }
        Ok(())
    }

    // Считывает следующий символ из побитового потока
    #[inline]
    fn decode_symbol(&self, reader: &mut BitReader) -> Result<u16, CompressionError> {
        let mut curr_node = 0usize;
        loop {
            let bit = reader.read_bits(1)? as usize;
            let next = self.nodes[curr_node][bit];
            if next == 0 {
                return Err(CompressionError::CorruptedData);
            }
            if (next & 0x8000) != 0 {
                return Ok(next & 0x7FFF);
            }
            curr_node = next as usize;
        }
    }
}

// Скользящее окно 32 КиБ для LZ77
struct SlidingWindow<'f, F: FnMut(&[u8]) -> Result<(), CompressionError>> {
    buffer: [u8; WINDOW_SIZE],
    head: usize,
    writer: &'f mut F,
    bytes_written: usize,
}

impl<'f, F: FnMut(&[u8]) -> Result<(), CompressionError>> SlidingWindow<'f, F> {
    fn new(writer: &'f mut F) -> Self {
        Self {
            buffer: [0u8; WINDOW_SIZE],
            head: 0,
            writer,
            bytes_written: 0,
        }
    }

    #[inline]
    fn emit_byte(&mut self, b: u8) -> Result<(), CompressionError> {
        self.buffer[self.head] = b;
        self.head = (self.head + 1) & (WINDOW_SIZE - 1);
        self.bytes_written += 1;
        (self.writer)(&[b])
    }

    fn copy_match(&mut self, length: usize, distance: usize) -> Result<(), CompressionError> {
        if distance == 0 || distance > WINDOW_SIZE {
            return Err(CompressionError::CorruptedData);
        }
        let mut src = (self.head + WINDOW_SIZE - distance) & (WINDOW_SIZE - 1);
        for _ in 0..length {
            let b = self.buffer[src];
            src = (src + 1) & (WINDOW_SIZE - 1);
            self.emit_byte(b)?;
        }
        Ok(())
    }
}

// Генерирует фиксированное дерево литералов RFC 1951
fn build_fixed_literal_tree() -> Result<HuffmanTree, CompressionError> {
    let mut lengths = [0u8; 288];
    for i in 0..=143 {
        lengths[i] = 8;
    }
    for i in 144..=255 {
        lengths[i] = 9;
    }
    for i in 256..=279 {
        lengths[i] = 7;
    }
    for i in 280..=287 {
        lengths[i] = 8;
    }
    HuffmanTree::build(&lengths)
}

// Генерирует фиксированное дерево расстояний RFC 1951
fn build_fixed_dist_tree() -> Result<HuffmanTree, CompressionError> {
    let lengths = [5u8; 32];
    HuffmanTree::build(&lengths)
}

// Распаковывает динамические таблицы Хаффмана (BTYPE 10)
fn parse_dynamic_trees(
    reader: &mut BitReader,
) -> Result<(HuffmanTree, HuffmanTree), CompressionError> {
    let hlit = (reader.read_bits(5)? as usize) + 257;
    let hdist = (reader.read_bits(5)? as usize) + 1;
    let hclen = (reader.read_bits(4)? as usize) + 4;

    if hlit > MAX_LITERAL_CODES || hdist > MAX_DISTANCE_CODES {
        return Err(CompressionError::CorruptedData);
    }

    let mut clen_lengths = [0u8; 19];
    for i in 0..hclen {
        clen_lengths[CODE_LENGTH_ORDER[i]] = reader.read_bits(3)? as u8;
    }

    let clen_tree = HuffmanTree::build(&clen_lengths)?;

    let mut combined_lengths = [0u8; MAX_LITERAL_CODES + MAX_DISTANCE_CODES];
    let total_codes = hlit + hdist;
    let mut i = 0;

    while i < total_codes {
        let sym = clen_tree.decode_symbol(reader)?;
        match sym {
            0..=15 => {
                combined_lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err(CompressionError::CorruptedData);
                }
                let prev = combined_lengths[i - 1];
                let repeat = (reader.read_bits(2)? as usize) + 3;
                if i + repeat > total_codes {
                    return Err(CompressionError::CorruptedData);
                }
                for _ in 0..repeat {
                    combined_lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let repeat = (reader.read_bits(3)? as usize) + 3;
                if i + repeat > total_codes {
                    return Err(CompressionError::CorruptedData);
                }
                for _ in 0..repeat {
                    combined_lengths[i] = 0;
                    i += 1;
                }
            }
            18 => {
                let repeat = (reader.read_bits(7)? as usize) + 11;
                if i + repeat > total_codes {
                    return Err(CompressionError::CorruptedData);
                }
                for _ in 0..repeat {
                    combined_lengths[i] = 0;
                    i += 1;
                }
            }
            _ => return Err(CompressionError::CorruptedData),
        }
    }

    let lit_tree = HuffmanTree::build(&combined_lengths[..hlit])?;
    let dist_tree = HuffmanTree::build(&combined_lengths[hlit..total_codes])?;
    Ok((lit_tree, dist_tree))
}

// Декодирует поток символов для открытого блока с деревьями Хаффмана
fn decode_huffman_block<F: FnMut(&[u8]) -> Result<(), CompressionError>>(
    reader: &mut BitReader,
    lit_tree: &HuffmanTree,
    dist_tree: &HuffmanTree,
    window: &mut SlidingWindow<F>,
) -> Result<(), CompressionError> {
    loop {
        let sym = lit_tree.decode_symbol(reader)?;
        match sym {
            0..=255 => {
                window.emit_byte(sym as u8)?;
            }
            256 => break, // Конец блока
            257..=285 => {
                let len_idx = (sym - 257) as usize;
                let base_len = LENGTH_BASE[len_idx] as usize;
                let extra_bits = LENGTH_EXTRA_BITS[len_idx];
                let extra = reader.read_bits(extra_bits)? as usize;
                let length = base_len + extra;

                let dist_sym = dist_tree.decode_symbol(reader)? as usize;
                if dist_sym >= 30 {
                    return Err(CompressionError::CorruptedData);
                }
                let base_dist = DIST_BASE[dist_sym] as usize;
                let dist_extra_bits = DIST_EXTRA_BITS[dist_sym];
                let dist_extra = reader.read_bits(dist_extra_bits)? as usize;
                let distance = base_dist + dist_extra;

                window.copy_match(length, distance)?;
            }
            _ => return Err(CompressionError::CorruptedData),
        }
    }
    Ok(())
}

// Точка входа потоковой декомпрессии RFC 1951 DEFLATE
pub fn inflate<F: FnMut(&[u8]) -> Result<(), CompressionError>>(
    input: &[u8],
    mut output_fn: F,
) -> Result<usize, CompressionError> {
    let mut reader = BitReader::new(input);
    let mut window = SlidingWindow::new(&mut output_fn);

    loop {
        let bfinal = reader.read_bits(1)? != 0;
        let btype = reader.read_bits(2)?;

        match btype {
            0 => {
                // Блок без сжатия (Store)
                reader.align_byte();
                let len = reader.read_u16_le()? as usize;
                let nlen = reader.read_u16_le()? as usize;
                if (len ^ 0xFFFF) != nlen {
                    return Err(CompressionError::CorruptedData);
                }
                for _ in 0..len {
                    let b = reader.read_bits(8)? as u8;
                    window.emit_byte(b)?;
                }
            }
            1 => {
                // Сжатие с фиксированными таблицами Хаффмана
                let lit_tree = build_fixed_literal_tree()?;
                let dist_tree = build_fixed_dist_tree()?;
                decode_huffman_block(&mut reader, &lit_tree, &dist_tree, &mut window)?;
            }
            2 => {
                // Сжатие с динамическими таблицами Хаффмана
                let (lit_tree, dist_tree) = parse_dynamic_trees(&mut reader)?;
                decode_huffman_block(&mut reader, &lit_tree, &dist_tree, &mut window)?;
            }
            _ => return Err(CompressionError::CorruptedData),
        }

        if bfinal {
            break;
        }
    }

    Ok(window.bytes_written)
}
