// Упаковка и распаковка формата RFC 1952 GZIP (.gz).
// Поддерживает проверку заголовка, CRC-32 и исходного размера ISIZE.

use crate::crypto::{crc32, Crc32};
use super::{deflate_fixed, inflate, CompressionError};

pub const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
pub const GZIP_METHOD_DEFLATE: u8 = 8;

pub const FLAG_FTEXT: u8 = 0x01;
pub const FLAG_FHCRC: u8 = 0x02;
pub const FLAG_FEXTRA: u8 = 0x04;
pub const FLAG_FNAME: u8 = 0x08;
pub const FLAG_FCOMMENT: u8 = 0x10;

// Заголовок GZIP
#[derive(Clone, Debug)]
pub struct GzipHeader<'a> {
    pub mtime: u32,
    pub filename: Option<&'a str>,
}

// Сжимает данные в формат GZIP
pub fn gzip_compress<F: FnMut(&[u8]) -> Result<(), CompressionError>>(
    input: &[u8],
    filename: Option<&str>,
    mut output_fn: F,
) -> Result<usize, CompressionError> {
    let mut written = 0usize;

    let flag = if filename.is_some() { FLAG_FNAME } else { 0 };
    let header = [
        GZIP_MAGIC[0],
        GZIP_MAGIC[1],
        GZIP_METHOD_DEFLATE,
        flag,
        0, 0, 0, 0, // MTIME (0 = не задано)
        0,          // XFL
        3,          // OS = Unix
    ];
    output_fn(&header)?;
    written += header.len();

    if let Some(name) = filename {
        output_fn(name.as_bytes())?;
        output_fn(&[0])?;
        written += name.len() + 1;
    }

    // Сжимаем данные методом DEFLATE
    let comp_size = deflate_fixed(input, &mut output_fn)?;
    written += comp_size;

    // Вычисляем CRC32 и ISIZE
    let crc = crc32(input);
    let isize = (input.len() & 0xFFFFFFFF) as u32;

    let trailer = [
        (crc & 0xFF) as u8,
        ((crc >> 8) & 0xFF) as u8,
        ((crc >> 16) & 0xFF) as u8,
        ((crc >> 24) & 0xFF) as u8,
        (isize & 0xFF) as u8,
        ((isize >> 8) & 0xFF) as u8,
        ((isize >> 16) & 0xFF) as u8,
        ((isize >> 24) & 0xFF) as u8,
    ];
    output_fn(&trailer)?;
    written += trailer.len();

    Ok(written)
}

// Распаковывает GZIP данные и валидирует CRC32 и размер
pub fn gzip_decompress<F: FnMut(&[u8]) -> Result<(), CompressionError>>(
    input: &[u8],
    mut output_fn: F,
) -> Result<(usize, GzipHeader<'_>), CompressionError> {
    if input.len() < 18 {
        // Минимальный размер: 10 байт заголовок + 0 байт поток + 8 байт трейлер
        return Err(CompressionError::CorruptedData);
    }

    if input[0] != GZIP_MAGIC[0] || input[1] != GZIP_MAGIC[1] {
        return Err(CompressionError::InvalidHeader);
    }

    if input[2] != GZIP_METHOD_DEFLATE {
        return Err(CompressionError::UnsupportedMethod);
    }

    let flag = input[3];
    let mtime = (input[4] as u32)
        | ((input[5] as u32) << 8)
        | ((input[6] as u32) << 16)
        | ((input[7] as u32) << 24);

    let mut offset = 10usize;

    // Пропуск FEXTRA
    if (flag & FLAG_FEXTRA) != 0 {
        if offset + 2 > input.len() {
            return Err(CompressionError::CorruptedData);
        }
        let xlen = (input[offset] as usize) | ((input[offset + 1] as usize) << 8);
        offset += 2 + xlen;
    }

    // Извлечение имени файла (FNAME)
    let mut filename = None;
    if (flag & FLAG_FNAME) != 0 {
        let start = offset;
        while offset < input.len() && input[offset] != 0 {
            offset += 1;
        }
        if offset >= input.len() {
            return Err(CompressionError::CorruptedData);
        }
        filename = core::str::from_utf8(&input[start..offset]).ok();
        offset += 1; // Пропускаем нуль-терминатор
    }

    // Пропуск FCOMMENT
    if (flag & FLAG_FCOMMENT) != 0 {
        while offset < input.len() && input[offset] != 0 {
            offset += 1;
        }
        if offset >= input.len() {
            return Err(CompressionError::CorruptedData);
        }
        offset += 1;
    }

    // Пропуск FHCRC (2 байта)
    if (flag & FLAG_FHCRC) != 0 {
        offset += 2;
    }

    if offset + 8 > input.len() {
        return Err(CompressionError::CorruptedData);
    }

    let compressed_data = &input[offset..input.len() - 8];
    let trailer = &input[input.len() - 8..];

    let expected_crc = (trailer[0] as u32)
        | ((trailer[1] as u32) << 8)
        | ((trailer[2] as u32) << 16)
        | ((trailer[3] as u32) << 24);

    let expected_isize = (trailer[4] as u32)
        | ((trailer[5] as u32) << 8)
        | ((trailer[6] as u32) << 16)
        | ((trailer[7] as u32) << 24);

    let mut hasher = Crc32::new();
    let mut total_uncompressed = 0usize;

    let uncompressed_len = inflate(compressed_data, |chunk| {
        hasher.update(chunk);
        total_uncompressed += chunk.len();
        output_fn(chunk)
    })?;

    if hasher.finish() != expected_crc {
        return Err(CompressionError::ChecksumMismatch);
    }

    if (total_uncompressed as u32) != expected_isize {
        return Err(CompressionError::SizeMismatch);
    }

    Ok((
        uncompressed_len,
        GzipHeader {
            mtime,
            filename,
        },
    ))
}
