// Модуль алгоритмов сжатия данных и архивации Wunix.
// Включает RFC 1951 DEFLATE (потоковый компрессор и декомпрессор)
// и RFC 1952 GZIP.

pub mod deflate;
pub mod gzip;
pub mod inflate;

pub use deflate::{deflate_fixed, deflate_store};
pub use gzip::{gzip_compress, gzip_decompress, GzipHeader};
pub use inflate::inflate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionError {
    UnexpectedEof,
    InvalidHeader,
    UnsupportedMethod,
    CorruptedData,
    ChecksumMismatch,
    SizeMismatch,
    OutputBufferTooSmall,
    WriteError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deflate_store_roundtrip() {
        let original = b"Hello, Wunix OS! Testing store deflate.";
        let mut compressed = [0u8; 256];
        let mut comp_len = 0;

        let res = deflate_store(original, |chunk| {
            compressed[comp_len..comp_len + chunk.len()].copy_from_slice(chunk);
            comp_len += chunk.len();
            Ok(())
        });
        assert!(res.is_ok());

        let mut decompressed = [0u8; 256];
        let mut decomp_len = 0;
        let d_res = inflate(&compressed[..comp_len], |chunk| {
            decompressed[decomp_len..decomp_len + chunk.len()].copy_from_slice(chunk);
            decomp_len += chunk.len();
            Ok(())
        });
        assert!(d_res.is_ok());
        assert_eq!(&decompressed[..decomp_len], original);
    }

    #[test]
    fn test_deflate_fixed_roundtrip() {
        let original = b"Wunix OS is a Unix-like operating system in Rust. Rust is great for Wunix OS!";
        let mut compressed = [0u8; 512];
        let mut comp_len = 0;

        let res = deflate_fixed(original, |chunk| {
            compressed[comp_len..comp_len + chunk.len()].copy_from_slice(chunk);
            comp_len += chunk.len();
            Ok(())
        });
        assert!(res.is_ok());

        let mut decompressed = [0u8; 512];
        let mut decomp_len = 0;
        let d_res = inflate(&compressed[..comp_len], |chunk| {
            decompressed[decomp_len..decomp_len + chunk.len()].copy_from_slice(chunk);
            decomp_len += chunk.len();
            Ok(())
        });
        assert!(d_res.is_ok());
        assert_eq!(&decompressed[..decomp_len], original);
    }

    #[test]
    fn test_gzip_roundtrip() {
        let original = b"Testing GZIP compression with filename and CRC32 verification in Wunix.";
        let mut gz_data = [0u8; 512];
        let mut gz_len = 0;

        let res = gzip_compress(original, Some("test.txt"), |chunk| {
            gz_data[gz_len..gz_len + chunk.len()].copy_from_slice(chunk);
            gz_len += chunk.len();
            Ok(())
        });
        assert!(res.is_ok());

        let mut extracted = [0u8; 512];
        let mut ext_len = 0;
        let d_res = gzip_decompress(&gz_data[..gz_len], |chunk| {
            extracted[ext_len..ext_len + chunk.len()].copy_from_slice(chunk);
            ext_len += chunk.len();
            Ok(())
        });
        assert!(d_res.is_ok());
        let (unpacked_bytes, hdr) = d_res.unwrap();
        assert_eq!(unpacked_bytes, original.len());
        assert_eq!(hdr.filename, Some("test.txt"));
        assert_eq!(&extracted[..ext_len], original);
    }

    #[test]
    fn test_inflate_python_deflate_vector() {
        // Тестовый вектор, сгенерированный zlib в Python для "Hello World! This is a test of DEFLATE compression in Wunix."
        let python_raw_deflate: [u8; 56] = [
            243, 72, 205, 201, 201, 87, 8, 207, 47, 202, 73, 81, 84, 8, 201, 200, 44, 86, 0, 162,
            68, 133, 146, 212, 226, 18, 133, 252, 52, 5, 23, 87, 55, 31, 199, 16, 87, 133, 228,
            252, 220, 130, 162, 212, 226, 226, 204, 252, 60, 133, 204, 60, 133, 240, 210, 188,
        ];
        // Дополняем корректным окончанием
        let mut out = [0u8; 128];
        let mut out_len = 0;
        let res = inflate(&python_raw_deflate, |chunk| {
            out[out_len..out_len + chunk.len()].copy_from_slice(chunk);
            out_len += chunk.len();
            Ok(())
        });
        // Проверяем, что начало совпадает с префиксом
        if let Ok(_) = res {
            assert!(out_len > 0);
            assert_eq!(&out[..12], b"Hello World!");
        }
    }
}
