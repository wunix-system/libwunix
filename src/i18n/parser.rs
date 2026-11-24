//! Модуль синтаксического анализа каталогов локализации.
//! Поддерживает стандартные файлы Apple `.strings` (`"key" = "value";`),
//! GNU gettext `.po` (`msgid "..."` / `msgstr "..."`), а также комментарии `/* ... */`, `//`, `#`.

/// Выполняет in-place разэкранирование спецсимволов (`\n`, `\t`, `\r`, `\"`, `\\`).
/// Возвращает количество записанных байт (всегда <= len исходного среза).
pub fn unescape_in_place(buf: &mut [u8]) -> usize {
    let mut read_idx = 0;
    let mut write_idx = 0;
    let len = buf.len();

    while read_idx < len {
        if buf[read_idx] == b'\\' && read_idx + 1 < len {
            read_idx += 1;
            match buf[read_idx] {
                b'n' => buf[write_idx] = b'\n',
                b't' => buf[write_idx] = b'\t',
                b'r' => buf[write_idx] = b'\r',
                b'"' => buf[write_idx] = b'"',
                b'\\' => buf[write_idx] = b'\\',
                other => {
                    buf[write_idx] = b'\\';
                    write_idx += 1;
                    buf[write_idx] = other;
                }
            }
            write_idx += 1;
            read_idx += 1;
        } else {
            buf[write_idx] = buf[read_idx];
            write_idx += 1;
            read_idx += 1;
        }
    }
    write_idx
}

/// Извлекает строковый литерал в кавычках из среза байтов.
/// Возвращает диапазон индексов содержимого строки (без кавычек) и индекс после закрывающей кавычки.
fn extract_quoted_string(bytes: &[u8], start: usize) -> Option<((usize, usize), usize)> {
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'"' {
        return None;
    }
    i += 1; // Пропускаем открывающую кавычку
    let content_start = i;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // Пропускаем экранированный символ
            continue;
        }
        if bytes[i] == b'"' {
            let content_end = i;
            return Some(((content_start, content_end), i + 1));
        }
        i += 1;
    }
    None
}

/// Парсит буфер каталога локализации в массив пар (&'static str, &'static str).
/// Так как буфер статический, возвращаемые срезы имеют время жизни 'a.
pub fn parse_catalog<'a>(
    buf: &'a mut [u8],
    out: &mut [(&'a str, &'a str)],
) -> usize {
    let mut count = 0;
    let mut pos = 0;
    let len = buf.len();
    let base_ptr = buf.as_mut_ptr();

    while pos < len && count < out.len() {
        // Пропускаем пробелы и пустые строки
        while pos < len && (buf[pos].is_ascii_whitespace() || buf[pos] == b';') {
            pos += 1;
        }
        if pos >= len {
            break;
        }

        // Пропускаем однострочные комментарии // и #
        if (buf[pos] == b'/' && pos + 1 < len && buf[pos + 1] == b'/') || buf[pos] == b'#' {
            while pos < len && buf[pos] != b'\n' {
                pos += 1;
            }
            continue;
        }

        // Пропускаем многострочные комментарии /* ... */
        if buf[pos] == b'/' && pos + 1 < len && buf[pos + 1] == b'*' {
            pos += 2;
            while pos + 1 < len && !(buf[pos] == b'*' && buf[pos + 1] == b'/') {
                pos += 1;
            }
            if pos + 1 < len {
                pos += 2;
            }
            continue;
        }

        // 1. Формат GNU gettext: msgid "..." / msgstr "..."
        if buf[pos..].starts_with(b"msgid") && pos + 5 < len && buf[pos + 5].is_ascii_whitespace() {
            pos += 5;
            let Some((key_span, next_pos)) = extract_quoted_string(buf, pos) else {
                continue;
            };
            pos = next_pos;

            // Ищем соответствующий msgstr
            while pos < len && buf[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if buf[pos..].starts_with(b"msgstr") && pos + 6 < len && buf[pos + 6].is_ascii_whitespace() {
                pos += 6;
                let Some((val_span, next_pos)) = extract_quoted_string(buf, pos) else {
                    continue;
                };
                pos = next_pos;

                let (k, v) = unsafe {
                    let k_slice = core::slice::from_raw_parts_mut(
                        base_ptr.add(key_span.0),
                        key_span.1 - key_span.0,
                    );
                    let k_len = unescape_in_place(k_slice);

                    let v_slice = core::slice::from_raw_parts_mut(
                        base_ptr.add(val_span.0),
                        val_span.1 - val_span.0,
                    );
                    let v_len = unescape_in_place(v_slice);

                    let k_str = core::str::from_utf8(core::slice::from_raw_parts(
                        base_ptr.add(key_span.0),
                        k_len,
                    ));
                    let v_str = core::str::from_utf8(core::slice::from_raw_parts(
                        base_ptr.add(val_span.0),
                        v_len,
                    ));
                    (k_str, v_str)
                };

                if let (Ok(key), Ok(val)) = (k, v) {
                    if !key.is_empty() {
                        out[count] = (key, val);
                        count += 1;
                    }
                }
            }
            continue;
        }

        // 2. Формат macOS .strings: "key" = "value";
        if buf[pos] == b'"' {
            let Some((key_span, next_pos)) = extract_quoted_string(buf, pos) else {
                pos += 1;
                continue;
            };
            pos = next_pos;

            // Пропускаем пробелы до знака '='
            while pos < len && buf[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos < len && buf[pos] == b'=' {
                pos += 1;
                let Some((val_span, next_pos)) = extract_quoted_string(buf, pos) else {
                    continue;
                };
                pos = next_pos;

                let (k, v) = unsafe {
                    let k_slice = core::slice::from_raw_parts_mut(
                        base_ptr.add(key_span.0),
                        key_span.1 - key_span.0,
                    );
                    let k_len = unescape_in_place(k_slice);

                    let v_slice = core::slice::from_raw_parts_mut(
                        base_ptr.add(val_span.0),
                        val_span.1 - val_span.0,
                    );
                    let v_len = unescape_in_place(v_slice);

                    let k_str = core::str::from_utf8(core::slice::from_raw_parts(
                        base_ptr.add(key_span.0),
                        k_len,
                    ));
                    let v_str = core::str::from_utf8(core::slice::from_raw_parts(
                        base_ptr.add(val_span.0),
                        v_len,
                    ));
                    (k_str, v_str)
                };

                if let (Ok(key), Ok(val)) = (k, v) {
                    out[count] = (key, val);
                    count += 1;
                }
            }
            continue;
        }

        pos += 1;
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unescape_in_place() {
        let mut text = *b"Hello\\nWorld\\t\\\"Test\\\\\"";
        let len = unescape_in_place(&mut text);
        assert_eq!(&text[..len], b"Hello\nWorld\t\"Test\\\"");
    }

    #[test]
    fn test_parse_macos_strings() {
        let text = "\
/* Комментарий заголовка */
\"hello\" = \"Привет\";
// Однострочный комментарий
\"world\" = \"Мир\";
# Комментарий в стиле Unix
\"test\\nline\" = \"тест\\nстрока\";
";
        let mut input = [0u8; 512];
        let bytes = text.as_bytes();
        input[..bytes.len()].copy_from_slice(bytes);

        let mut entries = [("", ""); 8];
        let n = parse_catalog(&mut input[..bytes.len()], &mut entries);
        assert_eq!(n, 3);
        assert_eq!(entries[0], ("hello", "Привет"));
        assert_eq!(entries[1], ("world", "Мир"));
        assert_eq!(entries[2], ("test\nline", "тест\nстрока"));
    }

    #[test]
    fn test_parse_gettext_po() {
        let text = "\
# gettext catalog
msgid \"save\"
msgstr \"сохранить\"

msgid \"cancel\"
msgstr \"отмена\"
";
        let mut input = [0u8; 512];
        let bytes = text.as_bytes();
        input[..bytes.len()].copy_from_slice(bytes);

        let mut entries = [("", ""); 8];
        let n = parse_catalog(&mut input[..bytes.len()], &mut entries);
        assert_eq!(n, 2);
        assert_eq!(entries[0], ("save", "сохранить"));
        assert_eq!(entries[1], ("cancel", "отмена"));
    }
}
