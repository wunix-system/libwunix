use crate::{read, write, STDIN_FILENO, STDOUT_FILENO};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LineMode {
    Echo,
    Masked(u8),
}

/// Удаляет байты последнего введенного символа из буфера.
/// Корректно учитывает как однобайтовые ASCII символы, так и многобайтовую кодировку
/// UTF-8 (например, кириллицу), где символ состоит из лидирующего байта и байтов продолжения.
pub fn pop_last_char_bytes(buf: &[u8], total: &mut usize) -> bool {
    if *total == 0 {
        return false;
    }
    loop {
        if *total == 0 {
            break;
        }
        *total -= 1;
        let prev = buf[*total];
        // Если байт не является продолжением UTF-8 (0x80..=0xBF), значит мы сняли весь символ
        if (prev & 0xC0) != 0x80 {
            break;
        }
    }
    true
}

/// Считывает одну строку из стандартного ввода STDIN_FILENO.
/// Для обычного ввода (Echo) отображает символы как есть.
/// Для скрытого пароля с маскировкой (Masked) отображает заданный символ (например, '*').
pub fn read_line_with_mode<'a>(buf: &'a mut [u8], mode: LineMode) -> Option<&'a str> {
    let mut total = 0;
    while total < buf.len() {
        let mut b = [0u8; 1];
        let n = read(STDIN_FILENO, &mut b);
        if n == 0 {
            if total == 0 {
                return None;
            }
            break;
        }

        let byte = b[0];

        // Завершение строки по нажатию Enter (\n или \r)
        if byte == b'\n' || byte == b'\r' {
            write(STDOUT_FILENO, b"\n");
            break;
        }

        // Прерывание ввода по Ctrl+C
        if byte == 3 {
            write(STDOUT_FILENO, b"^C\n");
            return None;
        }

        // Завершение ввода по Ctrl+D (EOF)
        if byte == 4 {
            if total == 0 {
                return None;
            }
            write(STDOUT_FILENO, b"\n");
            break;
        }

        // Очистка всей строки по Ctrl+U
        if byte == 21 {
            while pop_last_char_bytes(buf, &mut total) {
                write(STDOUT_FILENO, b"\x08 \x08");
            }
            continue;
        }

        // Удаление символа по Backspace (0x08) или DEL (0x7F)
        if byte == 8 || byte == 127 {
            if pop_last_char_bytes(buf, &mut total) {
                write(STDOUT_FILENO, b"\x08 \x08");
            }
            continue;
        }

        // Игнорируем остальные непечатные управляющие коды
        if byte < 0x20 {
            continue;
        }

        buf[total] = byte;
        total += 1;

        match mode {
            LineMode::Echo => {
                write(STDOUT_FILENO, &[byte]);
            }
            LineMode::Masked(mask) => {
                // В UTF-8 выводим звездочку только на лидирующий байт или ASCII,
                // чтобы двухбайтовая русская буква печатала ровно одну '*'
                if (byte & 0xC0) != 0x80 {
                    write(STDOUT_FILENO, &[mask]);
                }
            }
        }
    }

    core::str::from_utf8(&buf[..total]).ok()
}

/// Считывает имя пользователя или обычный текст со стандартным эхо-выводом.
pub fn read_line<'a>(buf: &'a mut [u8]) -> Option<&'a str> {
    read_line_with_mode(buf, LineMode::Echo)
}

/// Считывает пароль с отображением маскирующего символа '*' для каждого введенного знака.
pub fn read_password_masked<'a>(buf: &'a mut [u8]) -> Option<&'a str> {
    read_line_with_mode(buf, LineMode::Masked(b'*'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop_last_char_ascii() {
        let mut buf = [0u8; 16];
        buf[0] = b'x';
        buf[1] = b'y';
        let mut total = 2;

        assert!(pop_last_char_bytes(&buf, &mut total));
        assert_eq!(total, 1);
        assert_eq!(&buf[..total], b"x");

        assert!(pop_last_char_bytes(&buf, &mut total));
        assert_eq!(total, 0);

        assert!(!pop_last_char_bytes(&buf, &mut total));
    }

    #[test]
    fn test_pop_last_char_utf8() {
        let mut buf = [0u8; 16];
        // Буква 'ю' в UTF-8: 0xD1, 0x8E
        buf[0] = 0xD1;
        buf[1] = 0x8E;
        let mut total = 2;

        assert!(pop_last_char_bytes(&buf, &mut total));
        assert_eq!(total, 0);
    }
}
