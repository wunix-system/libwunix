//! Модуль определения и разрешения системной локали (POSIX / macOS совместимый).
//! Иерархия приоритетов:
//! 1. Переменная окружения `LC_ALL`
//! 2. Переменная окружения `LC_MESSAGES`
//! 3. Переменная окружения `LANG`
//! 4. Файл конфигурации `/etc/locale`
//! 5. Системный fallback (`en_US.UTF-8` / `C` / `ru_RU.UTF-8`)

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

pub const DEFAULT_LOCALE: &str = "ru_RU.UTF-8";
pub const FALLBACK_LOCALE: &str = "en_US.UTF-8";

#[repr(transparent)]
struct SyncCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for SyncCell<T> {}
impl<T> SyncCell<T> {
    const fn new(val: T) -> Self {
        Self(UnsafeCell::new(val))
    }
    #[inline(always)]
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

static LOCALE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CACHED_LOCALE: SyncCell<[u8; 32]> = SyncCell::new([0u8; 32]);
static CACHED_LOCALE_LEN: SyncCell<usize> = SyncCell::new(0);

/// Извлекает 2-3 буквенный код языка из полной строки локали (например, "ru" из "ru_RU.UTF-8").
pub fn extract_lang_code(locale: &str) -> &str {
    let clean = locale.trim();
    if let Some(idx) = clean.find('_') {
        &clean[..idx]
    } else if let Some(idx) = clean.find('.') {
        &clean[..idx]
    } else {
        clean
    }
}

/// Разбирает байты файла /etc/locale и извлекает имя локали.
pub fn parse_locale_file_bytes(bytes: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(bytes).ok()?;
    // Сначала ищем LC_ALL=
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("LC_ALL=") {
            let val = rest.trim().trim_matches('"').trim_matches('\'');
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    // Затем ищем LANG=
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("LANG=") {
            let val = rest.trim().trim_matches('"').trim_matches('\'');
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Принудительно устанавливает активную локаль в памяти процесса.
pub fn set_locale_str(new_locale: &str) {
    let trimmed = new_locale.trim();
    let bytes = trimmed.as_bytes();
    let copy_len = bytes.len().min(31);
    unsafe {
        let buf = &mut *CACHED_LOCALE.get();
        buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        buf[copy_len] = 0;
        *CACHED_LOCALE_LEN.get() = copy_len;
    }
    LOCALE_INITIALIZED.store(true, Ordering::Release);
}

/// Сбрасывает кэш для повторного автоопределения из окружения.
pub fn reset_locale_cache() {
    LOCALE_INITIALIZED.store(false, Ordering::Release);
}

/// Возвращает активную локаль системы в виде строкового среза.
pub fn get_active_locale() -> &'static str {
    if !LOCALE_INITIALIZED.load(Ordering::Acquire) {
        init_locale();
    }
    unsafe {
        let len = *CACHED_LOCALE_LEN.get();
        if len > 0 {
            let buf = &*CACHED_LOCALE.get();
            core::str::from_utf8_unchecked(&buf[..len])
        } else {
            DEFAULT_LOCALE
        }
    }
}

fn init_locale() {
    // 1. Проверяем переменные окружения
    if let Some(val) = crate::env::getenv("LC_ALL")
        .or_else(|| crate::env::getenv("LC_MESSAGES"))
        .or_else(|| crate::env::getenv("LANG"))
    {
        if !val.trim().is_empty() {
            set_locale_str(val);
            return;
        }
    }

    // 2. Читаем /etc/locale
    let mut buf = [0u8; 128];
    let fd = crate::open(b"/etc/locale\0", 0, 0);
    if fd >= 0 {
        let n = crate::read(fd as u64, &mut buf);
        let _ = crate::close(fd as u64);
        if n > 0 {
            let slice = &buf[..(n as usize).min(128)];
            if let Some(loc) = parse_locale_file_bytes(slice) {
                set_locale_str(loc);
                return;
            }
        }
    }

    // 3. Системный fallback
    set_locale_str(DEFAULT_LOCALE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_lang_code() {
        assert_eq!(extract_lang_code("ru_RU.UTF-8"), "ru");
        assert_eq!(extract_lang_code("en_US.UTF-8"), "en");
        assert_eq!(extract_lang_code("de_DE"), "de");
        assert_eq!(extract_lang_code("fr"), "fr");
    }

    #[test]
    fn test_parse_locale_file() {
        let content = b"LANG=ru_RU.UTF-8\nLC_ALL=ru_RU.UTF-8\n";
        assert_eq!(parse_locale_file_bytes(content), Some("ru_RU.UTF-8"));

        let content_lang_only = b"# Locale config\nLANG=\"en_US.UTF-8\"\n";
        assert_eq!(parse_locale_file_bytes(content_lang_only), Some("en_US.UTF-8"));
    }
}
