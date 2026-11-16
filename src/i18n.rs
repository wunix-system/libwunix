use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Language {
    Russian,
    English,
}

static DETECTED_LANG: AtomicU8 = AtomicU8::new(0); // 0 = uninit, 1 = Russian, 2 = English

fn parse_lang_bytes(slice: &[u8]) -> Language {
    if slice.starts_with(b"en")
        || slice.starts_with(b"EN")
        || slice.windows(7).any(|w| w == b"LANG=en")
        || slice.windows(9).any(|w| w == b"LC_ALL=en")
    {
        Language::English
    } else {
        Language::Russian
    }
}

/// Возвращает активный системный язык операционной системы Wunix.
/// Определяется однократно через переменные окружения (LC_ALL/LANG) или /etc/locale
/// и кэшируется в атомарной переменной, обеспечивая нулевые накладные расходы при повторных обращениях.
pub fn current_language() -> Language {
    match DETECTED_LANG.load(Ordering::Relaxed) {
        1 => Language::Russian,
        2 => Language::English,
        _ => {
            let lang = if let Some(v) = crate::env::getenv("LC_ALL").or_else(|| crate::env::getenv("LANG")) {
                if v.starts_with("en") || v.starts_with("EN") {
                    Language::English
                } else {
                    Language::Russian
                }
            } else {
                let mut buf = [0u8; 64];
                let fd = crate::open(b"/etc/locale\0", 0, 0);
                if fd >= 0 {
                    let n = crate::read(fd as u64, &mut buf);
                    let _ = crate::close(fd as u64);
                    if n > 0 {
                        parse_lang_bytes(&buf[..(n as usize).min(64)])
                    } else {
                        Language::Russian
                    }
                } else {
                    Language::Russian
                }
            };
            DETECTED_LANG.store(
                if lang == Language::Russian { 1 } else { 2 },
                Ordering::Relaxed,
            );
            lang
        }
    }
}

/// Возвращает вариант строки для активного языка системы (русский или английский).
#[inline]
pub fn t(ru: &'static str, en: &'static str) -> &'static str {
    match current_language() {
        Language::Russian => ru,
        Language::English => en,
    }
}
