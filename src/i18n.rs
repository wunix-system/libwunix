use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Language {
    Russian,
    English,
}

static DETECTED_LANG: AtomicU8 = AtomicU8::new(0); // 0 = uninit, 1 = Russian, 2 = English

/// Возвращает активный системный язык операционной системы Wunix.
/// Определяется однократно через /etc/locale и кэшируется в атомарной переменной,
/// обеспечивая нулевые накладные расходы при повторных обращениях.
pub fn current_language() -> Language {
    match DETECTED_LANG.load(Ordering::Relaxed) {
        1 => Language::Russian,
        2 => Language::English,
        _ => {
            let mut buf = [0u8; 32];
            let fd = crate::open(b"/etc/locale\0", 0, 0);
            let lang = if fd >= 0 {
                let n = crate::read(fd as u64, &mut buf);
                let _ = crate::close(fd as u64);
                if n > 0 {
                    let slice = &buf[..(n as usize).min(32)];
                    if slice.starts_with(b"en")
                        || slice.starts_with(b"EN")
                        || slice.windows(7).any(|w| w == b"LANG=en")
                    {
                        Language::English
                    } else {
                        Language::Russian
                    }
                } else {
                    Language::Russian
                }
            } else {
                Language::Russian
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
