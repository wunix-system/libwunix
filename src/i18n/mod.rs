//! Подсистема интернационализации и локализации Wunix (i18n / l10n).
//! Совместима с архитектурными стандартами Linux (GNU gettext) и macOS (.strings catalogs).
//!
//! Обеспечивает:
//! - Полное разделение исходного кода и переводов через внешние файлы на диске (`/usr/share/locale/<lang>/...`).
//! - Поддержку динамического добавления любых новых языков (ru, en, de, fr, es, etc.) без перекомпиляции ядра или программ.
//! - Стандартную иерархию POSIX переменных окружения (`LC_ALL` > `LC_MESSAGES` > `LANG` > `/etc/locale`).
//! - Zero-allocation архитектуру для Ring 3 (работает даже в самых минимальных no_std утилитах).

pub mod catalog;
pub mod locale;
pub mod parser;

pub use catalog::reload_catalog;
pub use locale::{get_active_locale, set_locale_str};

/// Обратная совместимость с устаревшим перечислением языков
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Language {
    Russian,
    English,
}

/// Возвращает активную строку системной локали (например, "ru_RU.UTF-8", "en_US.UTF-8", "de_DE.UTF-8").
#[inline]
pub fn current_locale() -> &'static str {
    get_active_locale()
}

/// Устанавливает активную локаль в памяти текущего процесса.
#[inline]
pub fn set_locale(loc: &str) {
    set_locale_str(loc);
    reload_catalog();
}

/// Возвращает текущий системный язык в виде устаревшего enum Language (для обратной совместимости).
pub fn current_language() -> Language {
    let loc = get_active_locale();
    if loc.starts_with("en") || loc.starts_with("EN") {
        Language::English
    } else {
        Language::Russian
    }
}

/// Основная функция перевода: ищет перевод msgid в каталоге активной локали.
/// Если перевод не найден или файл отсутствует, возвращает исходный msgid.
#[inline]
pub fn tr(msgid: &'static str) -> &'static str {
    catalog::lookup_message(msgid, "wunix").unwrap_or(msgid)
}

/// Стандартный POSIX / gettext псевдоним для tr()
#[inline]
pub fn gettext(msgid: &'static str) -> &'static str {
    tr(msgid)
}

/// Перевод с явным указанием домена (имени каталога) программы
#[inline]
pub fn dgettext(domain: &str, msgid: &'static str) -> &'static str {
    catalog::lookup_message(msgid, domain).unwrap_or(msgid)
}

/// Совместимая функция выбора перевода пары строк (RU / EN).
/// Сначала пытается найти перевод для активной локали в загруженном каталоге,
/// а при его отсутствии использует fallback по коду языка (RU или EN).
#[inline]
pub fn t(ru: &'static str, en: &'static str) -> &'static str {
    let loc = get_active_locale();
    if loc.starts_with("en") || loc.starts_with("EN") {
        return en;
    }
    if let Some(trans) = catalog::lookup_message(en, "wunix")
        .or_else(|| catalog::lookup_message(ru, "wunix"))
    {
        return trans;
    }
    if loc.starts_with("ru") || loc.starts_with("RU") {
        ru
    } else {
        en
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locale_and_translation_fallback() {
        set_locale("en_US.UTF-8");
        assert_eq!(current_locale(), "en_US.UTF-8");
        assert_eq!(current_language(), Language::English);
        assert_eq!(t("Привет", "Hello"), "Hello");
        assert_eq!(tr("Unknown string"), "Unknown string");

        set_locale("ru_RU.UTF-8");
        assert_eq!(current_locale(), "ru_RU.UTF-8");
        assert_eq!(current_language(), Language::Russian);
        assert_eq!(t("Привет", "Hello"), "Привет");
        // Проверяем встроенный fallback для стандартного сообщения
        assert_eq!(tr("wunix: system ready"), "wunix: система готова к работе");
    }
}
