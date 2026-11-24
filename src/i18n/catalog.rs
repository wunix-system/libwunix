//! Модуль загрузки и хранения каталога переводов в памяти.
//! Обеспечивает нулевые накладные расходы на аллокации (zero-alloc) и быстрое сопоставление строк.

use super::locale::{extract_lang_code, get_active_locale};
use super::parser::parse_catalog;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

const MAX_CATALOG_SIZE: usize = 32768;
const MAX_ENTRIES: usize = 512;

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

static CATALOG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CATALOG_BUFFER: SyncCell<[u8; MAX_CATALOG_SIZE]> = SyncCell::new([0u8; MAX_CATALOG_SIZE]);
static CATALOG_ENTRIES: SyncCell<[(&'static str, &'static str); MAX_ENTRIES]> =
    SyncCell::new([("", ""); MAX_ENTRIES]);
static CATALOG_COUNT: SyncCell<usize> = SyncCell::new(0);

static LOADED_LOCALE: SyncCell<[u8; 32]> = SyncCell::new([0u8; 32]);
static LOADED_DOMAIN: SyncCell<[u8; 32]> = SyncCell::new([0u8; 32]);

// Встроенная резервная таблица для русского языка (fallback при отсутствии файлов на диске)
static BUILTIN_RU_FALLBACK: &[(&str, &str)] = &[
    ("wunix: system ready", "wunix: система готова к работе"),
    ("^C (input cancelled)", "^C (ввод отменен)"),
    ("permission denied: ", "отказано в доступе: "),
    ("command not found: ", "команда не найдена: "),
    ("touch: cannot touch '", "touch: невозможно создать '"),
    ("': failed to create file\n", "': ошибка создания файла\n"),
    ("cat: read error\n", "cat: ошибка чтения\n"),
    ("chown: path too long\n", "chown: путь слишком длинный\n"),
    ("chown: cannot access '", "chown: невозможно получить доступ к '"),
    ("': No such file or directory\n", "': Нет такого файла или каталога\n"),
    ("': Operation not permitted\n", "': Операция не позволена\n"),
    ("': Permission denied\n", "': Отказано в доступе\n"),
    ("chmod: path too long\n", "chmod: путь слишком длинный\n"),
    ("chmod: cannot access '", "chmod: невозможно получить доступ к '"),
    ("chmod: invalid symbolic mode\n", "chmod: неверный символьный режим\n"),
    ("chmod: changing permissions of '", "chmod: изменение прав для '"),
    ("id: user '", "id: пользователь '"),
    ("': no such user\n", "': не найден\n"),
    ("wsh: cd: OLDPWD not set\n", "wsh: cd: переменная OLDPWD не задана\n"),
    ("wsh: type: missing operand\n", "wsh: type: пропущен аргумент\n"),
    ("is a shell builtin", "является встроенной командой шелла"),
    ("is", "это"),
    ("not found", "не найдено"),
    ("wsh: .: filename argument required\n", "wsh: .: требуется имя файла\n"),
    ("wsh: cannot open script: ", "wsh: не удалось открыть скрипт: "),
];

fn copy_slice_to_buf(dst: &mut [u8], src: &[u8]) -> usize {
    let len = src.len().min(dst.len());
    dst[..len].copy_from_slice(&src[..len]);
    len
}

fn build_path(
    out: &mut [u8; 128],
    prefix: &str,
    locale: &str,
    mid: &str,
    domain: &str,
    ext: &str,
) -> bool {
    let mut pos = 0;
    for part in &[prefix, locale, mid, domain, ext, "\0"] {
        let b = part.as_bytes();
        if pos + b.len() > out.len() {
            return false;
        }
        out[pos..pos + b.len()].copy_from_slice(b);
        pos += b.len();
    }
    true
}

fn try_read_catalog_file(path_bytes: &[u8]) -> bool {
    let fd = crate::open(path_bytes, 0, 0);
    if fd < 0 {
        return false;
    }
    let buf_ptr = CATALOG_BUFFER.get();
    let n = unsafe {
        crate::read(fd as u64, &mut *buf_ptr)
    };
    let _ = crate::close(fd as u64);

    if n > 0 {
        unsafe {
            let slice = &mut (&mut *buf_ptr)[..(n as usize).min(MAX_CATALOG_SIZE)];
            let entries = &mut *CATALOG_ENTRIES.get();
            *CATALOG_COUNT.get() = parse_catalog(slice, entries);
        }
        true
    } else {
        false
    }
}

/// Загружает каталог локализации для указанного домена и текущей активной локали.
pub fn load_catalog_for_domain(domain: &str) {
    let active_locale = get_active_locale();
    let lang_code = extract_lang_code(active_locale);

    unsafe {
        copy_slice_to_buf(&mut *LOADED_LOCALE.get(), active_locale.as_bytes());
        copy_slice_to_buf(&mut *LOADED_DOMAIN.get(), domain.as_bytes());
        *CATALOG_COUNT.get() = 0;

        let mut path_buf = [0u8; 128];

        // Кандидаты поиска каталога:
        // 1. /usr/share/locale/<locale>/LC_MESSAGES/<domain>.strings
        // 2. /usr/share/locale/<lang>/LC_MESSAGES/<domain>.strings
        // 3. /usr/share/locale/<locale>/<domain>.strings
        // 4. /usr/share/locale/<lang>/<domain>.strings
        let candidates = [
            (active_locale, "/LC_MESSAGES/"),
            (lang_code, "/LC_MESSAGES/"),
            (active_locale, "/"),
            (lang_code, "/"),
        ];

        let mut loaded = false;
        for (loc, mid) in &candidates {
            if build_path(&mut path_buf, "/usr/share/locale/", loc, mid, domain, ".strings") {
                if try_read_catalog_file(&path_buf) {
                    loaded = true;
                    break;
                }
            }
        }

        // Если домен специфический и не найден, пробуем загрузить общий домен wunix.strings
        if !loaded && domain != "wunix" {
            for (loc, mid) in &candidates {
                if build_path(&mut path_buf, "/usr/share/locale/", loc, mid, "wunix", ".strings") {
                    if try_read_catalog_file(&path_buf) {
                        break;
                    }
                }
            }
        }

        CATALOG_INITIALIZED.store(true, Ordering::Release);
    }
}

/// Ищет перевод строки в загруженном каталоге или встроенной таблице.
pub fn lookup_message(msgid: &str, domain: &str) -> Option<&'static str> {
    if !CATALOG_INITIALIZED.load(Ordering::Acquire) {
        load_catalog_for_domain(domain);
    }

    unsafe {
        let count = *CATALOG_COUNT.get();
        let entries = &*CATALOG_ENTRIES.get();
        for i in 0..count {
            if entries[i].0 == msgid {
                return Some(entries[i].1);
            }
        }
    }

    // Если перевод не найден в файле, проверяем встроенный fallback для русского языка
    let active_locale = get_active_locale();
    if active_locale.starts_with("ru") {
        for &(k, v) in BUILTIN_RU_FALLBACK {
            if k == msgid {
                return Some(v);
            }
        }
    }

    None
}

/// Принудительно перезагружает каталог (например, после смены переменной LANG).
pub fn reload_catalog() {
    CATALOG_INITIALIZED.store(false, Ordering::Release);
}
