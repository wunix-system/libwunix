use core::sync::atomic::{AtomicUsize, Ordering};

static ENVIRON: AtomicUsize = AtomicUsize::new(0);

pub fn init(envp: *const *const u8) {
    ENVIRON.store(envp as usize, Ordering::SeqCst);
}

pub fn getenv(key: &str) -> Option<&'static str> {
    let envp = ENVIRON.load(Ordering::Relaxed) as *const *const u8;
    if envp.is_null() {
        return None;
    }

    let mut idx = 0;
    loop {
        let entry_ptr = unsafe { *envp.add(idx) };
        if entry_ptr.is_null() {
            break;
        }

        let len = super::str_utils::strlen(entry_ptr);
        if let Ok(s) = core::str::from_utf8(unsafe { core::slice::from_raw_parts(entry_ptr, len) }) {
            if let Some((k, v)) = s.split_once('=') {
                if k == key {
                    return Some(v);
                }
            }
        }
        idx += 1;
    }
    None
}

pub fn environ() -> EnvIter {
    EnvIter {
        ptr: ENVIRON.load(Ordering::Relaxed) as *const *const u8,
        idx: 0,
    }
}

pub struct EnvIter {
    ptr: *const *const u8,
    idx: usize,
}

impl Iterator for EnvIter {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ptr.is_null() {
            return None;
        }

        let entry_ptr = unsafe { *self.ptr.add(self.idx) };
        if entry_ptr.is_null() {
            return None;
        }

        self.idx += 1;
        let len = super::str_utils::strlen(entry_ptr);
        core::str::from_utf8(unsafe { core::slice::from_raw_parts(entry_ptr, len) }).ok()
    }
}
