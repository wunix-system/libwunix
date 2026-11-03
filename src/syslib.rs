pub const SYSLIB_INFO_VADDR: u64 = 0x0000_7FFF_FFFF_0000;
pub const SYSLIB_MAGIC: [u8; 8] = *b"WUNIXLIB";
pub const MAX_SYSLIB_SYMBOLS: usize = 40;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyslibSymbol {
    pub name: [u8; 32],
    pub vaddr: u64,
    pub flags: u32,
    pub reserved: u32,
}

impl SyslibSymbol {
    pub fn matches(&self, query: &str) -> bool {
        let q = query.as_bytes();
        let mut len = 0;
        while len < 32 && self.name[len] != 0 {
            len += 1;
        }
        if len != q.len() {
            return false;
        }
        &self.name[..len] == q
    }
}

#[repr(C)]
pub struct SyslibSharedInfo {
    pub magic: [u8; 8],
    pub version: u32,
    pub num_symbols: u32,
    pub page_size: u32,
    pub ticks_per_sec: u32,
    pub boot_epoch_sec: u64,
    pub reserved: [u64; 2],
    pub symbols: [SyslibSymbol; MAX_SYSLIB_SYMBOLS],
}

pub fn is_available() -> bool {
    let ptr = SYSLIB_INFO_VADDR as *const SyslibSharedInfo;
    unsafe {
        // Проверяем наличие валидного заголовка
        (*ptr).magic == SYSLIB_MAGIC
    }
}

pub fn shared_info() -> Option<&'static SyslibSharedInfo> {
    if is_available() {
        let ptr = SYSLIB_INFO_VADDR as *const SyslibSharedInfo;
        Some(unsafe { &*ptr })
    } else {
        None
    }
}

pub fn resolve(symbol_name: &str) -> Option<u64> {
    if let Some(info) = shared_info() {
        let count = info.num_symbols as usize;
        for i in 0..count.min(MAX_SYSLIB_SYMBOLS) {
            if info.symbols[i].matches(symbol_name) {
                return Some(info.symbols[i].vaddr);
            }
        }
    }
    None
}

pub fn boot_timestamp() -> u64 {
    shared_info().map(|i| i.boot_epoch_sec).unwrap_or(0)
}

pub unsafe fn fast_strlen(s: *const u8) -> usize {
    if let Some(fn_addr) = resolve("strlen") {
        let f: extern "C" fn(*const u8) -> usize = unsafe { core::mem::transmute(fn_addr as usize) };
        f(s)
    } else {
        let mut len = 0;
        unsafe {
            while *s.add(len) != 0 {
                len += 1;
            }
        }
        len
    }
}

pub unsafe fn fast_memcpy(dst: *mut u8, src: *const u8, len: usize) {
    if let Some(fn_addr) = resolve("memcpy") {
        let f: extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 = unsafe { core::mem::transmute(fn_addr as usize) };
        f(dst, src, len);
    } else {
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst, len);
        }
    }
}

pub unsafe fn fast_memset(dst: *mut u8, val: u8, len: usize) {
    if let Some(fn_addr) = resolve("memset") {
        let f: extern "C" fn(*mut u8, u8, usize) -> *mut u8 = unsafe { core::mem::transmute(fn_addr as usize) };
        f(dst, val, len);
    } else {
        unsafe {
            core::ptr::write_bytes(dst, val, len);
        }
    }
}
