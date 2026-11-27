//! User-space SDK для файловых систем FUSE поверх `/dev/fuse`.

use core::mem::size_of;
use core::ptr::{read_unaligned, write_unaligned};

use wunix_drv::abi::fuse::{
    fuse_dirent_align, FuseAttr, FuseAttrOut, FuseCreateIn, FuseDirent, FuseEntryOut, FuseInHeader,
    FuseInitIn, FuseInitOut, FuseMkdirIn, FuseOpenIn, FuseOpenOut, FuseOutHeader, FuseReadIn,
    FuseStatfsOut, FuseWriteIn, FuseWriteOut, FUSE_CREATE, FUSE_FLUSH, FUSE_FORGET, FUSE_FSYNC,
    FUSE_GETATTR, FUSE_INIT, FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION, FUSE_LOOKUP,
    FUSE_MKDIR, FUSE_OPEN, FUSE_OPENDIR, FUSE_READ, FUSE_READDIR, FUSE_RELEASE, FUSE_RELEASEDIR,
    FUSE_STATFS, FUSE_UNLINK, FUSE_WRITE,
};
use wunix_drv::DriverError;

use crate::{close, mount, open, read, write, O_RDWR};

pub struct FuseDirentWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> FuseDirentWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Записывает одну запись каталога FUSE с выравниванием по 8 байт.
    pub fn push(&mut self, ino: u64, off: u64, typ: u32, name: &[u8]) -> bool {
        let entry_len = fuse_dirent_align(size_of::<FuseDirent>() + name.len());
        if self.pos + entry_len > self.buf.len() {
            return false;
        }
        let dirent = FuseDirent {
            ino,
            off,
            namelen: name.len() as u32,
            typ,
        };
        unsafe {
            write_unaligned(self.buf.as_mut_ptr().add(self.pos) as *mut FuseDirent, dirent);
        }
        let name_off = self.pos + size_of::<FuseDirent>();
        self.buf[name_off..name_off + name.len()].copy_from_slice(name);
        for b in &mut self.buf[name_off + name.len()..self.pos + entry_len] {
            *b = 0;
        }
        self.pos += entry_len;
        true
    }

    pub fn written(&self) -> usize {
        self.pos
    }
}

/// Контракт user-space файловой системы.
pub trait FuseOps {
    fn init(&mut self, req: &FuseInitIn) -> FuseInitOut {
        FuseInitOut {
            major: FUSE_KERNEL_VERSION,
            minor: req.minor.min(FUSE_KERNEL_MINOR_VERSION),
            max_readahead: req.max_readahead,
            flags: 0,
            max_background: 16,
            congestion_threshold: 12,
            max_write: 65536,
            time_gran: 1,
            max_pages: 16,
            map_alignment: 0,
            unused: [0; 8],
        }
    }

    fn lookup(&mut self, _parent: u64, _name: &str) -> Result<FuseEntryOut, i32> {
        Err(-2) // ENOENT
    }

    fn getattr(&mut self, _nodeid: u64) -> Result<FuseAttr, i32> {
        Err(-2)
    }

    fn readdir(
        &mut self,
        _nodeid: u64,
        _offset: u64,
        _out: &mut FuseDirentWriter<'_>,
    ) -> Result<(), i32> {
        Ok(())
    }

    fn open(&mut self, _nodeid: u64, _flags: u32) -> Result<FuseOpenOut, i32> {
        Ok(FuseOpenOut {
            fh: _nodeid,
            open_flags: 0,
            padding: 0,
        })
    }

    fn read(&mut self, _nodeid: u64, _fh: u64, _offset: u64, _out: &mut [u8]) -> Result<usize, i32> {
        Err(-38) // ENOSYS
    }

    fn write(&mut self, _nodeid: u64, _fh: u64, _offset: u64, _data: &[u8]) -> Result<usize, i32> {
        Err(-38)
    }

    fn create(
        &mut self,
        _parent: u64,
        _name: &str,
        _mode: u32,
    ) -> Result<(FuseEntryOut, FuseOpenOut), i32> {
        Err(-38)
    }

    fn mkdir(&mut self, _parent: u64, _name: &str, _mode: u32) -> Result<FuseEntryOut, i32> {
        Err(-38)
    }

    fn unlink(&mut self, _parent: u64, _name: &str) -> Result<(), i32> {
        Err(-38)
    }

    fn statfs(&mut self, _nodeid: u64) -> Result<FuseStatfsOut, i32> {
        let mut st = FuseStatfsOut::default();
        st.st.bsize = 4096;
        st.st.frsize = 4096;
        st.st.namelen = 255;
        Ok(st)
    }
}

fn encode_reply_hdr(resp: &mut [u8], unique: u64, error: i32, payload_len: usize) -> usize {
    let total = size_of::<FuseOutHeader>() + payload_len;
    let hdr = FuseOutHeader {
        len: total as u32,
        error,
        unique,
    };
    unsafe {
        write_unaligned(resp.as_mut_ptr() as *mut FuseOutHeader, hdr);
    }
    total
}

fn encode_struct<T: Copy>(resp: &mut [u8], unique: u64, val: T) -> usize {
    let hdr_sz = size_of::<FuseOutHeader>();
    let sz = size_of::<T>();
    if resp.len() < hdr_sz + sz {
        return encode_reply_hdr(resp, unique, -12, 0);
    }
    unsafe {
        write_unaligned(resp.as_mut_ptr().add(hdr_sz) as *mut T, val);
    }
    encode_reply_hdr(resp, unique, 0, sz)
}

fn cstr_name(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).ok()
}

/// Чистый диспетчер одного FUSE-пакета (работает без аллокаций и подходит для Ring 3 и host-тестов).
pub fn dispatch_fuse_packet<F: FuseOps + ?Sized>(
    ops: &mut F,
    req_buf: &[u8],
    resp_buf: &mut [u8],
) -> usize {
    let hdr_sz = size_of::<FuseInHeader>();
    if req_buf.len() < hdr_sz || resp_buf.len() < size_of::<FuseOutHeader>() {
        return 0;
    }
    let hdr = unsafe { read_unaligned(req_buf.as_ptr() as *const FuseInHeader) };
    let body = &req_buf[hdr_sz..(hdr.len as usize).min(req_buf.len())];

    match hdr.opcode {
        FUSE_FORGET => 0,
        FUSE_INIT if body.len() >= size_of::<FuseInitIn>() => {
            let init_in = unsafe { read_unaligned(body.as_ptr() as *const FuseInitIn) };
            encode_struct(resp_buf, hdr.unique, ops.init(&init_in))
        }
        FUSE_LOOKUP => match cstr_name(body) {
            Some(name) => match ops.lookup(hdr.nodeid, name) {
                Ok(entry) => encode_struct(resp_buf, hdr.unique, entry),
                Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
            },
            None => encode_reply_hdr(resp_buf, hdr.unique, -22, 0),
        },
        FUSE_GETATTR => match ops.getattr(hdr.nodeid) {
            Ok(attr) => {
                let out = FuseAttrOut {
                    attr_valid: 1,
                    attr_valid_nsec: 0,
                    dummy: 0,
                    attr,
                };
                encode_struct(resp_buf, hdr.unique, out)
            }
            Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
        },
        FUSE_OPEN | FUSE_OPENDIR => {
            let flags = if body.len() >= size_of::<FuseOpenIn>() {
                unsafe { read_unaligned(body.as_ptr() as *const FuseOpenIn) }.flags
            } else {
                0
            };
            match ops.open(hdr.nodeid, flags) {
                Ok(open_out) => encode_struct(resp_buf, hdr.unique, open_out),
                Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
            }
        }
        FUSE_READ if body.len() >= size_of::<FuseReadIn>() => {
            let rd = unsafe { read_unaligned(body.as_ptr() as *const FuseReadIn) };
            let out_hdr_sz = size_of::<FuseOutHeader>();
            let max_out = resp_buf.len().saturating_sub(out_hdr_sz).min(rd.size as usize);
            match ops.read(
                hdr.nodeid,
                rd.fh,
                rd.offset,
                &mut resp_buf[out_hdr_sz..out_hdr_sz + max_out],
            ) {
                Ok(n) => encode_reply_hdr(resp_buf, hdr.unique, 0, n.min(max_out)),
                Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
            }
        }
        FUSE_READDIR if body.len() >= size_of::<FuseReadIn>() => {
            let rd = unsafe { read_unaligned(body.as_ptr() as *const FuseReadIn) };
            let out_hdr_sz = size_of::<FuseOutHeader>();
            let max_out = resp_buf.len().saturating_sub(out_hdr_sz).min(rd.size as usize);
            let mut w = FuseDirentWriter::new(&mut resp_buf[out_hdr_sz..out_hdr_sz + max_out]);
            match ops.readdir(hdr.nodeid, rd.offset, &mut w) {
                Ok(()) => {
                    let n = w.written();
                    encode_reply_hdr(resp_buf, hdr.unique, 0, n)
                }
                Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
            }
        }
        FUSE_WRITE if body.len() >= size_of::<FuseWriteIn>() => {
            let wr = unsafe { read_unaligned(body.as_ptr() as *const FuseWriteIn) };
            let data = &body[size_of::<FuseWriteIn>()..];
            let actual = &data[..(wr.size as usize).min(data.len())];
            match ops.write(hdr.nodeid, wr.fh, wr.offset, actual) {
                Ok(written) => encode_struct(
                    resp_buf,
                    hdr.unique,
                    FuseWriteOut {
                        size: written as u32,
                        padding: 0,
                    },
                ),
                Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
            }
        }
        FUSE_CREATE if body.len() > size_of::<FuseCreateIn>() => {
            let cr = unsafe { read_unaligned(body.as_ptr() as *const FuseCreateIn) };
            let name_bytes = &body[size_of::<FuseCreateIn>()..];
            match cstr_name(name_bytes) {
                Some(name) => match ops.create(hdr.nodeid, name, cr.mode) {
                    Ok((entry, open_out)) => {
                        let out_hdr_sz = size_of::<FuseOutHeader>();
                        let e_sz = size_of::<FuseEntryOut>();
                        let o_sz = size_of::<FuseOpenOut>();
                        if resp_buf.len() < out_hdr_sz + e_sz + o_sz {
                            return encode_reply_hdr(resp_buf, hdr.unique, -12, 0);
                        }
                        unsafe {
                            write_unaligned(resp_buf.as_mut_ptr().add(out_hdr_sz) as *mut FuseEntryOut, entry);
                            write_unaligned(
                                resp_buf.as_mut_ptr().add(out_hdr_sz + e_sz) as *mut FuseOpenOut,
                                open_out,
                            );
                        }
                        encode_reply_hdr(resp_buf, hdr.unique, 0, e_sz + o_sz)
                    }
                    Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
                },
                None => encode_reply_hdr(resp_buf, hdr.unique, -22, 0),
            }
        }
        FUSE_MKDIR if body.len() > size_of::<FuseMkdirIn>() => {
            let mk = unsafe { read_unaligned(body.as_ptr() as *const FuseMkdirIn) };
            match cstr_name(&body[size_of::<FuseMkdirIn>()..]) {
                Some(name) => match ops.mkdir(hdr.nodeid, name, mk.mode) {
                    Ok(entry) => encode_struct(resp_buf, hdr.unique, entry),
                    Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
                },
                None => encode_reply_hdr(resp_buf, hdr.unique, -22, 0),
            }
        }
        FUSE_UNLINK => match cstr_name(body) {
            Some(name) => match ops.unlink(hdr.nodeid, name) {
                Ok(()) => encode_reply_hdr(resp_buf, hdr.unique, 0, 0),
                Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
            },
            None => encode_reply_hdr(resp_buf, hdr.unique, -22, 0),
        },
        FUSE_STATFS => match ops.statfs(hdr.nodeid) {
            Ok(st) => encode_struct(resp_buf, hdr.unique, st),
            Err(e) => encode_reply_hdr(resp_buf, hdr.unique, e, 0),
        },
        FUSE_RELEASE | FUSE_RELEASEDIR | FUSE_FLUSH | FUSE_FSYNC => {
            encode_reply_hdr(resp_buf, hdr.unique, 0, 0)
        }
        _ => encode_reply_hdr(resp_buf, hdr.unique, -38, 0),
    }
}

pub struct FuseChannel {
    fd: u64,
}

impl FuseChannel {
    pub fn open_dev() -> Result<Self, DriverError> {
        let res = open(b"/dev/fuse\0", O_RDWR as u64, 0);
        if res < 0 {
            Err(DriverError::from_errno(res as i32))
        } else {
            Ok(Self { fd: res as u64 })
        }
    }

    pub fn fd(&self) -> u64 {
        self.fd
    }

    pub fn mount_on(&self, target_cstr: &[u8]) -> Result<(), DriverError> {
        let mut opt = [0u8; 24];
        opt[0..3].copy_from_slice(b"fd=");
        let mut idx = 3usize;
        let mut n = self.fd;
        let mut rev = [0u8; 20];
        let mut rlen = 0usize;
        if n == 0 {
            rev[0] = b'0';
            rlen = 1;
        } else {
            while n > 0 {
                rev[rlen] = b'0' + (n % 10) as u8;
                n /= 10;
                rlen += 1;
            }
        }
        for i in (0..rlen).rev() {
            opt[idx] = rev[i];
            idx += 1;
        }
        opt[idx] = 0;
        let rc = mount(b"/dev/fuse\0", target_cstr, b"fuse\0", 0, &opt[..=idx]);
        if rc < 0 {
            Err(DriverError::from_errno(rc as i32))
        } else {
            Ok(())
        }
    }

    pub fn serve_step<F: FuseOps + ?Sized>(
        &self,
        ops: &mut F,
        rx_buf: &mut [u8],
        tx_buf: &mut [u8],
    ) -> Result<usize, DriverError> {
        let n = read(self.fd, rx_buf) as isize;
        if n < 0 {
            return Err(DriverError::from_errno(n as i32));
        }
        if n == 0 {
            return Ok(0);
        }
        let reply_len = dispatch_fuse_packet(ops, &rx_buf[..n as usize], tx_buf);
        if reply_len > 0 {
            let w = write(self.fd, &tx_buf[..reply_len]) as isize;
            if w < 0 {
                return Err(DriverError::from_errno(w as i32));
            }
        }
        Ok(reply_len)
    }
}

impl Drop for FuseChannel {
    fn drop(&mut self) {
        close(self.fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wunix_drv::abi::fuse::FUSE_ROOT_ID;

    struct MemFs {
        file_len: usize,
        file_data: [u8; 64],
        exists: bool,
    }

    impl FuseOps for MemFs {
        fn lookup(&mut self, parent: u64, name: &str) -> Result<FuseEntryOut, i32> {
            if parent == FUSE_ROOT_ID && name == "hello.txt" && self.exists {
                Ok(FuseEntryOut {
                    nodeid: 2,
                    generation: 1,
                    attr: self.getattr(2)?,
                    ..Default::default()
                })
            } else {
                Err(-2)
            }
        }

        fn getattr(&mut self, nodeid: u64) -> Result<FuseAttr, i32> {
            match nodeid {
                1 => Ok(FuseAttr {
                    ino: 1,
                    mode: 0o040755,
                    nlink: 2,
                    ..Default::default()
                }),
                2 if self.exists => Ok(FuseAttr {
                    ino: 2,
                    mode: 0o100644,
                    size: self.file_len as u64,
                    nlink: 1,
                    ..Default::default()
                }),
                _ => Err(-2),
            }
        }

        fn create(
            &mut self,
            parent: u64,
            name: &str,
            _mode: u32,
        ) -> Result<(FuseEntryOut, FuseOpenOut), i32> {
            if parent != FUSE_ROOT_ID || name != "hello.txt" {
                return Err(-22);
            }
            self.exists = true;
            self.file_len = 0;
            Ok((
                FuseEntryOut {
                    nodeid: 2,
                    generation: 1,
                    attr: self.getattr(2)?,
                    ..Default::default()
                },
                FuseOpenOut {
                    fh: 2,
                    ..Default::default()
                },
            ))
        }

        fn write(&mut self, nodeid: u64, _fh: u64, offset: u64, data: &[u8]) -> Result<usize, i32> {
            if nodeid != 2 || !self.exists {
                return Err(-2);
            }
            let off = offset as usize;
            let n = data.len().min(self.file_data.len().saturating_sub(off));
            self.file_data[off..off + n].copy_from_slice(&data[..n]);
            self.file_len = self.file_len.max(off + n);
            Ok(n)
        }

        fn read(&mut self, nodeid: u64, _fh: u64, offset: u64, out: &mut [u8]) -> Result<usize, i32> {
            if nodeid != 2 || !self.exists {
                return Err(-2);
            }
            let off = offset as usize;
            if off >= self.file_len {
                return Ok(0);
            }
            let n = (self.file_len - off).min(out.len());
            out[..n].copy_from_slice(&self.file_data[off..off + n]);
            Ok(n)
        }

        fn readdir(
            &mut self,
            nodeid: u64,
            _offset: u64,
            out: &mut FuseDirentWriter<'_>,
        ) -> Result<(), i32> {
            if nodeid != 1 {
                return Err(-20);
            }
            if self.exists {
                out.push(2, 1, 8, b"hello.txt");
            }
            Ok(())
        }
    }

    fn build_pkt<T: Copy>(opcode: u32, unique: u64, nodeid: u64, body: T, extra: &[u8]) -> [u8; 256] {
        let mut buf = [0u8; 256];
        let total = size_of::<FuseInHeader>() + size_of::<T>() + extra.len();
        let hdr = FuseInHeader {
            len: total as u32,
            opcode,
            unique,
            nodeid,
            ..Default::default()
        };
        unsafe {
            write_unaligned(buf.as_mut_ptr() as *mut FuseInHeader, hdr);
            write_unaligned(buf.as_mut_ptr().add(size_of::<FuseInHeader>()) as *mut T, body);
        }
        let ex_off = size_of::<FuseInHeader>() + size_of::<T>();
        buf[ex_off..ex_off + extra.len()].copy_from_slice(extra);
        buf
    }

    #[test]
    fn test_fuse_dispatcher_full_lifecycle() {
        let mut fs = MemFs {
            file_len: 0,
            file_data: [0; 64],
            exists: false,
        };
        let mut resp = [0u8; 512];

        // 1. INIT
        let init_req = build_pkt(
            FUSE_INIT,
            1,
            0,
            FuseInitIn {
                major: 7,
                minor: 31,
                max_readahead: 4096,
                flags: 0,
            },
            &[],
        );
        let rlen = dispatch_fuse_packet(&mut fs, &init_req, &mut resp);
        assert_eq!(rlen, size_of::<FuseOutHeader>() + size_of::<FuseInitOut>());
        let out_hdr = unsafe { read_unaligned(resp.as_ptr() as *const FuseOutHeader) };
        assert_eq!(out_hdr.error, 0);

        // 2. CREATE hello.txt
        let create_req = build_pkt(
            FUSE_CREATE,
            2,
            FUSE_ROOT_ID,
            FuseCreateIn {
                flags: 0,
                mode: 0o644,
                umask: 0,
                open_flags: 0,
            },
            b"hello.txt\0",
        );
        let rlen = dispatch_fuse_packet(&mut fs, &create_req, &mut resp);
        assert_eq!(
            rlen,
            size_of::<FuseOutHeader>() + size_of::<FuseEntryOut>() + size_of::<FuseOpenOut>()
        );

        // 3. WRITE "userland-fuse"
        let payload = b"userland-fuse";
        let write_req = build_pkt(
            FUSE_WRITE,
            3,
            2,
            FuseWriteIn {
                fh: 2,
                offset: 0,
                size: payload.len() as u32,
                ..Default::default()
            },
            payload,
        );
        let _ = dispatch_fuse_packet(&mut fs, &write_req, &mut resp);
        let wr_out = unsafe {
            read_unaligned(resp.as_ptr().add(size_of::<FuseOutHeader>()) as *const FuseWriteOut)
        };
        assert_eq!(wr_out.size, payload.len() as u32);

        // 4. READ обратно
        let read_req = build_pkt(
            FUSE_READ,
            4,
            2,
            FuseReadIn {
                fh: 2,
                offset: 0,
                size: 64,
                ..Default::default()
            },
            &[],
        );
        let rlen = dispatch_fuse_packet(&mut fs, &read_req, &mut resp);
        assert_eq!(&resp[size_of::<FuseOutHeader>()..rlen], payload);

        // 5. READDIR
        let readdir_req = build_pkt(
            FUSE_READDIR,
            5,
            1,
            FuseReadIn {
                fh: 1,
                offset: 0,
                size: 256,
                ..Default::default()
            },
            &[],
        );
        let rlen = dispatch_fuse_packet(&mut fs, &readdir_req, &mut resp);
        assert!(rlen > size_of::<FuseOutHeader>());
    }
}
