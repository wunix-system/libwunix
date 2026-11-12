#![cfg_attr(not(test), no_std)]

pub mod compression;
pub mod crypto;
pub mod env;
pub mod errno;
pub mod fmt;
pub mod i18n;
pub mod net;
pub mod passwd;
pub mod str_utils;
pub mod syslib;
pub mod terminal;
pub mod time;

pub use compression::{
    deflate_fixed, deflate_store, gzip_compress, gzip_decompress, inflate, CompressionError,
    GzipHeader,
};
pub use crypto::{crc32, hash_password, sha256, verify_password_hash, Crc32};
pub use errno::{check, Errno};
pub use i18n::{current_language, t, Language};
pub use terminal::{read_line, read_password_masked};
pub use net::{
    flush_dns_cache, for_each_cache_entry, get_default_nameserver, lookup_hosts_file,
    parse_ipv4_bytes, query_ntp_host, query_ntp_host_port, query_ntp_server,
    query_ntp_server_port, resolve_host, resolve_host_with_server, sync_system_time, DnsError,
    LeapIndicator, NtpError, NtpMode, NtpPacket, NtpResult, NtpTimestamp, NTP_PORT,
};
pub use passwd::{
    add_user_to_group, append_group_entry, append_passwd_entry, append_shadow_entry,
    delete_user_from_all, for_each_group, for_each_passwd, get_group_by_gid, get_group_by_name,
    get_next_uid, get_passwd_by_name, get_passwd_by_uid, get_shadow_by_name, remove_user_from_group,
    update_shadow_password, user_in_group, verify_password, AuthError, GroupEntry, PasswdEntry,
    ShadowEntry,
};

// Стандартные файловые дескрипторы POSIX
pub const STDIN_FILENO: u64 = 0;
pub const STDOUT_FILENO: u64 = 1;
pub const STDERR_FILENO: u64 = 2;

// Флаги открытия файлов (open flags)
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0x40;
pub const O_EXCL: u32 = 0x80;
pub const O_TRUNC: u32 = 0x200;
pub const O_APPEND: u32 = 0x400;

// Номера системных вызовов Wunix (совместимы с Linux x86_64 ABI)
pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_POLL: u64 = 7;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_SELECT: u64 = 23;
pub const SYS_YIELD: u64 = 24;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETPID: u64 = 39;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_SENDMSG: u64 = 46;
pub const SYS_RECVMSG: u64 = 47;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_UNAME: u64 = 63;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_SYMLINK: u64 = 88;
pub const SYS_READLINK: u64 = 89;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_FCHMOD: u64 = 91;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_FCHOWN: u64 = 93;
pub const SYS_UMASK: u64 = 95;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_GETUID: u64 = 102;
pub const SYS_SYSLOG: u64 = 103;
pub const SYS_GETGID: u64 = 104;
pub const SYS_SETUID: u64 = 105;
pub const SYS_SETGID: u64 = 106;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETPGID: u64 = 109;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_GETPGRP: u64 = 111;
pub const SYS_SETSID: u64 = 112;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_STATFS: u64 = 137;
pub const SYS_LSTAT: u64 = 6;
pub const AT_FDCWD: i64 = -100;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const RENAME_NOREPLACE: u32 = 1;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_SYNC: u64 = 162;
pub const SYS_SETTIMEOFDAY: u64 = 164;
pub const SYS_MOUNT: u64 = 165;
pub const SYS_UMOUNT2: u64 = 166;
pub const SYS_REBOOT: u64 = 169;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_CLOCK_SETTIME: u64 = 227;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_ACCEPT4: u64 = 288;
pub const SYS_DUP3: u64 = 292;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_RENAMEAT2: u64 = 316;

pub const LINUX_REBOOT_MAGIC1: u64 = 0xfee1dead;
pub const LINUX_REBOOT_MAGIC2: u64 = 672274793;
pub const LINUX_REBOOT_CMD_RESTART: u64 = 0x01234567;
pub const LINUX_REBOOT_CMD_HALT: u64 = 0xcdef0123;
pub const LINUX_REBOOT_CMD_POWER_OFF: u64 = 0x4321fedc;
pub const LINUX_REBOOT_CMD_RESTART2: u64 = 0xa1b2c3d4;

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_NONBLOCK: u32 = 0x800;
pub const SOCK_CLOEXEC: u32 = 0x80000;

pub const IPPROTO_ICMP: i32 = 1;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

pub const MS_RDONLY: u64 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,   // Big-endian сетевой порядок
    pub sin_addr: u32,   // Big-endian IPv4 адрес
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    pub fn new_v4(octets: [u8; 4], port: u16) -> Self {
        let addr = u32::from_be_bytes(octets);
        Self {
            sin_family: AF_INET,
            sin_port: port.to_be(),
            sin_addr: addr.to_be(),
            sin_zero: [0u8; 8],
        }
    }

    pub fn port(&self) -> u16 {
        u16::from_be(self.sin_port)
    }

    pub fn ip_bytes(&self) -> [u8; 4] {
        u32::from_be(self.sin_addr).to_ne_bytes()
    }
}

// Сырая обёртка: кладём номер в RAX, аргументы в RDI/RSI/RDX/R10/R8/R9 и дёргаем syscall.
// RCX и R11 затираются процессором (RIP и RFLAGS), поэтому 4-й аргумент идёт через R10.
#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall1(nr: u64, arg1: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall2(nr: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall3(nr: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall4(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall5(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall6(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            in("r9") arg6,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

pub fn write(fd: u64, buf: &[u8]) -> u64 {
    unsafe { syscall3(SYS_WRITE, fd, buf.as_ptr() as u64, buf.len() as u64) }
}

pub fn read(fd: u64, buf: &mut [u8]) -> u64 {
    unsafe { syscall3(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

pub fn exit(status: u64) -> ! {
    unsafe {
        syscall1(SYS_EXIT, status);
    }
    loop {}
}

pub fn yield_now() {
    unsafe {
        syscall0(SYS_YIELD);
    }
}

pub fn open(path: &[u8], flags: u64, mode: u64) -> i64 {
    unsafe { syscall3(SYS_OPEN, path.as_ptr() as u64, flags, mode) as i64 }
}

pub fn close(fd: u64) -> i64 {
    unsafe { syscall1(SYS_CLOSE, fd) as i64 }
}

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub fn lseek(fd: u64, offset: i64, whence: i32) -> i64 {
    unsafe { syscall3(SYS_LSEEK, fd, offset as u64, whence as u64) as i64 }
}

pub fn getdents64(fd: u64, buf: &mut [u8]) -> i64 {
    unsafe { syscall3(SYS_GETDENTS64, fd, buf.as_mut_ptr() as u64, buf.len() as u64) as i64 }
}

pub fn getuid() -> u32 {
    unsafe { syscall0(SYS_GETUID) as u32 }
}

pub fn getgid() -> u32 {
    unsafe { syscall0(SYS_GETGID) as u32 }
}

pub fn geteuid() -> u32 {
    unsafe { syscall0(SYS_GETEUID) as u32 }
}

pub fn getegid() -> u32 {
    unsafe { syscall0(SYS_GETEGID) as u32 }
}

pub fn setuid(uid: u32) -> i64 {
    unsafe { syscall1(SYS_SETUID, uid as u64) as i64 }
}

pub fn setgid(gid: u32) -> i64 {
    unsafe { syscall1(SYS_SETGID, gid as u64) as i64 }
}

pub fn getcwd(buf: &mut [u8]) -> i64 {
    unsafe { syscall3(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64, 0) as i64 }
}

pub fn chdir(path: &[u8]) -> i64 {
    unsafe { syscall1(SYS_CHDIR, path.as_ptr() as u64) as i64 }
}

pub fn unlink(path: &[u8]) -> i64 {
    unsafe { syscall1(SYS_UNLINK, path.as_ptr() as u64) as i64 }
}

pub fn getpid() -> u64 {
    unsafe { syscall0(SYS_GETPID) }
}

pub fn execve(path: &[u8], argv: u64, envp: u64) -> i64 {
    unsafe { syscall3(SYS_EXECVE, path.as_ptr() as u64, argv, envp) as i64 }
}

pub fn sysinfo(info_ptr: *mut u8) -> i64 {
    unsafe { syscall1(SYS_SYSINFO, info_ptr as u64) as i64 }
}

pub fn uname(uts_ptr: *mut u8) -> i64 {
    unsafe { syscall1(SYS_UNAME, uts_ptr as u64) as i64 }
}

pub fn statfs(path: &[u8], buf_ptr: *mut u8) -> i64 {
    unsafe { syscall3(SYS_STATFS, path.as_ptr() as u64, buf_ptr as u64, 0) as i64 }
}

pub fn syslog(action: u64, buf: &mut [u8]) -> i64 {
    unsafe { syscall3(SYS_SYSLOG, action, buf.as_mut_ptr() as u64, buf.len() as u64) as i64 }
}

pub fn nanosleep(req_ptr: *const u8, rem_ptr: *mut u8) -> i64 {
    unsafe { syscall3(SYS_NANOSLEEP, req_ptr as u64, rem_ptr as u64, 0) as i64 }
}

pub fn clock_gettime(clock_id: u64, ts_ptr: *mut u8) -> i64 {
    unsafe { syscall3(SYS_CLOCK_GETTIME, clock_id, ts_ptr as u64, 0) as i64 }
}

pub fn socket(domain: u16, sock_type: u32, protocol: i32) -> i64 {
    unsafe { syscall3(SYS_SOCKET, domain as u64, sock_type as u64, protocol as u64) as i64 }
}

pub fn connect(fd: u64, addr: &SockAddrIn) -> i64 {
    unsafe {
        syscall3(
            SYS_CONNECT,
            fd,
            addr as *const SockAddrIn as u64,
            core::mem::size_of::<SockAddrIn>() as u64,
        ) as i64
    }
}

pub fn bind(fd: u64, addr: &SockAddrIn) -> i64 {
    unsafe {
        syscall3(
            SYS_BIND,
            fd,
            addr as *const SockAddrIn as u64,
            core::mem::size_of::<SockAddrIn>() as u64,
        ) as i64
    }
}

pub fn listen(fd: u64, backlog: i32) -> i64 {
    unsafe { syscall2(SYS_LISTEN, fd, backlog as u64) as i64 }
}

pub fn accept(fd: u64, addr: Option<&mut SockAddrIn>) -> i64 {
    let (addr_ptr, mut addr_len) = match addr {
        Some(a) => (a as *mut SockAddrIn as u64, core::mem::size_of::<SockAddrIn>() as u64),
        None => (0, 0),
    };
    let len_ptr = if addr_ptr != 0 {
        &mut addr_len as *mut u64 as u64
    } else {
        0
    };
    unsafe { syscall3(SYS_ACCEPT, fd, addr_ptr, len_ptr) as i64 }
}

pub fn sendto(fd: u64, buf: &[u8], flags: i32, dest_addr: Option<&SockAddrIn>) -> i64 {
    let (addr_ptr, addr_len) = match dest_addr {
        Some(a) => (a as *const SockAddrIn as u64, core::mem::size_of::<SockAddrIn>() as u64),
        None => (0, 0),
    };
    unsafe {
        syscall6(
            SYS_SENDTO,
            fd,
            buf.as_ptr() as u64,
            buf.len() as u64,
            flags as u64,
            addr_ptr,
            addr_len,
        ) as i64
    }
}

pub fn recvfrom(fd: u64, buf: &mut [u8], flags: i32, src_addr: Option<&mut SockAddrIn>) -> i64 {
    let (addr_ptr, mut addr_len) = match src_addr {
        Some(a) => (a as *mut SockAddrIn as u64, core::mem::size_of::<SockAddrIn>() as u64),
        None => (0, 0),
    };
    let len_ptr = if addr_ptr != 0 {
        &mut addr_len as *mut u64 as u64
    } else {
        0
    };
    unsafe {
        syscall6(
            SYS_RECVFROM,
            fd,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            flags as u64,
            addr_ptr,
            len_ptr,
        ) as i64
    }
}

pub fn getsockname(fd: u64, addr: &mut SockAddrIn) -> i64 {
    let mut len = core::mem::size_of::<SockAddrIn>() as u64;
    unsafe {
        syscall3(
            SYS_GETSOCKNAME,
            fd,
            addr as *mut SockAddrIn as u64,
            &mut len as *mut u64 as u64,
        ) as i64
    }
}

pub fn getpeername(fd: u64, addr: &mut SockAddrIn) -> i64 {
    let mut len = core::mem::size_of::<SockAddrIn>() as u64;
    unsafe {
        syscall3(
            SYS_GETPEERNAME,
            fd,
            addr as *mut SockAddrIn as u64,
            &mut len as *mut u64 as u64,
        ) as i64
    }
}

pub fn mount(source: &[u8], target: &[u8], fstype: &[u8], flags: u64, data: &[u8]) -> i64 {
    unsafe {
        syscall5(
            SYS_MOUNT,
            source.as_ptr() as u64,
            target.as_ptr() as u64,
            fstype.as_ptr() as u64,
            flags,
            data.as_ptr() as u64,
        ) as i64
    }
}

pub fn umount2(target: &[u8], flags: i32) -> i64 {
    unsafe { syscall2(SYS_UMOUNT2, target.as_ptr() as u64, flags as u64) as i64 }
}

pub fn mkdir(path: &[u8], mode: u32) -> i64 {
    unsafe { syscall2(SYS_MKDIR, path.as_ptr() as u64, mode as u64) as i64 }
}

pub fn rmdir(path: &[u8]) -> i64 {
    unsafe { syscall1(SYS_RMDIR, path.as_ptr() as u64) as i64 }
}

pub fn rename(oldpath: &[u8], newpath: &[u8]) -> i64 {
    unsafe { syscall2(SYS_RENAME, oldpath.as_ptr() as u64, newpath.as_ptr() as u64) as i64 }
}

pub fn renameat2(olddirfd: i64, oldpath: &[u8], newdirfd: i64, newpath: &[u8], flags: u32) -> i64 {
    unsafe {
        syscall5(
            SYS_RENAMEAT2,
            olddirfd as u64,
            oldpath.as_ptr() as u64,
            newdirfd as u64,
            newpath.as_ptr() as u64,
            flags as u64,
        ) as i64
    }
}

pub fn symlink(target: &[u8], linkpath: &[u8]) -> i64 {
    unsafe { syscall2(SYS_SYMLINK, target.as_ptr() as u64, linkpath.as_ptr() as u64) as i64 }
}

pub fn readlink(path: &[u8], buf: &mut [u8]) -> i64 {
    unsafe { syscall3(SYS_READLINK, path.as_ptr() as u64, buf.as_mut_ptr() as u64, buf.len() as u64) as i64 }
}

pub fn truncate(path: &[u8], length: u64) -> i64 {
    unsafe { syscall2(SYS_TRUNCATE, path.as_ptr() as u64, length) as i64 }
}

pub fn ftruncate(fd: u64, length: u64) -> i64 {
    unsafe { syscall2(SYS_FTRUNCATE, fd, length) as i64 }
}

pub fn access(path: &[u8], mode: u32) -> i64 {
    unsafe { syscall2(SYS_ACCESS, path.as_ptr() as u64, mode as u64) as i64 }
}

pub fn pread64(fd: u64, buf: &mut [u8], offset: u64) -> i64 {
    unsafe { syscall4(SYS_PREAD64, fd, buf.as_mut_ptr() as u64, buf.len() as u64, offset) as i64 }
}

pub fn pwrite64(fd: u64, buf: &[u8], offset: u64) -> i64 {
    unsafe { syscall4(SYS_PWRITE64, fd, buf.as_ptr() as u64, buf.len() as u64, offset) as i64 }
}

pub fn dup(fd: u64) -> i64 {
    unsafe { syscall1(SYS_DUP, fd) as i64 }
}

pub fn dup2(oldfd: u64, newfd: u64) -> i64 {
    unsafe { syscall3(SYS_DUP3, oldfd, newfd, 0) as i64 }
}

pub fn dup3(oldfd: u64, newfd: u64, flags: u32) -> i64 {
    unsafe { syscall3(SYS_DUP3, oldfd, newfd, flags as u64) as i64 }
}

pub fn chmod(path: &[u8], mode: u32) -> i64 {
    unsafe { syscall2(SYS_CHMOD, path.as_ptr() as u64, mode as u64) as i64 }
}

pub fn fchmod(fd: u64, mode: u32) -> i64 {
    unsafe { syscall2(SYS_FCHMOD, fd, mode as u64) as i64 }
}

pub fn chown(path: &[u8], uid: u32, gid: u32) -> i64 {
    unsafe { syscall3(SYS_CHOWN, path.as_ptr() as u64, uid as u64, gid as u64) as i64 }
}

pub fn fchown(fd: u64, uid: u32, gid: u32) -> i64 {
    unsafe { syscall3(SYS_FCHOWN, fd, uid as u64, gid as u64) as i64 }
}

pub fn umask(mask: u32) -> u32 {
    unsafe { syscall1(SYS_UMASK, mask as u64) as u32 }
}

pub fn setsid() -> i64 {
    unsafe { syscall0(SYS_SETSID) as i64 }
}

pub fn wait4(pid: i64, status: *mut i32, options: u32) -> i64 {
    unsafe { syscall4(SYS_WAIT4, pid as u64, status as u64, options as u64, 0) as i64 }
}

pub fn shutdown(fd: u64, how: u32) -> i64 {
    unsafe { syscall2(SYS_SHUTDOWN, fd, how as u64) as i64 }
}

pub fn setsockopt(fd: u64, level: i32, optname: i32, optval: &[u8]) -> i64 {
    unsafe {
        syscall5(
            SYS_SETSOCKOPT,
            fd,
            level as u64,
            optname as u64,
            optval.as_ptr() as u64,
            optval.len() as u64,
        ) as i64
    }
}

pub fn getsockopt(fd: u64, level: i32, optname: i32, optval: &mut [u8]) -> i64 {
    let mut len = optval.len() as u32;
    unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            fd,
            level as u64,
            optname as u64,
            optval.as_mut_ptr() as u64,
            &mut len as *mut u32 as u64,
        ) as i64
    }
}

pub fn poll(fds: *mut u8, nfds: u64, timeout_ms: i64) -> i64 {
    unsafe { syscall3(SYS_POLL, fds as u64, nfds, timeout_ms as u64) as i64 }
}

pub const TIOCGWINSZ: u64 = 0x5413;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WinSize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

pub fn ioctl(fd: u64, cmd: u64, arg: u64) -> i64 {
    unsafe { syscall3(SYS_IOCTL, fd, cmd, arg) as i64 }
}

pub const TCGETS: u64 = 0x5401;
pub const TCSETS: u64 = 0x5402;
pub const TCSETSW: u64 = 0x5403;
pub const TCSETSF: u64 = 0x5404;

pub const IGNBRK: u32 = 0o000001;
pub const BRKINT: u32 = 0o000002;
pub const IGNPAR: u32 = 0o000004;
pub const PARMRK: u32 = 0o000010;
pub const INPCK: u32 = 0o000020;
pub const ISTRIP: u32 = 0o000040;
pub const INLCR: u32 = 0o000100;
pub const IGNCR: u32 = 0o000200;
pub const ICRNL: u32 = 0o000400;
pub const IXON: u32 = 0o002000;
pub const IXANY: u32 = 0o004000;
pub const IXOFF: u32 = 0o010000;

pub const OPOST: u32 = 0o000001;
pub const ONLCR: u32 = 0o000004;

pub const CS8: u32 = 0o000060;
pub const CREAD: u32 = 0o000200;

pub const ISIG: u32 = 0o000001;
pub const ICANON: u32 = 0o000002;
pub const ECHO: u32 = 0o000010;
pub const ECHOE: u32 = 0o000020;
pub const ECHOK: u32 = 0o000040;
pub const ECHONL: u32 = 0o000100;
pub const NOFLSH: u32 = 0o000200;
pub const TOSTOP: u32 = 0o000400;
pub const IEXTEN: u32 = 0o100000;

pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

pub fn tcgetattr(fd: u64, tio: &mut Termios) -> i64 {
    ioctl(fd, TCGETS, tio as *mut Termios as u64)
}

pub fn tcsetattr(fd: u64, _optional_actions: i32, tio: &Termios) -> i64 {
    ioctl(fd, TCSETS, tio as *const Termios as u64)
}

pub fn isatty(fd: u64) -> bool {
    let mut tio = Termios::default();
    tcgetattr(fd, &mut tio) == 0
}

pub fn get_terminal_size() -> (usize, usize) {
    let mut ws = WinSize::default();
    if ioctl(0, TIOCGWINSZ, &mut ws as *mut WinSize as u64) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        (ws.ws_col as usize, ws.ws_row as usize)
    } else {
        (80, 24)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoVec {
    pub iov_base: u64,
    pub iov_len: u64,
}

pub fn readv(fd: u64, iov: &[IoVec]) -> i64 {
    unsafe { syscall3(SYS_READV, fd, iov.as_ptr() as u64, iov.len() as u64) as i64 }
}

pub fn writev(fd: u64, iov: &[IoVec]) -> i64 {
    unsafe { syscall3(SYS_WRITEV, fd, iov.as_ptr() as u64, iov.len() as u64) as i64 }
}

pub fn getppid() -> u64 {
    unsafe { syscall0(SYS_GETPPID) }
}

pub fn getpgrp() -> u64 {
    unsafe { syscall0(SYS_GETPGRP) }
}

pub fn getpgid(pid: u64) -> i64 {
    unsafe { syscall1(SYS_GETPGID, pid) as i64 }
}

pub fn setpgid(pid: u64, pgid: u64) -> i64 {
    unsafe { syscall2(SYS_SETPGID, pid, pgid) as i64 }
}

pub struct Stdout;

impl core::fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write(STDOUT_FILENO, s.as_bytes());
        Ok(())
    }
}

pub struct Stderr;

impl core::fmt::Write for Stderr {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write(STDERR_FILENO, s.as_bytes());
        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

impl Stat {
    pub const fn zeroed() -> Self {
        Self {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atime: 0,
            st_atime_nsec: 0,
            st_mtime: 0,
            st_mtime_nsec: 0,
            st_ctime: 0,
            st_ctime_nsec: 0,
            __unused: [0; 3],
        }
    }
}

pub fn stat(path: &[u8], statbuf: &mut Stat) -> i64 {
    unsafe {
        syscall4(
            SYS_NEWFSTATAT,
            (-100i64) as u64,
            path.as_ptr() as u64,
            statbuf as *mut Stat as u64,
            0,
        ) as i64
    }
}

pub fn lstat(path: &[u8], statbuf: &mut Stat) -> i64 {
    unsafe {
        syscall4(
            SYS_NEWFSTATAT,
            (-100i64) as u64,
            path.as_ptr() as u64,
            statbuf as *mut Stat as u64,
            AT_SYMLINK_NOFOLLOW,
        ) as i64
    }
}

pub fn sync() -> i64 {
    unsafe { syscall0(SYS_SYNC) as i64 }
}

pub fn reboot(magic1: u64, magic2: u64, cmd: u64, arg: u64) -> i64 {
    unsafe { syscall4(SYS_REBOOT, magic1, magic2, cmd, arg) as i64 }
}

pub fn system_poweroff() -> i64 {
    sync();
    reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_POWER_OFF, 0)
}

pub fn system_reboot() -> i64 {
    sync();
    reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART, 0)
}

pub fn system_halt() -> i64 {
    sync();
    reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_HALT, 0)
}

pub fn clock_settime(clock_id: u64, ts: *const time::Timespec) -> i64 {
    unsafe { syscall2(SYS_CLOCK_SETTIME, clock_id, ts as u64) as i64 }
}

pub fn gettimeofday(tv: *mut time::Timeval, tz: *mut time::Timezone) -> i64 {
    unsafe { syscall2(SYS_GETTIMEOFDAY, tv as u64, tz as u64) as i64 }
}

pub fn settimeofday(tv: *const time::Timeval, tz: *const time::Timezone) -> i64 {
    unsafe { syscall2(SYS_SETTIMEOFDAY, tv as u64, tz as u64) as i64 }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        let _ = core::fmt::write(&mut $crate::Stdout, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => {{
        $crate::print!($($arg)*);
        $crate::print!("\n");
    }};
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {
        let _ = core::fmt::write(&mut $crate::Stderr, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => {{
        $crate::eprint!($($arg)*);
        $crate::eprint!("\n");
    }};
}
