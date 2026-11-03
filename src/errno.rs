#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    Perm = 1,
    NoEnt = 2,
    Srch = 3,
    Io = 5,
    NxIo = 6,
    TooBig = 7,
    NoExec = 8,
    BadF = 9,
    Child = 10,
    Again = 11,
    NoMem = 12,
    Acces = 13,
    Fault = 14,
    Busy = 16,
    Exist = 17,
    NoDev = 19,
    NotDir = 20,
    IsDir = 21,
    Inval = 22,
    NFile = 23,
    MFile = 24,
    NoTty = 25,
    Pipe = 32,
    Range = 34,
    NoSys = 38,
    NotEmpty = 39,
    Loop = 40,
    NotSock = 88,
    TimedOut = 110,
}

impl Errno {
    pub fn from_raw(code: i32) -> Option<Self> {
        match code {
            1 => Some(Self::Perm),
            2 => Some(Self::NoEnt),
            3 => Some(Self::Srch),
            5 => Some(Self::Io),
            6 => Some(Self::NxIo),
            7 => Some(Self::TooBig),
            8 => Some(Self::NoExec),
            9 => Some(Self::BadF),
            10 => Some(Self::Child),
            11 => Some(Self::Again),
            12 => Some(Self::NoMem),
            13 => Some(Self::Acces),
            14 => Some(Self::Fault),
            16 => Some(Self::Busy),
            17 => Some(Self::Exist),
            19 => Some(Self::NoDev),
            20 => Some(Self::NotDir),
            21 => Some(Self::IsDir),
            22 => Some(Self::Inval),
            23 => Some(Self::NFile),
            24 => Some(Self::MFile),
            25 => Some(Self::NoTty),
            32 => Some(Self::Pipe),
            34 => Some(Self::Range),
            38 => Some(Self::NoSys),
            39 => Some(Self::NotEmpty),
            40 => Some(Self::Loop),
            88 => Some(Self::NotSock),
            110 => Some(Self::TimedOut),
            _ => None,
        }
    }

    pub fn strerror(self) -> &'static str {
        match self {
            Self::Perm => "Operation not permitted",
            Self::NoEnt => "No such file or directory",
            Self::Srch => "No such process",
            Self::Io => "Input/output error",
            Self::NxIo => "No such device or address",
            Self::TooBig => "Argument list too long",
            Self::NoExec => "Exec format error",
            Self::BadF => "Bad file descriptor",
            Self::Child => "No child processes",
            Self::Again => "Resource temporarily unavailable",
            Self::NoMem => "Cannot allocate memory",
            Self::Acces => "Permission denied",
            Self::Fault => "Bad address",
            Self::Busy => "Device or resource busy",
            Self::Exist => "File exists",
            Self::NoDev => "No such device",
            Self::NotDir => "Not a directory",
            Self::IsDir => "Is a directory",
            Self::Inval => "Invalid argument",
            Self::NFile => "Too many open files in system",
            Self::MFile => "Too many open files",
            Self::NoTty => "Inappropriate ioctl for device",
            Self::Pipe => "Broken pipe",
            Self::Range => "Numerical result out of range",
            Self::NoSys => "Function not implemented",
            Self::NotEmpty => "Directory not empty",
            Self::Loop => "Too many levels of symbolic links",
            Self::NotSock => "Socket operation on non-socket",
            Self::TimedOut => "Connection timed out",
        }
    }
}

pub fn check(ret: i64) -> Result<u64, Errno> {
    if ret < 0 && ret >= -4096 {
        let code = (-ret) as i32;
        Err(Errno::from_raw(code).unwrap_or(Errno::Inval))
    } else {
        Ok(ret as u64)
    }
}
