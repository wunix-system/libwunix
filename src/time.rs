use super::{syscall2, syscall3, SYS_CLOCK_GETTIME, SYS_CLOCK_SETTIME, SYS_GETTIMEOFDAY, SYS_NANOSLEEP, SYS_SETTIMEOFDAY};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    pub fn from_ms(ms: u64) -> Self {
        Self {
            tv_sec: (ms / 1000) as i64,
            tv_nsec: ((ms % 1000) * 1_000_000) as i64,
        }
    }

    pub fn to_ms(&self) -> u64 {
        if self.tv_sec < 0 {
            0
        } else {
            (self.tv_sec as u64) * 1000 + (self.tv_nsec as u64) / 1_000_000
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timezone {
    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
    pub weekday: u8, // 0 = Sunday, 1 = Monday, ..., 6 = Saturday
    pub yearday: u16, // 1..=366
}

pub struct TimeFormatter<'a> {
    buf: &'a mut [u8],
    idx: usize,
}

impl<'a> TimeFormatter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, idx: 0 }
    }

    pub fn put_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.idx < self.buf.len() {
                self.buf[self.idx] = b;
                self.idx += 1;
            }
        }
    }

    pub fn put_num2(&mut self, n: u32) {
        let s = [(b'0' + ((n / 10) % 10) as u8), (b'0' + (n % 10) as u8)];
        self.put_bytes(&s);
    }

    pub fn put_num4(&mut self, n: u32) {
        let s = [
            (b'0' + ((n / 1000) % 10) as u8),
            (b'0' + ((n / 100) % 10) as u8),
            (b'0' + ((n / 10) % 10) as u8),
            (b'0' + (n % 10) as u8),
        ];
        self.put_bytes(&s);
    }

    pub fn finish(self) -> &'a str {
        core::str::from_utf8(&self.buf[..self.idx]).unwrap_or("")
    }
}

impl DateTime {
    pub const fn is_leap_year(year: i32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    pub const fn days_in_month(year: i32, month: u8) -> u8 {
        match month {
            1 => 31,
            2 => if Self::is_leap_year(year) { 29 } else { 28 },
            3 => 31,
            4 => 30,
            5 => 31,
            6 => 30,
            7 => 31,
            8 => 31,
            9 => 30,
            10 => 31,
            11 => 30,
            12 => 31,
            _ => 30,
        }
    }

    pub fn from_epoch(epoch_secs: i64, nanosecond: u32, tz_offset_secs: i32) -> Self {
        let adjusted_secs = epoch_secs + tz_offset_secs as i64;
        let (days, rem_secs) = if adjusted_secs >= 0 {
            (adjusted_secs / 86400, (adjusted_secs % 86400) as u32)
        } else {
            let d = (adjusted_secs - 86399) / 86400;
            let rem = (adjusted_secs - d * 86400) as u32;
            (d, rem)
        };

        let hour = (rem_secs / 3600) as u8;
        let minute = ((rem_secs % 3600) / 60) as u8;
        let second = (rem_secs % 60) as u8;
        let weekday = (((days + 4) % 7 + 7) % 7) as u8;

        let mut y = 1970i32;
        let mut d = days;
        if d >= 0 {
            loop {
                let diy = if Self::is_leap_year(y) { 366 } else { 365 };
                if d < diy as i64 {
                    break;
                }
                d -= diy as i64;
                y += 1;
            }
        } else {
            loop {
                y -= 1;
                let diy = if Self::is_leap_year(y) { 366 } else { 365 };
                d += diy as i64;
                if d >= 0 {
                    break;
                }
            }
        }

        let yearday = (d + 1) as u16;
        let mut m = 1u8;
        loop {
            let dim = Self::days_in_month(y, m);
            if d < dim as i64 {
                break;
            }
            d -= dim as i64;
            m += 1;
        }
        let day = (d + 1) as u8;

        Self {
            year: y,
            month: m,
            day,
            hour,
            minute,
            second,
            nanosecond,
            weekday,
            yearday,
        }
    }

    pub fn to_epoch(&self, tz_offset_secs: i32) -> i64 {
        let mut days = 0i64;
        if self.year >= 1970 {
            for y in 1970..self.year {
                days += if Self::is_leap_year(y) { 366 } else { 365 };
            }
        } else {
            for y in self.year..1970 {
                days -= if Self::is_leap_year(y) { 366 } else { 365 };
            }
        }
        for m in 1..self.month {
            days += Self::days_in_month(self.year, m) as i64;
        }
        days += (self.day as i64) - 1;

        let secs = days * 86400
            + (self.hour as i64) * 3600
            + (self.minute as i64) * 60
            + (self.second as i64);
        secs - tz_offset_secs as i64
    }

    pub fn format_strftime<'a>(
        &self,
        fmt: &str,
        tz_name: &str,
        tz_offset_secs: i32,
        is_ru: bool,
        buf: &'a mut [u8],
    ) -> &'a str {
        let mut f = TimeFormatter::new(buf);
        let bytes = fmt.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'%' && i + 1 < bytes.len() {
                i += 1;
                match bytes[i] {
                    b'Y' => f.put_num4(self.year.abs() as u32),
                    b'y' => f.put_num2((self.year.abs() % 100) as u32),
                    b'm' => f.put_num2(self.month as u32),
                    b'd' => f.put_num2(self.day as u32),
                    b'e' => {
                        if self.day < 10 {
                            f.put_bytes(b" ");
                            f.put_bytes(&[b'0' + self.day]);
                        } else {
                            f.put_num2(self.day as u32);
                        }
                    }
                    b'H' => f.put_num2(self.hour as u32),
                    b'I' => {
                        let h12 = match self.hour % 12 {
                            0 => 12,
                            h => h,
                        };
                        f.put_num2(h12 as u32);
                    }
                    b'M' => f.put_num2(self.minute as u32),
                    b'S' => f.put_num2(self.second as u32),
                    b's' => {
                        let epoch = self.to_epoch(tz_offset_secs);
                        let mut num_buf = [0u8; 24];
                        let s = crate::fmt::itoa(epoch, &mut num_buf);
                        f.put_bytes(s.as_bytes());
                    }
                    b'Z' => f.put_bytes(tz_name.as_bytes()),
                    b'z' => {
                        let sign = if tz_offset_secs >= 0 { b'+' } else { b'-' };
                        let abs_m = (tz_offset_secs.abs() / 60) as u32;
                        let zh = abs_m / 60;
                        let zm = abs_m % 60;
                        f.put_bytes(&[sign]);
                        f.put_num2(zh);
                        f.put_num2(zm);
                    }
                    b'F' => {
                        f.put_num4(self.year.abs() as u32);
                        f.put_bytes(b"-");
                        f.put_num2(self.month as u32);
                        f.put_bytes(b"-");
                        f.put_num2(self.day as u32);
                    }
                    b'T' => {
                        f.put_num2(self.hour as u32);
                        f.put_bytes(b":");
                        f.put_num2(self.minute as u32);
                        f.put_bytes(b":");
                        f.put_num2(self.second as u32);
                    }
                    b'R' => {
                        f.put_num2(self.hour as u32);
                        f.put_bytes(b":");
                        f.put_num2(self.minute as u32);
                    }
                    b'D' => {
                        f.put_num2(self.month as u32);
                        f.put_bytes(b"/");
                        f.put_num2(self.day as u32);
                        f.put_bytes(b"/");
                        f.put_num2((self.year.abs() % 100) as u32);
                    }
                    b'a' => {
                        let name = self.weekday_short_str(is_ru);
                        f.put_bytes(name.as_bytes());
                    }
                    b'A' => {
                        let name = self.weekday_full_str(is_ru);
                        f.put_bytes(name.as_bytes());
                    }
                    b'b' | b'h' => {
                        let name = self.month_short_str(is_ru);
                        f.put_bytes(name.as_bytes());
                    }
                    b'B' => {
                        let name = self.month_full_str(is_ru);
                        f.put_bytes(name.as_bytes());
                    }
                    b'j' => {
                        let yd = self.yearday as u32;
                        let s = [
                            (b'0' + ((yd / 100) % 10) as u8),
                            (b'0' + ((yd / 10) % 10) as u8),
                            (b'0' + (yd % 10) as u8),
                        ];
                        f.put_bytes(&s);
                    }
                    b'w' => f.put_bytes(&[b'0' + self.weekday]),
                    b'u' => {
                        let u = if self.weekday == 0 { 7 } else { self.weekday };
                        f.put_bytes(&[b'0' + u]);
                    }
                    b'p' => {
                        if self.hour >= 12 {
                            f.put_bytes(b"PM");
                        } else {
                            f.put_bytes(b"AM");
                        }
                    }
                    b'P' => {
                        if self.hour >= 12 {
                            f.put_bytes(b"pm");
                        } else {
                            f.put_bytes(b"am");
                        }
                    }
                    b'N' => {
                        let mut num_buf = [0u8; 16];
                        let s = crate::fmt::utoa(self.nanosecond as u64, &mut num_buf);
                        f.put_bytes(s.as_bytes());
                    }
                    b'n' => f.put_bytes(b"\n"),
                    b't' => f.put_bytes(b"\t"),
                    b'%' => f.put_bytes(b"%"),
                    other => {
                        f.put_bytes(b"%");
                        f.put_bytes(&[other]);
                    }
                }
            } else {
                f.put_bytes(&[bytes[i]]);
            }
            i += 1;
        }

        f.finish()
    }

    pub fn weekday_short_str(&self, is_ru: bool) -> &'static str {
        if is_ru {
            match self.weekday {
                0 => "Вс",
                1 => "Пн",
                2 => "Вт",
                3 => "Ср",
                4 => "Чт",
                5 => "Пт",
                _ => "Сб",
            }
        } else {
            match self.weekday {
                0 => "Sun",
                1 => "Mon",
                2 => "Tue",
                3 => "Wed",
                4 => "Thu",
                5 => "Fri",
                _ => "Sat",
            }
        }
    }

    pub fn weekday_full_str(&self, is_ru: bool) -> &'static str {
        if is_ru {
            match self.weekday {
                0 => "Воскресенье",
                1 => "Понедельник",
                2 => "Вторник",
                3 => "Среда",
                4 => "Четверг",
                5 => "Пятница",
                _ => "Суббота",
            }
        } else {
            match self.weekday {
                0 => "Sunday",
                1 => "Monday",
                2 => "Tuesday",
                3 => "Wednesday",
                4 => "Thursday",
                5 => "Friday",
                _ => "Saturday",
            }
        }
    }

    pub fn month_short_str(&self, is_ru: bool) -> &'static str {
        if is_ru {
            match self.month {
                1 => "янв",
                2 => "фев",
                3 => "мар",
                4 => "апр",
                5 => "май",
                6 => "июн",
                7 => "июл",
                8 => "авг",
                9 => "сен",
                10 => "окт",
                11 => "ноя",
                _ => "дек",
            }
        } else {
            match self.month {
                1 => "Jan",
                2 => "Feb",
                3 => "Mar",
                4 => "Apr",
                5 => "May",
                6 => "Jun",
                7 => "Jul",
                8 => "Aug",
                9 => "Sep",
                10 => "Oct",
                11 => "Nov",
                _ => "Dec",
            }
        }
    }

    pub fn month_full_str(&self, is_ru: bool) -> &'static str {
        if is_ru {
            match self.month {
                1 => "Январь",
                2 => "Февраль",
                3 => "Март",
                4 => "Апрель",
                5 => "Май",
                6 => "Июнь",
                7 => "Июль",
                8 => "Август",
                9 => "Сентябрь",
                10 => "Октябрь",
                11 => "Ноябрь",
                _ => "Декабрь",
            }
        } else {
            match self.month {
                1 => "January",
                2 => "February",
                3 => "March",
                4 => "April",
                5 => "May",
                6 => "June",
                7 => "July",
                8 => "August",
                9 => "September",
                10 => "October",
                11 => "November",
                _ => "December",
            }
        }
    }

    /// Форматирует дату в стандартном формате date: "Fri Oct 30 13:00:23 MSK 2026"
    pub fn format_default<'a>(
        &self,
        tz_name: &str,
        is_ru: bool,
        buf: &'a mut [u8],
    ) -> &'a str {
        let fmt = "%a %b %e %T %Z %Y";
        self.format_strftime(fmt, tz_name, 0, is_ru, buf)
    }

    /// Форматирует дату в формате RFC 5322 (email): "Fri, 30 Oct 2026 13:00:23 +0300"
    pub fn format_rfc5322<'a>(
        &self,
        tz_offset_secs: i32,
        buf: &'a mut [u8],
    ) -> &'a str {
        self.format_strftime("%a, %d %b %Y %T %z", "", tz_offset_secs, false, buf)
    }

    /// Форматирует дату в формате ISO 8601: "2026-10-30T13:00:23+03:00"
    pub fn format_iso8601<'a>(
        &self,
        include_time: bool,
        tz_offset_secs: i32,
        buf: &'a mut [u8],
    ) -> &'a str {
        if !include_time {
            self.format_strftime("%F", "", tz_offset_secs, false, buf)
        } else {
            let mut tmp = [0u8; 128];
            let base = self.format_strftime("%FT%T", "", tz_offset_secs, false, &mut tmp);
            let sign = if tz_offset_secs >= 0 { "+" } else { "-" };
            let abs_m = (tz_offset_secs.abs() / 60) as u32;
            let zh = abs_m / 60;
            let zm = abs_m % 60;

            let mut f = TimeFormatter::new(buf);
            f.put_bytes(base.as_bytes());
            f.put_bytes(sign.as_bytes());
            f.put_num2(zh);
            f.put_bytes(b":");
            f.put_num2(zm);
            f.finish()
        }
    }

    /// Парсит строку даты/времени. Поддерживает форматы:
    /// - `@<секунды_эпохи>` (например, "@1793354423")
    /// - `YYYY-MM-DD HH:MM:SS` или `YYYY-MM-DDTHH:MM:SS`
    /// - `YYYY-MM-DD`
    /// - `HH:MM:SS` или `HH:MM`
    pub fn parse(s: &str, current: &DateTime) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.starts_with('@') {
            if let Ok(epoch) = crate::str_utils::strtol(&trimmed[1..], 10) {
                return Some(Self::from_epoch(epoch, 0, 0));
            }
            return None;
        }

        // Проверяем YYYY-MM-DD ...
        if trimmed.len() >= 10 && trimmed.as_bytes()[4] == b'-' && trimmed.as_bytes()[7] == b'-' {
            let year = crate::str_utils::strtol(&trimmed[0..4], 10).ok()? as i32;
            let month = crate::str_utils::strtoul(&trimmed[5..7], 10).ok()? as u8;
            let day = crate::str_utils::strtoul(&trimmed[8..10], 10).ok()? as u8;

            let mut hour = 0;
            let mut minute = 0;
            let mut second = 0;

            if trimmed.len() > 10 {
                let rest = trimmed[10..].trim_start_matches(|c| c == ' ' || c == 'T');
                if rest.len() >= 5 && rest.as_bytes()[2] == b':' {
                    hour = crate::str_utils::strtoul(&rest[0..2], 10).ok()? as u8;
                    minute = crate::str_utils::strtoul(&rest[3..5], 10).ok()? as u8;
                    if rest.len() >= 8 && rest.as_bytes()[5] == b':' {
                        second = crate::str_utils::strtoul(&rest[6..8], 10).ok()? as u8;
                    }
                }
            }

            let dt = Self {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond: 0,
                weekday: 0,
                yearday: 1,
            };
            let ep = dt.to_epoch(0);
            return Some(Self::from_epoch(ep, 0, 0));
        }

        // Проверяем только время HH:MM:SS или HH:MM
        if trimmed.len() >= 5 && trimmed.as_bytes()[2] == b':' {
            let hour = crate::str_utils::strtoul(&trimmed[0..2], 10).ok()? as u8;
            let minute = crate::str_utils::strtoul(&trimmed[3..5], 10).ok()? as u8;
            let mut second = 0;
            if trimmed.len() >= 8 && trimmed.as_bytes()[5] == b':' {
                second = crate::str_utils::strtoul(&trimmed[6..8], 10).ok()? as u8;
            }

            let mut dt = *current;
            dt.hour = hour;
            dt.minute = minute;
            dt.second = second;
            let ep = dt.to_epoch(0);
            return Some(Self::from_epoch(ep, 0, 0));
        }

        None
    }
}

pub fn clock_realtime() -> Timespec {
    let mut ts = Timespec::default();
    unsafe {
        syscall3(SYS_CLOCK_GETTIME, 0, &mut ts as *mut Timespec as u64, 0);
    }
    ts
}

pub fn clock_monotonic() -> Timespec {
    let mut ts = Timespec::default();
    unsafe {
        syscall3(SYS_CLOCK_GETTIME, 1, &mut ts as *mut Timespec as u64, 0);
    }
    ts
}

pub fn clock_set_realtime(ts: &Timespec) -> i64 {
    unsafe {
        syscall2(SYS_CLOCK_SETTIME, 0, ts as *const Timespec as u64) as i64
    }
}

pub fn get_time_of_day(tv: &mut Timeval, tz: Option<&mut Timezone>) -> i64 {
    let tz_ptr = match tz {
        Some(z) => z as *mut Timezone as u64,
        None => 0,
    };
    unsafe {
        syscall2(SYS_GETTIMEOFDAY, tv as *mut Timeval as u64, tz_ptr) as i64
    }
}

pub fn set_time_of_day(tv: &Timeval, tz: Option<&Timezone>) -> i64 {
    let tz_ptr = match tz {
        Some(z) => z as *const Timezone as u64,
        None => 0,
    };
    unsafe {
        syscall2(SYS_SETTIMEOFDAY, tv as *const Timeval as u64, tz_ptr) as i64
    }
}

pub fn sleep_ms(ms: u64) {
    let req = Timespec::from_ms(ms);
    let mut rem = Timespec::default();
    unsafe {
        syscall3(
            SYS_NANOSLEEP,
            &req as *const Timespec as u64,
            &mut rem as *mut Timespec as u64,
            0,
        );
    }
}

pub fn sleep_sec(sec: u64) {
    sleep_ms(sec.saturating_mul(1000));
}

/// Считывает настроенную временную зону из `/etc/timezone`.
/// Если файл не найден или пуст, по умолчанию используется "Europe/Moscow" (+03:00 / MSK).
pub fn get_system_timezone() -> (i32, &'static str, &'static str) {
    let mut buf = [0u8; 64];
    let fd = crate::open(b"/etc/timezone\0", 0, 0);
    if fd >= 0 {
        let n = crate::read(fd as u64, &mut buf);
        crate::close(fd as u64);
        if n > 0 {
            if let Ok(tz_str) = core::str::from_utf8(&buf[..n as usize]) {
                let trimmed = tz_str.trim();
                if trimmed == "UTC" || trimmed == "Etc/UTC" {
                    return (0, "UTC", "UTC");
                }
                if trimmed == "Europe/London" || trimmed == "GMT" {
                    return (0, "GMT", "Europe/London");
                }
                if trimmed == "Europe/Kaliningrad" {
                    return (7200, "EET", "Europe/Kaliningrad");
                }
                if trimmed == "Europe/Samara" {
                    return (14400, "SAMT", "Europe/Samara");
                }
                if trimmed == "Asia/Yekaterinburg" {
                    return (18000, "YEKT", "Asia/Yekaterinburg");
                }
            }
        }
    }
    // По умолчанию московское время MSK (UTC+3)
    (10800, "MSK", "Europe/Moscow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datetime_epoch_roundtrip() {
        // 2026-10-30 10:00:23 UTC -> 1793354423
        let dt = DateTime::from_epoch(1793354423, 0, 0);
        assert_eq!(dt.year, 2026);
        assert_eq!(dt.month, 10);
        assert_eq!(dt.day, 30);
        assert_eq!(dt.hour, 10);
        assert_eq!(dt.minute, 0);
        assert_eq!(dt.second, 23);
        assert_eq!(dt.weekday, 5); // Friday

        let ep = dt.to_epoch(0);
        assert_eq!(ep, 1793354423);
    }

    #[test]
    fn test_datetime_format_rfc5322() {
        let dt = DateTime::from_epoch(1793354423, 0, 0);
        let mut buf = [0u8; 64];
        let s = dt.format_rfc5322(0, &mut buf);
        assert_eq!(s, "Fri, 30 Oct 2026 10:00:23 +0000");
    }

    #[test]
    fn test_datetime_format_iso8601() {
        let dt = DateTime::from_epoch(1793354423, 0, 10800);
        let mut buf = [0u8; 64];
        let s = dt.format_iso8601(true, 10800, &mut buf);
        assert_eq!(s, "2026-10-30T13:00:23+03:00");

        let s_date = dt.format_iso8601(false, 10800, &mut buf);
        assert_eq!(s_date, "2026-10-30");
    }

    #[test]
    fn test_datetime_parse() {
        let current = DateTime::from_epoch(1793354423, 0, 0);
        let parsed = DateTime::parse("@1793354423", &current).unwrap();
        assert_eq!(parsed.to_epoch(0), 1793354423);

        let parsed_iso = DateTime::parse("2026-10-30 13:00:23", &current).unwrap();
        assert_eq!(parsed_iso.year, 2026);
        assert_eq!(parsed_iso.month, 10);
        assert_eq!(parsed_iso.day, 30);
        assert_eq!(parsed_iso.hour, 13);
        assert_eq!(parsed_iso.minute, 0);
        assert_eq!(parsed_iso.second, 23);
    }
}
