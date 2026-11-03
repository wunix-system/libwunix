// Модуль управления базой пользователей, групп и паролей Wunix.
// Поддерживает безопасное чтение и модификацию /etc/passwd, /etc/group, /etc/shadow
// в автономном no_std окружении.

use crate::crypto::verify_password_hash;

pub const PASSWD_PATH: &[u8] = b"/etc/passwd\0";
pub const GROUP_PATH: &[u8] = b"/etc/group\0";
pub const SHADOW_PATH: &[u8] = b"/etc/shadow\0";
pub const SHADOW_TMP_PATH: &[u8] = b"/etc/shadow.tmp\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    FileNotFound,
    IoError,
    ParseError,
    UserNotFound,
    GroupNotFound,
    WrongPassword,
    PermissionDenied,
    AlreadyExists,
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswdEntry {
    pub uid: u32,
    pub gid: u32,
    pub username_buf: [u8; 32],
    pub username_len: usize,
    pub gecos_buf: [u8; 64],
    pub gecos_len: usize,
    pub home_buf: [u8; 64],
    pub home_len: usize,
    pub shell_buf: [u8; 64],
    pub shell_len: usize,
}

impl PasswdEntry {
    pub fn new(username: &str, uid: u32, gid: u32, gecos: &str, home: &str, shell: &str) -> Self {
        let mut entry = Self {
            uid,
            gid,
            username_buf: [0; 32],
            username_len: 0,
            gecos_buf: [0; 64],
            gecos_len: 0,
            home_buf: [0; 64],
            home_len: 0,
            shell_buf: [0; 64],
            shell_len: 0,
        };

        let u_bytes = username.as_bytes();
        let u_len = u_bytes.len().min(32);
        entry.username_buf[..u_len].copy_from_slice(&u_bytes[..u_len]);
        entry.username_len = u_len;

        let g_bytes = gecos.as_bytes();
        let g_len = g_bytes.len().min(64);
        entry.gecos_buf[..g_len].copy_from_slice(&g_bytes[..g_len]);
        entry.gecos_len = g_len;

        let h_bytes = home.as_bytes();
        let h_len = h_bytes.len().min(64);
        entry.home_buf[..h_len].copy_from_slice(&h_bytes[..h_len]);
        entry.home_len = h_len;

        let s_bytes = shell.as_bytes();
        let s_len = s_bytes.len().min(64);
        entry.shell_buf[..s_len].copy_from_slice(&s_bytes[..s_len]);
        entry.shell_len = s_len;

        entry
    }

    pub fn username(&self) -> &str {
        core::str::from_utf8(&self.username_buf[..self.username_len]).unwrap_or("")
    }

    pub fn gecos(&self) -> &str {
        core::str::from_utf8(&self.gecos_buf[..self.gecos_len]).unwrap_or("")
    }

    pub fn home(&self) -> &str {
        core::str::from_utf8(&self.home_buf[..self.home_len]).unwrap_or("")
    }

    pub fn shell(&self) -> &str {
        core::str::from_utf8(&self.shell_buf[..self.shell_len]).unwrap_or("")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupEntry {
    pub gid: u32,
    pub name_buf: [u8; 32],
    pub name_len: usize,
    pub members_buf: [[u8; 32]; 16],
    pub members_len: [usize; 16],
    pub members_count: usize,
}

impl GroupEntry {
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name_buf[..self.name_len]).unwrap_or("")
    }

    pub fn has_member(&self, username: &str) -> bool {
        for i in 0..self.members_count {
            if let Ok(m) = core::str::from_utf8(&self.members_buf[i][..self.members_len[i]]) {
                if m == username {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowEntry {
    pub username_buf: [u8; 32],
    pub username_len: usize,
    pub hash_buf: [u8; 128],
    pub hash_len: usize,
}

impl ShadowEntry {
    pub fn username(&self) -> &str {
        core::str::from_utf8(&self.username_buf[..self.username_len]).unwrap_or("")
    }

    pub fn hash(&self) -> &str {
        core::str::from_utf8(&self.hash_buf[..self.hash_len]).unwrap_or("")
    }
}

fn read_text_file(path: &[u8], buf: &mut [u8]) -> Result<usize, AuthError> {
    let fd = crate::open(path, crate::O_RDONLY as u64, 0);
    if fd < 0 {
        return Err(AuthError::FileNotFound);
    }
    let mut total = 0;
    while total < buf.len() {
        let n = crate::read(fd as u64, &mut buf[total..]);
        if n <= 0 {
            break;
        }
        total += n as usize;
    }
    let _ = crate::close(fd as u64);
    Ok(total)
}

fn write_text_file(path: &[u8], data: &[u8], mode: u32) -> Result<(), AuthError> {
    let fd = crate::open(
        path,
        (crate::O_WRONLY | crate::O_CREAT | crate::O_TRUNC) as u64,
        mode as u64,
    );
    if fd < 0 {
        return Err(AuthError::IoError);
    }
    let mut written = 0;
    while written < data.len() {
        let n = crate::write(fd as u64, &data[written..]);
        if n <= 0 {
            let _ = crate::close(fd as u64);
            return Err(AuthError::IoError);
        }
        written += n as usize;
    }
    let _ = crate::close(fd as u64);
    Ok(())
}

fn parse_u32(s: &str) -> Option<u32> {
    let mut val = 0u32;
    if s.is_empty() {
        return None;
    }
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(val)
}

pub fn parse_passwd_line(line: &str) -> Option<PasswdEntry> {
    // Формат: username:password:uid:gid:gecos:home:shell
    let mut parts = line.split(':');
    let username = parts.next()?;
    let _passwd = parts.next()?;
    let uid_str = parts.next()?;
    let gid_str = parts.next()?;
    let gecos = parts.next().unwrap_or("");
    let home = parts.next().unwrap_or("");
    let shell = parts.next().unwrap_or("");

    let uid = parse_u32(uid_str)?;
    let gid = parse_u32(gid_str)?;

    Some(PasswdEntry::new(username, uid, gid, gecos, home, shell))
}

pub fn parse_group_line(line: &str) -> Option<GroupEntry> {
    // Формат: groupname:password:gid:user1,user2,...
    let mut parts = line.split(':');
    let name = parts.next()?;
    let _passwd = parts.next()?;
    let gid_str = parts.next()?;
    let members_str = parts.next().unwrap_or("");

    let gid = parse_u32(gid_str)?;

    let mut entry = GroupEntry {
        gid,
        name_buf: [0; 32],
        name_len: 0,
        members_buf: [[0; 32]; 16],
        members_len: [0; 16],
        members_count: 0,
    };

    let n_bytes = name.as_bytes();
    let n_len = n_bytes.len().min(32);
    entry.name_buf[..n_len].copy_from_slice(&n_bytes[..n_len]);
    entry.name_len = n_len;

    if !members_str.is_empty() {
        for m in members_str.split(',') {
            let m_trimmed = m.trim();
            if m_trimmed.is_empty() || entry.members_count >= 16 {
                continue;
            }
            let idx = entry.members_count;
            let m_bytes = m_trimmed.as_bytes();
            let m_len = m_bytes.len().min(32);
            entry.members_buf[idx][..m_len].copy_from_slice(&m_bytes[..m_len]);
            entry.members_len[idx] = m_len;
            entry.members_count += 1;
        }
    }

    Some(entry)
}

pub fn parse_shadow_line(line: &str) -> Option<ShadowEntry> {
    // Формат: username:hash:lastchanged:min:max:warn:inact:expire:flag
    let mut parts = line.split(':');
    let username = parts.next()?;
    let hash = parts.next()?;

    let mut entry = ShadowEntry {
        username_buf: [0; 32],
        username_len: 0,
        hash_buf: [0; 128],
        hash_len: 0,
    };

    let u_bytes = username.as_bytes();
    let u_len = u_bytes.len().min(32);
    entry.username_buf[..u_len].copy_from_slice(&u_bytes[..u_len]);
    entry.username_len = u_len;

    let h_bytes = hash.as_bytes();
    let h_len = h_bytes.len().min(128);
    entry.hash_buf[..h_len].copy_from_slice(&h_bytes[..h_len]);
    entry.hash_len = h_len;

    Some(entry)
}

pub fn for_each_passwd<F: FnMut(&PasswdEntry) -> bool>(mut f: F) -> Result<(), AuthError> {
    let mut buf = [0u8; 8192];
    let len = read_text_file(PASSWD_PATH, &mut buf)?;
    let content = core::str::from_utf8(&buf[..len]).map_err(|_| AuthError::ParseError)?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(entry) = parse_passwd_line(trimmed) {
            if !f(&entry) {
                break;
            }
        }
    }
    Ok(())
}

pub fn get_passwd_by_name(name: &str) -> Result<Option<PasswdEntry>, AuthError> {
    let mut found = None;
    for_each_passwd(|e| {
        if e.username() == name {
            found = Some(*e);
            false
        } else {
            true
        }
    })?;
    Ok(found)
}

pub fn get_passwd_by_uid(uid: u32) -> Result<Option<PasswdEntry>, AuthError> {
    let mut found = None;
    for_each_passwd(|e| {
        if e.uid == uid {
            found = Some(*e);
            false
        } else {
            true
        }
    })?;
    Ok(found)
}

pub fn get_next_uid() -> Result<u32, AuthError> {
    let mut max_uid = 999u32;
    for_each_passwd(|e| {
        if e.uid >= 1000 && e.uid > max_uid {
            max_uid = e.uid;
        }
        true
    })?;
    Ok(max_uid + 1)
}

pub fn for_each_group<F: FnMut(&GroupEntry) -> bool>(mut f: F) -> Result<(), AuthError> {
    let mut buf = [0u8; 8192];
    let len = read_text_file(GROUP_PATH, &mut buf)?;
    let content = core::str::from_utf8(&buf[..len]).map_err(|_| AuthError::ParseError)?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(entry) = parse_group_line(trimmed) {
            if !f(&entry) {
                break;
            }
        }
    }
    Ok(())
}

pub fn get_group_by_name(name: &str) -> Result<Option<GroupEntry>, AuthError> {
    let mut found = None;
    for_each_group(|g| {
        if g.name() == name {
            found = Some(*g);
            false
        } else {
            true
        }
    })?;
    Ok(found)
}

pub fn get_group_by_gid(gid: u32) -> Result<Option<GroupEntry>, AuthError> {
    let mut found = None;
    for_each_group(|g| {
        if g.gid == gid {
            found = Some(*g);
            false
        } else {
            true
        }
    })?;
    Ok(found)
}

pub fn user_in_group(username: &str, group_name: &str) -> bool {
    if let Ok(Some(group)) = get_group_by_name(group_name) {
        if group.has_member(username) {
            return true;
        }
    }
    if let Ok(Some(user)) = get_passwd_by_name(username) {
        if let Ok(Some(group)) = get_group_by_name(group_name) {
            if user.gid == group.gid {
                return true;
            }
        }
    }
    false
}

pub fn get_shadow_by_name(name: &str) -> Result<Option<ShadowEntry>, AuthError> {
    let mut buf = [0u8; 8192];
    let len = match read_text_file(SHADOW_PATH, &mut buf) {
        Ok(l) => l,
        Err(AuthError::FileNotFound) => return Err(AuthError::FileNotFound),
        Err(_) => return Err(AuthError::PermissionDenied),
    };
    let content = core::str::from_utf8(&buf[..len]).map_err(|_| AuthError::ParseError)?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(entry) = parse_shadow_line(trimmed) {
            if entry.username() == name {
                return Ok(Some(entry));
            }
        }
    }
    Ok(None)
}

pub fn verify_password(username: &str, raw_password: &str) -> Result<PasswdEntry, AuthError> {
    let user_entry = match get_passwd_by_name(username)? {
        Some(u) => u,
        None => return Err(AuthError::UserNotFound),
    };

    let shadow_entry = match get_shadow_by_name(username)? {
        Some(s) => s,
        None => return Err(AuthError::UserNotFound),
    };

    // Если у пользователя пароль не установлен (пустой хеш) — вход разрешен без пароля
    if shadow_entry.hash().is_empty() {
        return Ok(user_entry);
    }

    if verify_password_hash(raw_password, shadow_entry.hash()) {
        Ok(user_entry)
    } else {
        Err(AuthError::WrongPassword)
    }
}

pub fn update_shadow_password(username: &str, new_hash: &str) -> Result<(), AuthError> {
    let mut in_buf = [0u8; 8192];
    let len = read_text_file(SHADOW_PATH, &mut in_buf)?;
    let content = core::str::from_utf8(&in_buf[..len]).map_err(|_| AuthError::ParseError)?;

    let mut out_buf = [0u8; 8192];
    let mut out_len = 0;
    let mut found = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            let bytes = trimmed.as_bytes();
            if out_len + bytes.len() + 1 > out_buf.len() {
                return Err(AuthError::BufferTooSmall);
            }
            out_buf[out_len..out_len + bytes.len()].copy_from_slice(bytes);
            out_len += bytes.len();
            out_buf[out_len] = b'\n';
            out_len += 1;
            continue;
        }

        if let Some(mut parts) = Some(trimmed.split(':')) {
            if let Some(u) = parts.next() {
                if u == username {
                    found = true;
                    // Формируем обновленную строку: username:new_hash:19000:0:99999:7:::
                    let prefix = username.as_bytes();
                    let h_bytes = new_hash.as_bytes();
                    let suffix = b":19000:0:99999:7:::\n";
                    let row_len = prefix.len() + 1 + h_bytes.len() + suffix.len();
                    if out_len + row_len > out_buf.len() {
                        return Err(AuthError::BufferTooSmall);
                    }
                    out_buf[out_len..out_len + prefix.len()].copy_from_slice(prefix);
                    out_len += prefix.len();
                    out_buf[out_len] = b':';
                    out_len += 1;
                    out_buf[out_len..out_len + h_bytes.len()].copy_from_slice(h_bytes);
                    out_len += h_bytes.len();
                    out_buf[out_len..out_len + suffix.len()].copy_from_slice(suffix);
                    out_len += suffix.len();
                    continue;
                }
            }
        }

        let bytes = trimmed.as_bytes();
        if out_len + bytes.len() + 1 > out_buf.len() {
            return Err(AuthError::BufferTooSmall);
        }
        out_buf[out_len..out_len + bytes.len()].copy_from_slice(bytes);
        out_len += bytes.len();
        out_buf[out_len] = b'\n';
        out_len += 1;
    }

    if !found {
        return Err(AuthError::UserNotFound);
    }

    // Записываем во временный файл с правами 0600 (доступен только root)
    write_text_file(SHADOW_TMP_PATH, &out_buf[..out_len], 0o600)?;
    let ret = crate::rename(SHADOW_TMP_PATH, SHADOW_PATH);
    if ret < 0 {
        let _ = crate::unlink(SHADOW_TMP_PATH);
        return Err(AuthError::IoError);
    }

    Ok(())
}

pub fn append_passwd_entry(entry: &PasswdEntry) -> Result<(), AuthError> {
    let mut in_buf = [0u8; 8192];
    let len = read_text_file(PASSWD_PATH, &mut in_buf).unwrap_or(0);

    let mut out_buf = [0u8; 8192];
    if len > 0 {
        out_buf[..len].copy_from_slice(&in_buf[..len]);
    }
    let mut out_len = len;

    if out_len > 0 && out_buf[out_len - 1] != b'\n' {
        out_buf[out_len] = b'\n';
        out_len += 1;
    }

    // username:x:uid:gid:gecos:home:shell\n
    let mut row_buf = [0u8; 256];
    let mut r_pos = 0;

    let u_bytes = entry.username().as_bytes();
    row_buf[r_pos..r_pos + u_bytes.len()].copy_from_slice(u_bytes);
    r_pos += u_bytes.len();

    let static_x = b":x:";
    row_buf[r_pos..r_pos + static_x.len()].copy_from_slice(static_x);
    r_pos += static_x.len();

    let mut num_buf = [0u8; 10];
    let uid_str = crate::fmt::utoa(entry.uid as u64, &mut num_buf);
    let uid_len = uid_str.len();
    row_buf[r_pos..r_pos + uid_len].copy_from_slice(uid_str.as_bytes());
    r_pos += uid_len;

    row_buf[r_pos] = b':';
    r_pos += 1;

    let gid_str = crate::fmt::utoa(entry.gid as u64, &mut num_buf);
    let gid_len = gid_str.len();
    row_buf[r_pos..r_pos + gid_len].copy_from_slice(gid_str.as_bytes());
    r_pos += gid_len;

    row_buf[r_pos] = b':';
    r_pos += 1;

    let g_bytes = entry.gecos().as_bytes();
    row_buf[r_pos..r_pos + g_bytes.len()].copy_from_slice(g_bytes);
    r_pos += g_bytes.len();

    row_buf[r_pos] = b':';
    r_pos += 1;

    let h_bytes = entry.home().as_bytes();
    row_buf[r_pos..r_pos + h_bytes.len()].copy_from_slice(h_bytes);
    r_pos += h_bytes.len();

    row_buf[r_pos] = b':';
    r_pos += 1;

    let s_bytes = entry.shell().as_bytes();
    row_buf[r_pos..r_pos + s_bytes.len()].copy_from_slice(s_bytes);
    r_pos += s_bytes.len();

    row_buf[r_pos] = b'\n';
    r_pos += 1;

    if out_len + r_pos > out_buf.len() {
        return Err(AuthError::BufferTooSmall);
    }
    out_buf[out_len..out_len + r_pos].copy_from_slice(&row_buf[..r_pos]);
    out_len += r_pos;

    write_text_file(PASSWD_PATH, &out_buf[..out_len], 0o644)?;
    Ok(())
}

pub fn append_shadow_entry(username: &str, hash: &str) -> Result<(), AuthError> {
    let mut in_buf = [0u8; 8192];
    let len = read_text_file(SHADOW_PATH, &mut in_buf).unwrap_or(0);

    let mut out_buf = [0u8; 8192];
    if len > 0 {
        out_buf[..len].copy_from_slice(&in_buf[..len]);
    }
    let mut out_len = len;

    if out_len > 0 && out_buf[out_len - 1] != b'\n' {
        out_buf[out_len] = b'\n';
        out_len += 1;
    }

    let u_bytes = username.as_bytes();
    let h_bytes = hash.as_bytes();
    let suffix = b":19000:0:99999:7:::\n";
    let needed = u_bytes.len() + 1 + h_bytes.len() + suffix.len();

    if out_len + needed > out_buf.len() {
        return Err(AuthError::BufferTooSmall);
    }

    out_buf[out_len..out_len + u_bytes.len()].copy_from_slice(u_bytes);
    out_len += u_bytes.len();
    out_buf[out_len] = b':';
    out_len += 1;
    out_buf[out_len..out_len + h_bytes.len()].copy_from_slice(h_bytes);
    out_len += h_bytes.len();
    out_buf[out_len..out_len + suffix.len()].copy_from_slice(suffix);
    out_len += suffix.len();

    write_text_file(SHADOW_PATH, &out_buf[..out_len], 0o600)?;
    Ok(())
}

pub fn append_group_entry(group_name: &str, gid: u32, member: &str) -> Result<(), AuthError> {
    let mut in_buf = [0u8; 8192];
    let len = read_text_file(GROUP_PATH, &mut in_buf).unwrap_or(0);

    let mut out_buf = [0u8; 8192];
    if len > 0 {
        out_buf[..len].copy_from_slice(&in_buf[..len]);
    }
    let mut out_len = len;

    if out_len > 0 && out_buf[out_len - 1] != b'\n' {
        out_buf[out_len] = b'\n';
        out_len += 1;
    }

    let g_bytes = group_name.as_bytes();
    let m_bytes = member.as_bytes();
    let mut num_buf = [0u8; 10];
    let gid_str = crate::fmt::utoa(gid as u64, &mut num_buf);
    let gid_len = gid_str.len();

    let needed = g_bytes.len() + 3 + gid_len + 1 + m_bytes.len() + 1;
    if out_len + needed > out_buf.len() {
        return Err(AuthError::BufferTooSmall);
    }

    out_buf[out_len..out_len + g_bytes.len()].copy_from_slice(g_bytes);
    out_len += g_bytes.len();
    out_buf[out_len..out_len + 3].copy_from_slice(b":x:");
    out_len += 3;
    out_buf[out_len..out_len + gid_len].copy_from_slice(gid_str.as_bytes());
    out_len += gid_len;
    out_buf[out_len] = b':';
    out_len += 1;
    out_buf[out_len..out_len + m_bytes.len()].copy_from_slice(m_bytes);
    out_len += m_bytes.len();
    out_buf[out_len] = b'\n';
    out_len += 1;

    write_text_file(GROUP_PATH, &out_buf[..out_len], 0o644)?;
    Ok(())
}

pub fn delete_user_from_all(username: &str) -> Result<(), AuthError> {
    // 1. Из /etc/passwd
    let mut in_buf = [0u8; 8192];
    let len = read_text_file(PASSWD_PATH, &mut in_buf)?;
    let content = core::str::from_utf8(&in_buf[..len]).map_err(|_| AuthError::ParseError)?;

    let mut out_buf = [0u8; 8192];
    let mut out_len = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(colon) = trimmed.find(':') {
            if &trimmed[..colon] == username {
                continue; // пропускаем удаляемого пользователя
            }
        }
        let b = trimmed.as_bytes();
        out_buf[out_len..out_len + b.len()].copy_from_slice(b);
        out_len += b.len();
        out_buf[out_len] = b'\n';
        out_len += 1;
    }
    write_text_file(PASSWD_PATH, &out_buf[..out_len], 0o644)?;

    // 2. Из /etc/shadow
    let len = read_text_file(SHADOW_PATH, &mut in_buf)?;
    let content = core::str::from_utf8(&in_buf[..len]).map_err(|_| AuthError::ParseError)?;
    out_len = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(colon) = trimmed.find(':') {
            if &trimmed[..colon] == username {
                continue;
            }
        }
        let b = trimmed.as_bytes();
        out_buf[out_len..out_len + b.len()].copy_from_slice(b);
        out_len += b.len();
        out_buf[out_len] = b'\n';
        out_len += 1;
    }
    write_text_file(SHADOW_PATH, &out_buf[..out_len], 0o600)?;

    // 3. Из /etc/group (удаляем группу пользователя и убираем из списков других групп)
    let len = read_text_file(GROUP_PATH, &mut in_buf)?;
    let content = core::str::from_utf8(&in_buf[..len]).map_err(|_| AuthError::ParseError)?;
    out_len = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split(':');
        let gname = match parts.next() {
            Some(g) => g,
            None => continue,
        };
        if gname == username {
            continue; // удаляем собственную группу пользователя
        }
        let gpass = parts.next().unwrap_or("x");
        let ggid = parts.next().unwrap_or("0");
        let members = parts.next().unwrap_or("");

        let mut row_buf = [0u8; 256];
        let mut r_pos = 0;
        let gn_b = gname.as_bytes();
        row_buf[r_pos..r_pos + gn_b.len()].copy_from_slice(gn_b);
        r_pos += gn_b.len();
        row_buf[r_pos] = b':';
        r_pos += 1;
        let gp_b = gpass.as_bytes();
        row_buf[r_pos..r_pos + gp_b.len()].copy_from_slice(gp_b);
        r_pos += gp_b.len();
        row_buf[r_pos] = b':';
        r_pos += 1;
        let gg_b = ggid.as_bytes();
        row_buf[r_pos..r_pos + gg_b.len()].copy_from_slice(gg_b);
        r_pos += gg_b.len();
        row_buf[r_pos] = b':';
        r_pos += 1;

        let mut first = true;
        for m in members.split(',') {
            let m_trim = m.trim();
            if m_trim.is_empty() || m_trim == username {
                continue;
            }
            if !first {
                row_buf[r_pos] = b',';
                r_pos += 1;
            }
            let mb = m_trim.as_bytes();
            row_buf[r_pos..r_pos + mb.len()].copy_from_slice(mb);
            r_pos += mb.len();
            first = false;
        }
        row_buf[r_pos] = b'\n';
        r_pos += 1;

        out_buf[out_len..out_len + r_pos].copy_from_slice(&row_buf[..r_pos]);
        out_len += r_pos;
    }
    write_text_file(GROUP_PATH, &out_buf[..out_len], 0o644)?;

    Ok(())
}

fn copy_bytes(out: &mut [u8], pos: &mut usize, data: &[u8]) -> Result<(), AuthError> {
    if *pos + data.len() > out.len() {
        return Err(AuthError::BufferTooSmall);
    }
    out[*pos..*pos + data.len()].copy_from_slice(data);
    *pos += data.len();
    Ok(())
}

/// Чистая функция для добавления пользователя в список участников группы в текстовом формате /etc/group.
pub fn add_user_to_group_text(
    group_content: &str,
    username: &str,
    group_name: &str,
    out: &mut [u8],
) -> Result<usize, AuthError> {
    let mut pos = 0;
    let mut found = false;

    for line in group_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            copy_bytes(out, &mut pos, trimmed.as_bytes())?;
            copy_bytes(out, &mut pos, b"\n")?;
            continue;
        }

        let mut parts = trimmed.split(':');
        let gname = parts.next().ok_or(AuthError::ParseError)?;
        let gpass = parts.next().unwrap_or("x");
        let ggid = parts.next().unwrap_or("0");
        let members = parts.next().unwrap_or("");

        if gname == group_name {
            found = true;
            // Проверяем, не состоит ли пользователь уже в этой группе
            for m in members.split(',') {
                if m.trim() == username {
                    return Err(AuthError::AlreadyExists);
                }
            }

            copy_bytes(out, &mut pos, gname.as_bytes())?;
            copy_bytes(out, &mut pos, b":")?;
            copy_bytes(out, &mut pos, gpass.as_bytes())?;
            copy_bytes(out, &mut pos, b":")?;
            copy_bytes(out, &mut pos, ggid.as_bytes())?;
            copy_bytes(out, &mut pos, b":")?;

            let trimmed_members = members.trim();
            if !trimmed_members.is_empty() {
                copy_bytes(out, &mut pos, trimmed_members.as_bytes())?;
                copy_bytes(out, &mut pos, b",")?;
            }
            copy_bytes(out, &mut pos, username.as_bytes())?;
            copy_bytes(out, &mut pos, b"\n")?;
        } else {
            copy_bytes(out, &mut pos, trimmed.as_bytes())?;
            copy_bytes(out, &mut pos, b"\n")?;
        }
    }

    if !found {
        return Err(AuthError::GroupNotFound);
    }

    Ok(pos)
}

/// Чистая функция для удаления пользователя из участников группы в текстовом формате /etc/group.
pub fn remove_user_from_group_text(
    group_content: &str,
    username: &str,
    group_name: &str,
    out: &mut [u8],
) -> Result<usize, AuthError> {
    let mut pos = 0;
    let mut group_found = false;
    let mut user_found = false;

    for line in group_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            copy_bytes(out, &mut pos, trimmed.as_bytes())?;
            copy_bytes(out, &mut pos, b"\n")?;
            continue;
        }

        let mut parts = trimmed.split(':');
        let gname = parts.next().ok_or(AuthError::ParseError)?;
        let gpass = parts.next().unwrap_or("x");
        let ggid = parts.next().unwrap_or("0");
        let members = parts.next().unwrap_or("");

        if gname == group_name {
            group_found = true;
            copy_bytes(out, &mut pos, gname.as_bytes())?;
            copy_bytes(out, &mut pos, b":")?;
            copy_bytes(out, &mut pos, gpass.as_bytes())?;
            copy_bytes(out, &mut pos, b":")?;
            copy_bytes(out, &mut pos, ggid.as_bytes())?;
            copy_bytes(out, &mut pos, b":")?;

            let mut first = true;
            for m in members.split(',') {
                let m_trim = m.trim();
                if m_trim.is_empty() {
                    continue;
                }
                if m_trim == username {
                    user_found = true;
                    continue;
                }
                if !first {
                    copy_bytes(out, &mut pos, b",")?;
                }
                copy_bytes(out, &mut pos, m_trim.as_bytes())?;
                first = false;
            }
            copy_bytes(out, &mut pos, b"\n")?;
        } else {
            copy_bytes(out, &mut pos, trimmed.as_bytes())?;
            copy_bytes(out, &mut pos, b"\n")?;
        }
    }

    if !group_found {
        return Err(AuthError::GroupNotFound);
    }
    if !user_found {
        return Err(AuthError::UserNotFound);
    }

    Ok(pos)
}

/// Добавляет пользователя в группу в файле /etc/group.
pub fn add_user_to_group(username: &str, group_name: &str) -> Result<(), AuthError> {
    if get_passwd_by_name(username)?.is_none() {
        return Err(AuthError::UserNotFound);
    }

    let mut in_buf = [0u8; 8192];
    let len = read_text_file(GROUP_PATH, &mut in_buf)?;
    let content = core::str::from_utf8(&in_buf[..len]).map_err(|_| AuthError::ParseError)?;

    let mut out_buf = [0u8; 8192];
    let out_len = add_user_to_group_text(content, username, group_name, &mut out_buf)?;
    write_text_file(GROUP_PATH, &out_buf[..out_len], 0o644)?;
    Ok(())
}

/// Удаляет пользователя из группы в файле /etc/group.
pub fn remove_user_from_group(username: &str, group_name: &str) -> Result<(), AuthError> {
    let mut in_buf = [0u8; 8192];
    let len = read_text_file(GROUP_PATH, &mut in_buf)?;
    let content = core::str::from_utf8(&in_buf[..len]).map_err(|_| AuthError::ParseError)?;

    let mut out_buf = [0u8; 8192];
    let out_len = remove_user_from_group_text(content, username, group_name, &mut out_buf)?;
    write_text_file(GROUP_PATH, &out_buf[..out_len], 0o644)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_user_to_group_text() {
        let original = "\
root:x:0:root
wheel:x:10:root
users:x:100:
";
        let mut out = [0u8; 1024];

        // 1. Успешное добавление нового пользователя в wheel
        let len = add_user_to_group_text(original, "alice", "wheel", &mut out).unwrap();
        let res = core::str::from_utf8(&out[..len]).unwrap();
        assert_eq!(
            res,
            "root:x:0:root\nwheel:x:10:root,alice\nusers:x:100:\n"
        );

        // 2. Добавление в группу с пустым списком участников
        let len = add_user_to_group_text(original, "bob", "users", &mut out).unwrap();
        let res = core::str::from_utf8(&out[..len]).unwrap();
        assert_eq!(
            res,
            "root:x:0:root\nwheel:x:10:root\nusers:x:100:bob\n"
        );

        // 3. Пользователь уже существует в группе
        let err = add_user_to_group_text(original, "root", "wheel", &mut out);
        assert_eq!(err, Err(AuthError::AlreadyExists));

        // 4. Несуществующая группа
        let err = add_user_to_group_text(original, "alice", "nonexistent", &mut out);
        assert_eq!(err, Err(AuthError::GroupNotFound));
    }

    #[test]
    fn test_remove_user_from_group_text() {
        let original = "\
root:x:0:root
wheel:x:10:root,alice,bob
users:x:100:charlie
";
        let mut out = [0u8; 1024];

        // 1. Удаление alice из середины списка wheel
        let len = remove_user_from_group_text(original, "alice", "wheel", &mut out).unwrap();
        let res = core::str::from_utf8(&out[..len]).unwrap();
        assert_eq!(
            res,
            "root:x:0:root\nwheel:x:10:root,bob\nusers:x:100:charlie\n"
        );

        // 2. Удаление единственного участника charlie из users
        let len = remove_user_from_group_text(original, "charlie", "users", &mut out).unwrap();
        let res = core::str::from_utf8(&out[..len]).unwrap();
        assert_eq!(
            res,
            "root:x:0:root\nwheel:x:10:root,alice,bob\nusers:x:100:\n"
        );

        // 3. Пользователя нет в группе
        let err = remove_user_from_group_text(original, "david", "wheel", &mut out);
        assert_eq!(err, Err(AuthError::UserNotFound));

        // 4. Несуществующая группа
        let err = remove_user_from_group_text(original, "alice", "unknown", &mut out);
        assert_eq!(err, Err(AuthError::GroupNotFound));
    }
}
