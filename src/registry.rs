use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR,
};
use windows_sys::Win32::System::Registry::{
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY, REG_ROUTINE_FLAGS, REG_SZ,
    RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};

use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

#[derive(Debug, Clone, Copy)]
pub enum Root {
    CurrentUser,
    LocalMachine,
}

impl Root {
    fn hkey(self) -> HKEY {
        match self {
            Self::CurrentUser => HKEY_CURRENT_USER,
            Self::LocalMachine => HKEY_LOCAL_MACHINE,
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn missing(err: WIN32_ERROR) -> bool {
    err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND
}

/// Raw value bytes - `Ok(None)` if the key or value doesn't exist
fn read(
    root: Root,
    key: &str,
    value: &str,
    kind: REG_ROUTINE_FLAGS,
) -> io::Result<Option<Vec<u8>>> {
    let (key, value) = (wide(key), wide(value));
    let mut buf = vec![0u8; 256];
    loop {
        let mut len = buf.len() as u32;
        let err = unsafe {
            RegGetValueW(
                root.hkey(),
                key.as_ptr(),
                value.as_ptr(),
                kind,
                ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        match err {
            ERROR_SUCCESS => {
                buf.truncate(len as usize);
                return Ok(Some(buf));
            }

            ERROR_MORE_DATA => buf.resize(len as usize + 2, 0),
            e if missing(e) => return Ok(None),
            e => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
}

pub fn read_string(root: Root, key: &str, value: &str) -> io::Result<Option<String>> {
    Ok(read(root, key, value, RRF_RT_REG_SZ)?.map(|bytes| {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }))
}

pub fn read_dword(root: Root, key: &str, value: &str) -> io::Result<Option<u32>> {
    Ok(read(root, key, value, RRF_RT_REG_DWORD)?
        .and_then(|b| Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))))
}

pub fn read_binary(root: Root, key: &str, value: &str) -> io::Result<Option<Vec<u8>>> {
    read(root, key, value, RRF_RT_REG_BINARY)
}

/// Creates the key if needed
pub fn set_string(root: Root, key: &str, value: &str, data: &str) -> io::Result<()> {
    let (key, value, data) = (wide(key), wide(value), wide(data));
    let err = unsafe {
        RegSetKeyValueW(
            root.hkey(),
            key.as_ptr(),
            value.as_ptr(),
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    match err {
        ERROR_SUCCESS => Ok(()),
        e => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

pub fn delete_value(root: Root, key: &str, value: &str) -> io::Result<()> {
    let (key, value) = (wide(key), wide(value));
    match unsafe { RegDeleteKeyValueW(root.hkey(), key.as_ptr(), value.as_ptr()) } {
        ERROR_SUCCESS => Ok(()),
        e if missing(e) => Ok(()),
        e => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_existing_and_missing_values() {
        let nt = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        let name = read_string(Root::LocalMachine, nt, "ProductName").unwrap();
        assert!(name.is_some_and(|n| n.starts_with("Windows")));
        assert_eq!(
            read_string(Root::LocalMachine, nt, "no-such-value").unwrap(),
            None
        );
        assert_eq!(
            read_dword(Root::LocalMachine, r"SOFTWARE\no-such-key", "x").unwrap(),
            None
        );
    }
}
