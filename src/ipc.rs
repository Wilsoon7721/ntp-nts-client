use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, RevertToSelf, TokenGroups,
    WinBuiltinAdministratorsSid, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_GROUPS,
    TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::config::CustomServer;
use crate::servers::Protocol;
use crate::sync::Status;

pub const PIPE_NAME: &str = r"\\.\pipe\nts-client";

/// The service and SYSTEM/Administrators: everything, interactive users: read + write data (0x12008b = FILE_GENERIC_READ | FILE_WRITE_DATA)
const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12008b;;;IU)";
/// FILE_GENERIC_READ | FILE_WRITE_DATA
const CLIENT_ACCESS: u32 = 0x0012_008b;

/// Longest request or reply line accepted
const MAX_LINE: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    SetServer {
        id: String,
        accept_unauthenticated: bool,
    },
    SetCustom {
        host: String,
        protocol: Protocol,
        accept_unauthenticated: bool,
    },
}

/// Who sent a request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Client {
    pub is_admin: bool,
}

/// Every reply carries the current state, whatever the request
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    /// Set if the request was refused
    pub error: Option<String>,
    /// Id of the selected server, or [`crate::config::CUSTOM_ID`]
    pub server_id: String,
    /// The custom server, if one is saved
    #[serde(default)]
    pub custom: Option<CustomServer>,
    pub status: Status,
}

/// Serves requests until creating a pipe instance fails
pub fn serve(
    name: &str,
    handler: impl Fn(Request, Client) -> Reply + Send + Sync + 'static,
) -> io::Result<()> {
    let handler = Arc::new(handler);
    let mut first = true;
    loop {
        let pipe = create_instance(name, first)?;
        first = false;
        let connected = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), ptr::null_mut()) } != 0
            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            continue;
        }
        let handler = Arc::clone(&handler);
        thread::spawn(move || {
            let _ = handle_client(&pipe, &*handler);
            unsafe {
                FlushFileBuffers(pipe.as_raw_handle());
                DisconnectNamedPipe(pipe.as_raw_handle());
            }
        });
    }
}

fn create_instance(name: &str, first: bool) -> io::Result<File> {
    let wide_name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let wide_sddl: Vec<u16> = SDDL.encode_utf16().chain([0]).collect();
    unsafe {
        let mut descriptor = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let handle = CreateNamedPipeW(
            wide_name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            &attributes,
        );
        let err = io::Error::last_os_error();
        LocalFree(descriptor);
        if handle == INVALID_HANDLE_VALUE {
            return Err(err);
        }
        Ok(File::from_raw_handle(handle))
    }
}

fn handle_client(pipe: &File, handler: &dyn Fn(Request, Client) -> Reply) -> io::Result<()> {
    let mut line = String::new();
    BufReader::new(pipe.take(MAX_LINE)).read_line(&mut line)?;
    let client = Client {
        is_admin: client_is_admin(pipe),
    };
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(request) => handler(request, client),
        Err(e) => {
            let mut r = handler(Request::Status, client);
            r.error = Some(format!("bad request: {e}"));
            r
        }
    };
    let mut out = serde_json::to_string(&reply).map_err(io::Error::other)?;
    out.push('\n');
    (&*pipe).write_all(out.as_bytes())
}

/// Takes on the client's identity to read its token
fn client_is_admin(pipe: &File) -> bool {
    unsafe {
        if ImpersonateNamedPipeClient(pipe.as_raw_handle()) == 0 {
            return false;
        }
        let mut token: HANDLE = ptr::null_mut();
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) != 0;
        RevertToSelf();
        if !opened {
            return false;
        }
        let admin = token_has_admin_group(token);
        CloseHandle(token);
        admin
    }
}

unsafe fn token_has_admin_group(token: HANDLE) -> bool {
    unsafe {
        let mut len = 0u32;
        GetTokenInformation(token, TokenGroups, ptr::null_mut(), 0, &mut len);
        if len == 0 {
            return false;
        }
        // u64s so the TOKEN_GROUPS read from it is suitably aligned
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        if GetTokenInformation(token, TokenGroups, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
            return false;
        }
        let groups = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let entries =
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);

        let mut admins = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = SECURITY_MAX_SID_SIZE;
        if CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            admins.as_mut_ptr().cast(),
            &mut size,
        ) == 0
        {
            return false;
        }
        let mask = (SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY) as u32;
        entries
            .iter()
            .any(|g| g.Attributes & mask != 0 && EqualSid(g.Sid, admins.as_mut_ptr().cast()) != 0)
    }
}

/// Sends a request to the service and waits for the reply
pub fn request(name: &str, request: &Request) -> io::Result<Reply> {
    let pipe = open(name)?;
    let mut out = serde_json::to_string(request).map_err(io::Error::other)?;
    out.push('\n');
    (&pipe).write_all(out.as_bytes())?;

    let mut line = String::new();
    BufReader::new((&pipe).take(MAX_LINE)).read_line(&mut line)?;
    serde_json::from_str(&line).map_err(io::Error::other)
}

/// Opens the pipe, retrying briefly while every instance is busy
fn open(name: &str) -> io::Result<File> {
    let mut attempts = 0;
    loop {
        match OpenOptions::new().access_mode(CLIENT_ACCESS).open(name) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempts < 20 => {
                attempts += 1;
                thread::sleep(Duration::from_millis(50));
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_json_shape() {
        let r = Request::SetServer {
            id: "pool".into(),
            accept_unauthenticated: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            r#"{"cmd":"set_server","id":"pool","accept_unauthenticated":true}"#
        );
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), r);
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"cmd":"status"}"#).unwrap(),
            Request::Status
        );
    }

    #[test]
    fn round_trip_over_a_real_pipe() {
        let name = format!(r"\\.\pipe\nts-client-test-{}", std::process::id());
        let server_name = name.clone();
        thread::spawn(move || {
            serve(&server_name, |req, client| Reply {
                error: match req {
                    Request::SetServer { id, .. } => Some(format!("refused {id}")),
                    Request::SetCustom { .. } => Some(format!("admin={}", client.is_admin)),
                    Request::Status => None,
                },
                server_id: "cloudflare".into(),
                custom: None,
                status: Status {
                    state: "Synced".into(),
                    ..Status::default()
                },
            })
        });

        // The server thread may not have created the pipe yet
        let status = (0..50)
            .find_map(|_| {
                request(&name, &Request::Status)
                    .inspect_err(|_| thread::sleep(Duration::from_millis(20)))
                    .ok()
            })
            .expect("server never answered");
        assert_eq!(status.status.state, "Synced");
        assert_eq!(status.error, None);

        // Several clients in a row each get their own instance
        for _ in 0..3 {
            let r = request(
                &name,
                &Request::SetServer {
                    id: "pool".into(),
                    accept_unauthenticated: false,
                },
            )
            .unwrap();
            assert_eq!(r.error.as_deref(), Some("refused pool"));
        }

        let r = request(
            &name,
            &Request::SetCustom {
                host: "example.org".into(),
                protocol: Protocol::Nts,
                accept_unauthenticated: false,
            },
        )
        .unwrap();
        let expected = format!("admin={}", own_token_is_admin());
        assert_eq!(r.error.as_deref(), Some(expected.as_str()));
    }

    fn own_token_is_admin() -> bool {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            assert!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0);
            let admin = token_has_admin_group(token);
            CloseHandle(token);
            admin
        }
    }

    #[test]
    fn first_instance_refuses_an_existing_pipe() {
        let name = format!(r"\\.\pipe\nts-client-squat-{}", std::process::id());
        let _squatter = create_instance(&name, false).unwrap();
        assert!(create_instance(&name, true).is_err());
    }
}
