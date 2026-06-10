//! Async, throttled reverse-DNS lookups.
//!
//! We don't add a new dep — we just use the system resolver via `tokio::net::lookup_host`
//! is wrong direction; instead, `tokio::task::spawn_blocking(|| dns_lookup::lookup_addr(ip))`
//! would be ideal but pulls a dep. To stay dependency-free, we shell out to nothing —
//! we use std's blocking getaddrinfo for forward only. Reverse needs `getnameinfo`.
//!
//! `std` doesn't expose `getnameinfo` directly, so we call libc via a small unsafe wrapper.
//! macOS + Linux both have it under the same signature.

use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tokio::task;
use tokio::time::timeout;

use super::engine::CaptureEvent;

/// Spawn a reverse-DNS lookup for `ip`. On success, sends a `CaptureEvent::Rdns` back.
pub fn spawn_lookup(tx: UnboundedSender<CaptureEvent>, ip: IpAddr) {
    tokio::spawn(async move {
        let res = timeout(
            Duration::from_secs(2),
            task::spawn_blocking(move || resolve_blocking(ip)),
        )
        .await;
        if let Ok(Ok(Some(name))) = res {
            let _ = tx.send(CaptureEvent::Rdns { ip, name });
        }
    });
}

fn resolve_blocking(ip: IpAddr) -> Option<String> {
    let sa: SocketAddr = SocketAddr::new(ip, 0);
    let mut storage: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::zeroed();
    let salen = match sa {
        SocketAddr::V4(v4) => {
            let p = storage.as_mut_ptr() as *mut libc::sockaddr_in;
            unsafe {
                (*p).sin_family = libc::AF_INET as _;
                (*p).sin_port = v4.port().to_be();
                (*p).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                };
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let p = storage.as_mut_ptr() as *mut libc::sockaddr_in6;
            unsafe {
                (*p).sin6_family = libc::AF_INET6 as _;
                (*p).sin6_port = v6.port().to_be();
                (*p).sin6_addr = libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                };
                (*p).sin6_flowinfo = 0;
                (*p).sin6_scope_id = v6.scope_id();
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };

    let mut host_buf = [0u8; 256];
    let rc = unsafe {
        libc::getnameinfo(
            storage.as_ptr() as *const _,
            salen,
            host_buf.as_mut_ptr() as *mut _,
            host_buf.len() as _,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return None;
    }
    let c = unsafe { CStr::from_ptr(host_buf.as_ptr() as *const _) };
    let s = c.to_string_lossy().into_owned();
    if s.is_empty() || s == ip.to_string() {
        None
    } else {
        Some(s)
    }
}

// Keep CString unused warning silent for the path where we don't construct one.
const _: fn() = || {
    let _ = CString::new("").is_ok();
};
