//! Linux AF_PACKET access used by the OpenWrt Agent.
//!
//! The socket is deliberately attached to a configured interface rather than
//! guessing which switch VLAN faces the door or the physical pad.  It receives
//! complete Ethernet frames and can inject a complete frame unchanged.

use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result};

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: i32 = 263;
const PACKET_ADD_MEMBERSHIP: i32 = 1;
const PACKET_MR_PROMISC: u16 = 1;
const PACKET_IGNORE_OUTGOING: i32 = 23;

pub struct PacketSocket {
    fd: OwnedFd,
    ifindex: i32,
    interface: String,
}

impl PacketSocket {
    pub fn open(interface: &str) -> Result<Self> {
        let name = CString::new(interface).context("interface contains NUL")?;
        // SAFETY: name is a valid, NUL-terminated C string.
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) } as i32;
        anyhow::ensure!(
            ifindex > 0,
            "interface {interface}: {}",
            io::Error::last_os_error()
        );
        // SAFETY: socket arguments are Linux AF_PACKET constants.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                ETH_P_ALL.to_be() as i32,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error()).context("opening AF_PACKET socket");
        }
        // SAFETY: ownership of the newly-created descriptor is transferred.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let one: libc::c_int = 1;
        // Ignore frames emitted by this same socket, preventing injection loops.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_IGNORE_OUTGOING,
                &one as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        // SAFETY: zero is a valid initialization for sockaddr_ll.
        let mut address: libc::sockaddr_ll = unsafe { zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = ETH_P_ALL.to_be();
        address.sll_ifindex = ifindex;
        // SAFETY: address and length exactly describe sockaddr_ll.
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("binding AF_PACKET socket to {interface}"));
        }
        let membership = libc::packet_mreq {
            mr_ifindex: ifindex,
            mr_type: PACKET_MR_PROMISC,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        // SAFETY: membership and its exact size are passed to setsockopt.
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &membership as *const _ as *const libc::c_void,
                size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("enabling promiscuous capture on {interface}"));
        }
        Ok(Self {
            fd,
            ifindex,
            interface: interface.into(),
        })
    }

    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buffer is writable for its complete advertised length.
        let length = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };
        if length < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(length as usize)
        }
    }

    pub fn send(&self, frame: &[u8]) -> io::Result<usize> {
        // SAFETY: frame is readable for its complete advertised length.
        let length = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
        };
        if length < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(length as usize)
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }
}
