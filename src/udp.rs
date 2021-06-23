//! # UDP Sockets for nrfxlib
//!
//! UDP socket related code.
//!
//! Copyright (c) 42 Technology Ltd 2019
//!
//! Dual-licensed under MIT and Apache 2.0. See the [README](../README.md) for
//! more details.

//******************************************************************************
// Sub-Modules
//******************************************************************************

// None

//******************************************************************************
// Imports
//******************************************************************************

use super::{get_last_error, Error};
use crate::{nal::Stack, raw::*};
use embedded_nal::SocketAddr;
use log::debug;
use nrfxlib_sys as sys;

//******************************************************************************
// Types
//******************************************************************************

/// Represents a connection to a remote TCP/IP device using plain UDP
#[derive(Debug)]
pub struct UdpSocket {
	socket: Socket,
}

//******************************************************************************
// Constants
//******************************************************************************

// None

//******************************************************************************
// Global Variables
//******************************************************************************

// None

//******************************************************************************
// Macros
//******************************************************************************

// None

//******************************************************************************
// Public Functions and Impl on Public Types
//******************************************************************************

// None

//******************************************************************************
// Private Functions and Impl on Private Types
//******************************************************************************

impl UdpSocket {
	/// Create a new TCP socket.
	pub fn new(domain: SocketDomain) -> Result<UdpSocket, Error> {
		let socket = Socket::new(
			domain,
			SocketType::Datagram,
			SocketProtocol::Udp,
		)?;

		// Now configure this socket

		Ok(UdpSocket { socket })
	}

	/// Look up the hostname and for each result returned, try to connect to
	/// it.
	pub fn connect(&self, hostname: &str, port: u16) -> Result<(), Error> {
		use core::fmt::Write;

		debug!("Connecting via UDP to {}:{}", hostname, port);

		// Now, make a null-terminated hostname
		let mut hostname_smallstring: heapless::String<64> = heapless::String::new();
		write!(hostname_smallstring, "{}\0", hostname).map_err(|_| Error::HostnameTooLong)?;
		// Now call getaddrinfo with some hints
		let hints = sys::nrf_addrinfo {
			ai_flags: 0,
			ai_family: sys::NRF_AF_INET as i32,
			ai_socktype: sys::NRF_SOCK_DGRAM as i32,
			ai_protocol: 0,
			ai_addrlen: 0,
			ai_addr: core::ptr::null_mut(),
			ai_canonname: core::ptr::null_mut(),
			ai_next: core::ptr::null_mut(),
		};
		let mut output_ptr: *mut sys::nrf_addrinfo = core::ptr::null_mut();
		let mut result = unsafe {
			sys::nrf_getaddrinfo(
				// hostname
				hostname_smallstring.as_ptr(),
				// service
				core::ptr::null(),
				// hints
				&hints,
				// output pointer
				&mut output_ptr,
			)
		};
		if (result == 0) && (!output_ptr.is_null()) {
			let mut record: &sys::nrf_addrinfo = unsafe { &*output_ptr };
			loop {
				let dns_addr: &sys::nrf_sockaddr_in =
					unsafe { &*(record.ai_addr as *const sys::nrf_sockaddr_in) };
				// Create a new sockaddr_in with the right port
				let connect_addr = sys::nrf_sockaddr_in {
					sin_len: core::mem::size_of::<sys::nrf_sockaddr_in>() as u8,
					sin_family: sys::NRF_AF_INET as i32,
					sin_port: htons(port),
					sin_addr: dns_addr.sin_addr,
				};

				debug!("Trying IP address {}", &crate::NrfSockAddrIn(connect_addr));

				// try and connect to this result
				result = unsafe {
					sys::nrf_connect(
						self.socket.fd,
						&connect_addr as *const sys::nrf_sockaddr_in as *const _,
						connect_addr.sin_len as u32,
					)
				};
				if result == 0 {
					break;
				}
				if !record.ai_next.is_null() {
					record = unsafe { &*record.ai_next };
				} else {
					break;
				}
			}
			unsafe {
				sys::nrf_freeaddrinfo(output_ptr);
			}
		}
		if result != 0 {
			Err(Error::Nordic("udp_connect", result, get_last_error()))
		} else {
			Ok(())
		}
	}
}

impl Pollable for UdpSocket {
	/// Get the underlying socket ID for this socket.
	fn get_fd(&self) -> i32 {
		self.socket.fd
	}
}

impl core::ops::DerefMut for UdpSocket {
	fn deref_mut(&mut self) -> &mut Socket {
		&mut self.socket
	}
}

impl core::ops::Deref for UdpSocket {
	type Target = Socket;
	fn deref(&self) -> &Socket {
		&self.socket
	}
}

impl embedded_nal::UdpClientStack for Stack {
	type UdpSocket = Option<UdpSocket>;
	type Error = Error;

	fn socket(&mut self) -> Result<Self::UdpSocket, Self::Error> {
        Ok(None)
    }

	fn connect(
		&mut self,
		socket: &mut Self::UdpSocket,
		remote: embedded_nal::SocketAddr,
	) -> Result<(), Self::Error> {
		let result = match remote {
			embedded_nal::SocketAddr::V4(addr) => {
				let socket = socket.insert(UdpSocket::new(SocketDomain::Inet)?);
				
				let sockaddr = sys::nrf_sockaddr_in {
					sin_len: core::mem::size_of::<sys::nrf_sockaddr_in>() as u8,
					sin_family: sys::NRF_AF_INET as i32,
					sin_port: htons(addr.port()),
					sin_addr: sys::nrf_in_addr {
						s_addr: u32::from_le_bytes(addr.ip().octets()),
					},
				};

				unsafe {
					sys::nrf_connect(
						socket.socket.fd,
						&sockaddr as *const sys::nrf_sockaddr_in as *const _,
						sockaddr.sin_len as u32,
					)
				}
			}
			embedded_nal::SocketAddr::V6(addr) => {
				let socket = socket.insert(UdpSocket::new(SocketDomain::Inet6)?);

				let sockaddr = sys::nrf_sockaddr_in6 {
					sin6_len: core::mem::size_of::<sys::nrf_sockaddr_in>() as u8,
					sin6_family: sys::NRF_AF_INET as i32,
					sin6_port: htons(addr.port()),
					sin6_addr: sys::nrf_in6_addr {
						s6_addr: addr.ip().octets(),
					},
					sin6_flowinfo: 0,
					sin6_scope_id: 0,		
				};

				unsafe {
					sys::nrf_connect(
						socket.socket.fd,
						&sockaddr as *const sys::nrf_sockaddr_in6 as *const _,
						sockaddr.sin6_len as u32,
					)
				}
			},
		};
		
		if result != 0 {
			Err(Error::Nordic("udp_connect", result, get_last_error()))
		} else {
			Ok(())
		}
    }

	fn send(
		&mut self,
		socket: &mut Self::UdpSocket,
		buffer: &[u8],
	) -> embedded_nal::nb::Result<(), Self::Error> {
        todo!()
    }

	fn receive(
		&mut self,
		socket: &mut Self::UdpSocket,
		buffer: &mut [u8],
	) -> embedded_nal::nb::Result<(usize, SocketAddr), Self::Error> {
        todo!()
    }

	fn close(&mut self, socket: Self::UdpSocket) -> Result<(), Self::Error> {
        drop(socket);
		Ok(())
    }
}

//******************************************************************************
// End of File
//******************************************************************************
