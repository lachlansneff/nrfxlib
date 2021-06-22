//! # TCP Sockets for nrfxlib
//!
//! TCP socket related code.
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

use core::mem::MaybeUninit;

use super::{get_last_error, Error};
use crate::raw::*;
use embedded_nal::IpAddr;
use log::debug;
use nrfxlib_sys as sys;

//******************************************************************************
// Types
//******************************************************************************

/// Represents a connection to a remote TCP/IP device using plain TCP
#[derive(Debug)]
pub struct TcpSocket {
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

impl TcpSocket {
	/// Create a new TCP socket.
	pub fn new() -> Result<TcpSocket, Error> {
		let socket = Socket::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)?;

		// Now configure this socket

		Ok(TcpSocket { socket })
	}

	/// Look up the hostname and for each result returned, try to connect to
	/// it.
	pub fn connect(&self, hostname: &str, port: u16) -> Result<(), Error> {
		use core::fmt::Write;

		debug!("Connecting via TCP to {}:{}", hostname, port);

		// Now, make a null-terminated hostname
		let mut hostname_smallstring: heapless::String<64> = heapless::String::new();
		write!(hostname_smallstring, "{}\0", hostname).map_err(|_| Error::HostnameTooLong)?;
		// Now call getaddrinfo with some hints
		let hints = sys::nrf_addrinfo {
			ai_flags: 0,
			ai_family: sys::NRF_AF_INET as i32,
			ai_socktype: sys::NRF_SOCK_STREAM as i32,
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
			Err(Error::Nordic("tcp_connect", result, get_last_error()))
		} else {
			Ok(())
		}
	}
}

impl Pollable for TcpSocket {
	/// Get the underlying socket ID for this socket.
	fn get_fd(&self) -> i32 {
		self.socket.fd
	}
}

impl core::ops::DerefMut for TcpSocket {
	fn deref_mut(&mut self) -> &mut Socket {
		&mut self.socket
	}
}

impl core::ops::Deref for TcpSocket {
	type Target = Socket;
	fn deref(&self) -> &Socket {
		&self.socket
	}
}

/// Struct used to implement embedded-nal traits.
#[derive(Default)]
pub struct TcpClient {
	_private: (),
}

impl embedded_nal::TcpClientStack for TcpClient {
	type TcpSocket = TcpSocket;
	type Error = Error;

	fn socket(&mut self) -> Result<Self::TcpSocket, Self::Error> {
        TcpSocket::new()
    }

	fn connect(
		&mut self,
		socket: &mut TcpSocket,
		remote: embedded_nal::SocketAddr,
	) -> embedded_nal::nb::Result<(), Self::Error> {
		let result = match remote {
			embedded_nal::SocketAddr::V4(addr) => {
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
			Err(embedded_nal::nb::Error::Other(Error::Nordic("tcp_connect", result, get_last_error())))
		} else {
			Ok(())
		}
    }

	fn is_connected(&mut self, socket: &TcpSocket) -> Result<bool, Self::Error> {
        todo!()
    }

	fn send(
		&mut self,
		socket: &mut Self::TcpSocket,
		buffer: &[u8],
	) -> embedded_nal::nb::Result<usize, Self::Error> {
        todo!()
    }

	fn receive(
		&mut self,
		socket: &mut TcpSocket,
		buffer: &mut [u8],
	) -> embedded_nal::nb::Result<usize, Self::Error> {
        todo!()
    }

	fn close(&mut self, socket: TcpSocket) -> Result<(), Self::Error> {
        drop(socket);
		Ok(())
    }
}

/// The iterator returned by `embedded-nal::Dns::get_hosts_by_name`.
pub struct IpAddrIter {
	record: Option<&'static sys::nrf_addrinfo>,
	output_ptr: *mut sys::nrf_addrinfo,
}

impl Iterator for IpAddrIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
		if let Some(record) = self.record.take() {
			let addr = match record.ai_family as u32 {
				sys::NRF_AF_INET => {
					let dns_addr: &sys::nrf_sockaddr_in = unsafe { &*(record.ai_addr as *const _) };

					embedded_nal::IpAddr::V4(dns_addr.sin_addr.s_addr.into())
				},
				sys::NRF_AF_INET6 => {
					let dns_addr: &sys::nrf_sockaddr_in6 = unsafe { &*(record.ai_addr as *const _) };

					embedded_nal::IpAddr::V6(dns_addr.sin6_addr.s6_addr.into())
				},
				_ => unimplemented!(),
			};

			if !record.ai_next.is_null() {
				self.record = Some(unsafe { &*record.ai_next });
			}

			Some(addr)
		} else {
			None
		}
    }
}

impl Drop for IpAddrIter {
    fn drop(&mut self) {
        unsafe {
			sys::nrf_freeaddrinfo(self.output_ptr);
		}
    }
}

impl<'a> embedded_nal::Dns<'a> for TcpClient {
    type Error = Error;
	type IpAddrIter = IpAddrIter;

	/// # Usage:
	/// ```rust, norun
	/// let mut client = TcpClient::default();
	/// 
	/// let addresses = client.get_hosts_by_name("google.com", AddrType::IPv6)?;
	/// for addr in addresses {
	///		println!("{:?", addr);
	/// }
	/// ```
    fn get_hosts_by_name(
		&'a mut self,
		hostname: &'a str,
		addr_type: embedded_nal::AddrType,
	) -> Result<IpAddrIter, Self::Error> {
		use core::fmt::Write;

		// Hostnames can be a maximum of 244 characters.
		let mut hostname_smallstring: heapless::String<255> = heapless::String::new();
		write!(hostname_smallstring, "{}\0", hostname).map_err(|_| Error::HostnameTooLong)?;

		// Now call getaddrinfo with some hints
		let hints = sys::nrf_addrinfo {
			ai_flags: 0,
			ai_family: match addr_type {
				embedded_nal::AddrType::IPv4 => sys::NRF_AF_INET as i32,
				embedded_nal::AddrType::IPv6 => sys::NRF_AF_INET6 as i32,
				embedded_nal::AddrType::Either => 0,
			},
			ai_socktype: sys::NRF_SOCK_STREAM as i32,
			ai_protocol: 0,
			ai_addrlen: 0,
			ai_addr: core::ptr::null_mut(),
			ai_canonname: core::ptr::null_mut(),
			ai_next: core::ptr::null_mut(),
		};
		let mut output_ptr: *mut sys::nrf_addrinfo = core::ptr::null_mut();
		let result = unsafe {
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
			let record: &sys::nrf_addrinfo = unsafe { &*output_ptr };

			Ok(IpAddrIter {
				record: Some(record),
				output_ptr,
			})
		} else {
			Err(Error::Nordic("dns_resolve", result, get_last_error()))
		}
    }

    fn get_host_by_address(&mut self, _addr: embedded_nal::IpAddr) -> Result<heapless::String<256>, Self::Error> {
        Err(Error::IPAddrToHostNameUnsupported)
    }
}

//******************************************************************************
// End of File
//******************************************************************************
