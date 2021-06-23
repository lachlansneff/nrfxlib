//! The dns module contains the implementation of the embedded-nal::Dns trait for crate::nal::Stack;

use super::{get_last_error, Error};
use embedded_nal::IpAddr;
use nrfxlib_sys as sys;

impl embedded_nal::Dns for crate::nal::Stack {
    type Error = Error;

	/// # Usage:
	/// ```rust, norun
	/// let mut client = TcpClient::default();
	/// 
	/// let addresses = client.get_hosts_by_name("google.com", AddrType::IPv6)?;
	/// for addr in addresses {
	///		println!("{:?", addr);
	/// }
	/// ```
    fn get_hosts_by_name<const UP_TO: usize>(
		&mut self,
		hostname: &str,
		addr_type: embedded_nal::AddrType,
	) -> Result<heapless::Vec<IpAddr, UP_TO>, Self::Error> {
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
			ai_socktype: 0,
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
			let mut ret = heapless::Vec::new();
			let mut record: &sys::nrf_addrinfo = unsafe { &*output_ptr };
		
			// There's always at least one item in the linked list.
			for _ in 0..UP_TO {
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

				unsafe { ret.push_unchecked(addr); }

				if record.ai_next.is_null() {
					break;
				} else {
					record = unsafe { &*record.ai_next };
				}
			}

			Ok(ret)
		} else {
			Err(Error::Nordic("dns_resolve", result, get_last_error()))
		}
    }

    fn get_host_by_address(&mut self, _addr: embedded_nal::IpAddr) -> Result<heapless::String<256>, Self::Error> {
        Err(Error::IPAddrToHostNameUnsupported)
    }
}
