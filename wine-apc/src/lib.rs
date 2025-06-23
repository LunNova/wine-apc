// SPDX-FileCopyrightText: 2025 LunNova
//
// SPDX-License-Identifier: AGPL-3.0-or-later

mod protocol;

use std::any::type_name;
use std::fs;
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

pub use protocol::*;

/// Wine client
pub struct WineClient {
	_socket: UnixStream, // Keep socket alive
	request_fd: RawFd,
	reply_fd: RawFd,
	our_wine_pid: u32, // Our Wine process ID from init_first_thread
}

impl WineClient {
	/// Connect to Wine server for the given process ID
	pub fn connect_to_wine_process(pid: u32) -> io::Result<Self> {
		let socket_path = Self::find_wine_socket(pid)?;

		debug!("Connecting to socket: {socket_path:?}");
		let socket = UnixStream::connect(&socket_path)?;
		let socket_fd = socket.as_raw_fd();

		// Enable SO_PASSCRED for credential passing
		debug!("Enabling SO_PASSCRED");
		Self::enable_passcred(socket_fd)?;

		// Perform Wine handshake
		debug!("Performing Wine handshake");
		let request_fd = Self::receive_request_fd(socket_fd)?;
		debug!("Received request fd: {request_fd}");

		// Create pipes for communication
		let (reply_read_fd, reply_write_fd) = Self::create_pipe()?;
		let (wait_read_fd, wait_write_fd) = Self::create_pipe()?;

		// Initialize Wine client
		let mut client = Self {
			request_fd,
			reply_fd: reply_read_fd,
			_socket: socket,
			our_wine_pid: 0,
		};

		// Perform Wine handshake using the correct sequence
		client.init_first_thread_with_fds(socket_fd, reply_write_fd, wait_write_fd)?;
		client.init_process_done()?;

		// Clean up write ends
		unsafe {
			libc::close(reply_write_fd);
			libc::close(wait_write_fd);
			libc::close(wait_read_fd);
		}

		Self::disable_passcred(socket_fd)?;
		info!("Wine client initialization complete");
		Ok(client)
	}

	/// Send a Wine request with proper 64-byte padding
	fn send_request<T>(&self, request: &T) -> io::Result<()> {
		let mut padded_request = [0u8; WINE_REQUEST_SIZE];
		let request_bytes = unsafe { std::slice::from_raw_parts(request as *const _ as *const u8, mem::size_of::<T>()) };
		padded_request[..request_bytes.len()].copy_from_slice(request_bytes);

		trace!(
			"send_request<{}> - size: {} bytes, padded to: {} bytes",
			std::any::type_name::<T>(),
			mem::size_of::<T>(),
			WINE_REQUEST_SIZE
		);
		trace!("Request bytes: {:02x?}", &padded_request[..32]);

		let write_result = unsafe {
			libc::write(
				self.request_fd,
				padded_request.as_ptr() as *const libc::c_void,
				padded_request.len(),
			)
		};

		if write_result != WINE_REQUEST_SIZE as isize {
			let error = if write_result == -1 {
				io::Error::last_os_error()
			} else {
				io::Error::new(
					io::ErrorKind::WriteZero,
					format!("Expected to write {WINE_REQUEST_SIZE} bytes, wrote {write_result}"),
				)
			};
			warn!("Write failed: {error}");
			return Err(error);
		}

		trace!("Successfully wrote {write_result} bytes");
		Ok(())
	}

	/// Send a Wine request with additional data (atomic write)
	fn send_request_with_data<T, D>(&self, request: &T, data: &D) -> io::Result<()> {
		// FIXME: wine uses one writev with two 64b bufs instead of a single large buf
		let data_size = mem::size_of::<D>();
		// FIXED: Pad APC data to 64 bytes to match Wine's union apc_call size
		// Wine's wine_server_add_data always uses sizeof(union apc_call) = 64 bytes
		let padded_data_size = if data_size == mem::size_of::<crate::protocol::VirtualAllocCall>() {
			WINE_REQUEST_SIZE // 64 bytes to match union apc_call
		} else {
			data_size // For non-APC data, use original size
		};
		let total_size = WINE_REQUEST_SIZE + padded_data_size;
		let mut combined_buffer = vec![0u8; total_size];

		// Pack the request (padded to 64 bytes)
		let request_bytes = unsafe { std::slice::from_raw_parts(request as *const _ as *const u8, mem::size_of::<T>()) };
		combined_buffer[..request_bytes.len()].copy_from_slice(request_bytes);

		// Pack the data immediately after the padded request, zero-padded to 64 bytes for APC
		let data_bytes = unsafe { std::slice::from_raw_parts(data as *const _ as *const u8, data_size) };
		combined_buffer[WINE_REQUEST_SIZE..WINE_REQUEST_SIZE + data_size].copy_from_slice(data_bytes);
		// The rest of the padded_data_size is already zero-filled by vec![0u8; total_size]

		trace!(
			"send_request_with_data<{}, {}> - request size: {} bytes, data size: {} bytes (padded to {}), total: {} bytes",
			std::any::type_name::<T>(),
			std::any::type_name::<D>(),
			mem::size_of::<T>(),
			data_size,
			padded_data_size,
			total_size
		);
		trace!("Request bytes: {:02x?}", &combined_buffer[..32]);
		trace!(
			"Data bytes: {:02x?}",
			&combined_buffer[WINE_REQUEST_SIZE..WINE_REQUEST_SIZE + std::cmp::min(32, padded_data_size)]
		);

		let write_result = unsafe {
			libc::write(
				self.request_fd,
				combined_buffer.as_ptr() as *const libc::c_void,
				combined_buffer.len(),
			)
		};

		if write_result != combined_buffer.len() as isize {
			return Err(io::Error::new(
				io::ErrorKind::WriteZero,
				format!("Incomplete write: expected {} bytes, wrote {}", combined_buffer.len(), write_result),
			));
		}

		trace!("Successfully wrote {write_result} bytes");
		Ok(())
	}

	/// Read a Wine reply with 64-byte padding
	fn read_reply<T>(&self) -> io::Result<T> {
		let mut padded_reply = [0u8; WINE_REQUEST_SIZE];

		trace!(
			"read_reply<{}> - expecting {} bytes struct, reading {} bytes padded",
			std::any::type_name::<T>(),
			mem::size_of::<T>(),
			WINE_REQUEST_SIZE
		);

		let read_result = unsafe { libc::read(self.reply_fd, padded_reply.as_mut_ptr() as *mut libc::c_void, padded_reply.len()) };

		if read_result != WINE_REQUEST_SIZE as isize {
			return Err(io::Error::new(
				io::ErrorKind::UnexpectedEof,
				format!("Expected {WINE_REQUEST_SIZE} bytes, got {read_result}"),
			));
		}

		trace!("Successfully read {read_result} bytes");
		trace!("Reply bytes: {:02x?}", &padded_reply[..32]);

		// Copy the meaningful struct data to our reply struct
		let mut reply: T = unsafe { mem::zeroed() };
		unsafe {
			std::ptr::copy_nonoverlapping(padded_reply.as_ptr(), &mut reply as *mut _ as *mut u8, mem::size_of::<T>());
		}

		Ok(reply)
	}

	/// Check for unread data in the reply pipe
	fn check_pipe_clean(&self, context: &str) -> io::Result<()> {
		let mut poll_fd = libc::pollfd {
			fd: self.reply_fd,
			events: libc::POLLIN,
			revents: 0,
		};

		let poll_result = unsafe { libc::poll(&mut poll_fd, 1, 0) };

		if poll_result < 0 {
			return Err(io::Error::last_os_error());
		}

		if poll_result > 0 && (poll_fd.revents & libc::POLLIN) != 0 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("Unread data in pipe after {context}"),
			));
		}

		trace!("Pipe clean after {context}");
		Ok(())
	}

	/// Initialize first thread with Wine server using correct FD sequence
	fn init_first_thread_with_fds(&mut self, socket_fd: RawFd, reply_write_fd: RawFd, wait_write_fd: RawFd) -> io::Result<()> {
		debug!("Starting init_first_thread_with_fds - reply_fd: {reply_write_fd}, wait_fd: {wait_write_fd}");

		// First send the FDs to Wine server
		debug!("Sending FDs to Wine server");
		Self::send_fd_to_server(socket_fd, reply_write_fd)?;
		Self::send_fd_to_server(socket_fd, wait_write_fd)?;

		// Then send the init_first_thread request
		let request = InitFirstThreadRequest {
			header: RequestHeader {
				req: REQ_INIT_FIRST_THREAD,
				request_size: 0,
				reply_size: mem::size_of::<InitFirstThreadReply>() as u32 - mem::size_of::<ReplyHeader>() as u32,
			},
			unix_pid: unsafe { libc::getpid() },
			unix_tid: unsafe { libc::gettid() },
			debug_level: 0,
			reply_fd: reply_write_fd,
			wait_fd: wait_write_fd,
		};

		debug!("Sending init_first_thread request");
		self.send_request(&request)?;

		debug!("Reading init_first_thread reply");
		let reply: InitFirstThreadReply = self.read_reply()?;

		if reply.header.error != 0 {
			return Err(io::Error::other(format!(
				"init_first_thread failed with NTSTATUS: 0x{:08x}",
				reply.header.error
			)));
		}

		// Store our Wine PID
		self.our_wine_pid = reply.pid;

		// Handle additional data if indicated by reply_size
		if reply.header.reply_size > 0 {
			let mut additional_data = vec![0u8; reply.header.reply_size as usize];
			let read_result = unsafe {
				libc::read(
					self.reply_fd,
					additional_data.as_mut_ptr() as *mut libc::c_void,
					additional_data.len(),
				)
			};
			if read_result < 0 {
				return Err(io::Error::last_os_error());
			}
		}

		self.check_pipe_clean("init_first_thread")?;
		Ok(())
	}

	/// Complete Wine process initialization
	fn init_process_done(&mut self) -> io::Result<()> {
		let request = InitProcessDoneRequest {
			header: RequestHeader {
				req: REQ_INIT_PROCESS_DONE,
				request_size: 0,
				reply_size: mem::size_of::<InitProcessDoneReply>() as u32 - mem::size_of::<ReplyHeader>() as u32,
			},
			_pad: [0; 4],
			teb: 0,
			peb: 0,
			ldt_copy: 0,
		};

		self.send_request(&request)?;

		let reply: InitProcessDoneReply = self.read_reply()?;

		if reply.header.error != 0 {
			return Err(io::Error::other(format!(
				"init_process_done failed with NTSTATUS: 0x{:08x}",
				reply.header.error
			)));
		}

		self.check_pipe_clean("init_process_done")?;
		Ok(())
	}

	/// Open a process handle for the given PID
	pub fn open_process(&mut self, pid: u32, access: u32) -> io::Result<u32> {
		let request = OpenProcessRequest {
			header: RequestHeader {
				req: REQ_OPEN_PROCESS,
				request_size: 0,
				reply_size: mem::size_of::<OpenProcessReply>() as u32 - mem::size_of::<ReplyHeader>() as u32,
			},
			pid,
			access,
			attributes: 0,
		};

		self.send_request(&request)?;

		let reply: OpenProcessReply = self.read_reply()?;

		if reply.header.error != 0 {
			return Err(io::Error::other(format!(
				"open_process failed with NTSTATUS: 0x{:08x}",
				reply.header.error
			)));
		}

		debug!("open_process reply handle: 0x{:x}", reply.handle);

		Ok(reply.handle)
	}

	/// Queue an APC to the Wine process
	fn queue_apc(&mut self, process_handle: u32, apc_call: &VirtualAllocCall) -> io::Result<u32> {
		let request = QueueApcRequest {
			header: RequestHeader {
				req: REQ_QUEUE_APC,
				// FIXED: Use 64 bytes to match Wine's union apc_call size
				request_size: WINE_REQUEST_SIZE as u32, // 64 bytes
				reply_size: mem::size_of::<QueueApcReply>() as u32 - mem::size_of::<ReplyHeader>() as u32,
			},
			handle: process_handle,
		};

		debug!("Queueing APC {}", type_name::<VirtualAllocCall>());

		self.send_request_with_data(&request, apc_call)?;

		let reply: QueueApcReply = self.read_reply()?;

		if reply.header.error != 0 {
			return Err(io::Error::other(format!(
				"queue_apc failed with NTSTATUS: 0x{:08x}",
				reply.header.error
			)));
		}

		if reply.self_exec != 0 {
			return Err(io::Error::other("Self-executing APC not supported in external client"));
		}

		self.check_pipe_clean("queue_apc")?;
		Ok(reply.handle)
	}

	/// Wait for APC completion using Wine's select mechanism
	fn wait_for_apc(&mut self, apc_handle: u32) -> io::Result<()> {
		// FIXME: this is not correct and always errors
		let request = SelectRequest {
			header: RequestHeader {
				req: REQ_SELECT,
				request_size: 48, // Match working Windows example: includes 40 bytes padding + 8 bytes data
				reply_size: mem::size_of::<SelectReply>() as u32 - mem::size_of::<ReplyHeader>() as u32,
			},
			flags: 2, // Match working Windows example (not SELECT_ALERTABLE=1)
			cookie: 0,
			timeout: 0x7fffffffffffffff, // TIMEOUT_INFINITE
			size: 2,                     // Match working Windows example: size of select operations
			prev_apc: 0,
		};

		debug!("Waiting for APC completion using select with handle {}", apc_handle);

		// Send select request with additional data matching Windows example:
		// 64 bytes request + 40 bytes padding + 8 bytes (size=2, prev_apc=handle)
		let mut padded_request = [0u8; WINE_REQUEST_SIZE];
		let request_bytes = unsafe { std::slice::from_raw_parts(&request as *const _ as *const u8, mem::size_of::<SelectRequest>()) };
		padded_request[..request_bytes.len()].copy_from_slice(request_bytes);

		let padding = [0u8; 40];
		let select_data = [2u32.to_le_bytes(), apc_handle.to_le_bytes()].concat();

		// Use writev to send all three parts atomically like Windows does
		let write_result = unsafe {
			let iovs = [
				libc::iovec {
					iov_base: padded_request.as_ptr() as *mut libc::c_void,
					iov_len: padded_request.len(),
				},
				libc::iovec {
					iov_base: padding.as_ptr() as *mut libc::c_void,
					iov_len: padding.len(),
				},
				libc::iovec {
					iov_base: select_data.as_ptr() as *mut libc::c_void,
					iov_len: select_data.len(),
				},
			];
			libc::writev(self.request_fd, iovs.as_ptr(), 3)
		};

		if write_result != (WINE_REQUEST_SIZE + 40 + 8) as isize {
			return Err(io::Error::new(
				io::ErrorKind::WriteZero,
				format!("Expected to write {} bytes, wrote {}", WINE_REQUEST_SIZE + 40 + 8, write_result),
			));
		}

		let reply: SelectReply = self.read_reply()?;

		if reply.header.error != 0 {
			return Err(io::Error::other(format!(
				"wait_for_apc failed with NTSTATUS: 0x{:08x}",
				reply.header.error
			)));
		}

		debug!("APC wait completed, signaled: {}", reply.signaled);
		self.check_pipe_clean("wait_for_apc")?;
		Ok(())
	}

	/// Get the result of an APC call
	fn get_apc_result(&mut self, apc_handle: u32) -> io::Result<VirtualAllocResult> {
		let request = GetApcResultRequest {
			header: RequestHeader {
				req: REQ_GET_APC_RESULT,
				request_size: 0,
				reply_size: mem::size_of::<GetApcResultReply>() as u32 - mem::size_of::<ReplyHeader>() as u32,
			},
			handle: apc_handle,
		};

		self.send_request(&request)?;

		let reply: GetApcResultReply = self.read_reply()?;

		if reply.header.error != 0 {
			return Err(io::Error::other(format!(
				"get_apc_result failed with NTSTATUS: 0x{:08x}",
				reply.header.error
			)));
		}

		self.check_pipe_clean("get_apc_result")?;
		Ok(reply.result)
	}

	/// Allocate memory in the remote Wine process
	pub fn virtual_alloc_ex(
		&mut self,
		process_handle: u32,
		address: Option<u64>,
		size: u64,
		allocation_type: u32,
		protection: u32,
	) -> io::Result<(u64, u64)> {
		let apc_call = VirtualAllocCall {
			apc_type: APC_VIRTUAL_ALLOC,
			op_type: allocation_type,
			addr: address.unwrap_or(0),
			size,
			zero_bits: 0,
			prot: protection,
		};

		let apc_handle = self.queue_apc(process_handle, &apc_call)?;
		// self.wait_for_apc(apc_handle)?;
		// FIXME: wait_for_apc needs to work - NtWaitForSingleObject(handle)
		std::thread::sleep(Duration::from_millis(16));
		let result = self.get_apc_result(apc_handle)?;

		if result.status == 0 {
			Ok((result.addr, result.size))
		} else {
			Err(io::Error::other(format!(
				"VirtualAllocEx failed with NTSTATUS: 0x{:08x}",
				result.status
			)))
		}
	}

	/// Map Linux process ID to Wine process ID
	pub fn linux_pid_to_wine_pid(&mut self, linux_pid: u32) -> io::Result<u32> {
		const BUFFER_SIZE: usize = 65536;

		let request = ListProcessesRequest {
			header: RequestHeader {
				req: REQ_LIST_PROCESSES,
				request_size: 0,
				reply_size: BUFFER_SIZE as u32,
			},
			_pad: [0; 4],
		};

		self.send_request(&request)?;

		// Read variable-length reply
		let mut buffer = vec![0u8; mem::size_of::<ListProcessesReply>() + BUFFER_SIZE];
		let read_result = unsafe { libc::read(self.reply_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };

		if read_result < 0 {
			return Err(io::Error::last_os_error());
		}

		let reply = unsafe { std::ptr::read(buffer.as_ptr() as *const ListProcessesReply) };

		if reply.header.error != 0 {
			return Err(io::Error::other(format!(
				"list_processes failed with NTSTATUS: 0x{:08x}",
				reply.header.error
			)));
		}

		self.check_pipe_clean("list_processes")?;

		// Parse process data
		let process_data_start = mem::size_of::<ListProcessesReply>();
		let process_data = &buffer[process_data_start..];

		debug!("Found {} Wine processes", reply.process_count);
		let mut pos = 0;
		for i in 0..reply.process_count {
			pos = (pos + 7) & !7; // Align to 8-byte boundary

			if pos + mem::size_of::<ProcessInfo>() > process_data.len() {
				break;
			}

			let process_info = unsafe { std::ptr::read(process_data.as_ptr().add(pos) as *const ProcessInfo) };

			// Read process name if available
			let name_start = pos + mem::size_of::<ProcessInfo>();
			let name_end = name_start + process_info.name_len as usize;
			let process_name = if name_end <= process_data.len() {
				String::from_utf8_lossy(&process_data[name_start..name_end]).to_string()
			} else {
				"<unknown>".to_string()
			};

			trace!(
				"  Process {}: Wine PID {} <-> Linux PID {} ({})",
				i, process_info.pid, process_info.unix_pid, process_name
			);

			if process_info.unix_pid == linux_pid as i32 {
				debug!("Found target! Linux PID {} -> Wine PID {}", linux_pid, process_info.pid);
				return Ok(process_info.pid);
			}

			// Skip to next process entry
			pos += mem::size_of::<ProcessInfo>();
			pos += process_info.name_len as usize;
			pos = (pos + 7) & !7;
			pos += process_info.thread_count as usize * mem::size_of::<ThreadInfo>();
		}

		Err(io::Error::new(
			io::ErrorKind::NotFound,
			format!("No Wine process found for Linux PID {linux_pid}"),
		))
	}

	/// Get our own Wine process ID
	pub fn get_our_wine_pid(&self) -> io::Result<u32> {
		if self.our_wine_pid == 0 {
			Err(io::Error::other("Wine PID not yet initialized"))
		} else {
			Ok(self.our_wine_pid)
		}
	}

	// Helper methods for Wine handshake
	fn find_wine_socket(pid: u32) -> io::Result<PathBuf> {
		let maps_path = format!("/proc/{pid}/maps");
		let maps_data = fs::read_to_string(&maps_path)?;

		for line in maps_data.lines() {
			if let Some(idx) = line.find("/tmp/.wine-")
				&& let Some(tmpmap_idx) = line.find("/tmpmap-")
			{
				let server_dir = &line[idx..tmpmap_idx];
				let socket_path = PathBuf::from(server_dir).join("socket");
				if socket_path.exists() {
					return Ok(socket_path);
				}
			}
		}

		Err(io::Error::new(
			io::ErrorKind::NotFound,
			format!("No Wine server socket found for PID {pid}"),
		))
	}

	fn enable_passcred(socket_fd: RawFd) -> io::Result<()> {
		let enable: libc::c_int = 1;
		let result = unsafe {
			libc::setsockopt(
				socket_fd,
				libc::SOL_SOCKET,
				libc::SO_PASSCRED,
				&enable as *const _ as *const libc::c_void,
				mem::size_of::<libc::c_int>() as libc::socklen_t,
			)
		};
		if result != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
	}

	fn disable_passcred(socket_fd: RawFd) -> io::Result<()> {
		let disable: libc::c_int = 0;
		unsafe {
			libc::setsockopt(
				socket_fd,
				libc::SOL_SOCKET,
				libc::SO_PASSCRED,
				&disable as *const _ as *const libc::c_void,
				mem::size_of::<libc::c_int>() as libc::socklen_t,
			);
		}
		Ok(())
	}

	fn receive_request_fd(socket_fd: RawFd) -> io::Result<RawFd> {
		let mut handle: u32 = 0;
		let mut iov = libc::iovec {
			iov_base: &mut handle as *mut u32 as *mut libc::c_void,
			iov_len: mem::size_of::<u32>(),
		};

		let mut cmsg_buffer = [0u8; 256];
		let mut msg: libc::msghdr = unsafe { mem::zeroed() };
		msg.msg_iov = &mut iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut libc::c_void;
		msg.msg_controllen = cmsg_buffer.len();

		let ret = unsafe { libc::recvmsg(socket_fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
		if ret <= 0 {
			return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "Failed to receive Wine handshake"));
		}

		// Extract file descriptor from control messages
		let mut received_fd = -1;
		unsafe {
			let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
			while !cmsg.is_null() {
				if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
					let fd_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
					received_fd = *fd_ptr;
					break;
				}
				cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
			}
		}

		if received_fd == -1 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"No file descriptor received in Wine handshake",
			));
		}

		// Verify protocol version
		if handle != SERVER_PROTOCOL_VERSION {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("Protocol version mismatch: expected {SERVER_PROTOCOL_VERSION}, got {handle}"),
			));
		}

		Ok(received_fd)
	}

	fn create_pipe() -> io::Result<(RawFd, RawFd)> {
		let mut pipe_fds = [0; 2];
		let result = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
		if result != 0 {
			Err(io::Error::last_os_error())
		} else {
			Ok((pipe_fds[0], pipe_fds[1]))
		}
	}

	fn send_fd_to_server(socket_fd: RawFd, fd_to_send: RawFd) -> io::Result<()> {
		// Wine expects 8 bytes of data: 4 zero bytes + 4 bytes containing the fd number
		let mut data = [0u8; 8];
		data[4..8].copy_from_slice(&(fd_to_send as u32).to_le_bytes());

		let mut iov = libc::iovec {
			iov_base: data.as_ptr() as *mut libc::c_void,
			iov_len: data.len(),
		};

		let mut cmsg_buffer = [0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
		let mut msg: libc::msghdr = unsafe { mem::zeroed() };
		msg.msg_iov = &mut iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut libc::c_void;
		msg.msg_controllen = cmsg_buffer.len();

		unsafe {
			let cmsg = libc::CMSG_FIRSTHDR(&msg);
			(*cmsg).cmsg_level = libc::SOL_SOCKET;
			(*cmsg).cmsg_type = libc::SCM_RIGHTS;
			(*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as usize;
			let data_ptr = libc::CMSG_DATA(cmsg) as *mut RawFd;
			*data_ptr = fd_to_send;
			msg.msg_controllen = (*cmsg).cmsg_len;
		}

		let result = unsafe { libc::sendmsg(socket_fd, &msg, 0) };
		if result < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
	}

	/// Send terminate_thread request for proper cleanup (avoids SIGQUIT)
	fn terminate_current_thread(&mut self) -> io::Result<()> {
		// Use GetCurrentThread() pseudo-handle: ~(ULONG_PTR)1 = 0xfffffffe (32-bit)
		const CURRENT_THREAD_PSEUDO_HANDLE: u32 = 0xfffffffe;

		let request = TerminateThreadRequest {
			header: RequestHeader {
				req: REQ_TERMINATE_THREAD,
				request_size: 0,
				reply_size: mem::size_of::<TerminateThreadReply>() as u32 - mem::size_of::<ReplyHeader>() as u32,
			},
			handle: CURRENT_THREAD_PSEUDO_HANDLE,
			exit_code: 0,
			_pad: [0; 4],
		};

		// Send the terminate request
		match self.send_request(&request) {
			Ok(_) => {
				trace!("Sent terminate_thread request");
				// Try to read the reply to ensure server processes it
				match self.read_reply::<TerminateThreadReply>() {
					Ok(reply) => {
						debug!("Server acknowledged thread termination (self={})", reply.self_);
						// If self_=1, the server will terminate us after this response
						// so we should expect the connection to close soon
					}
					Err(_) => {
						debug!("Server closed connection during termination (expected)")
					}
				}
			}
			Err(e) => {
				debug!("Failed to send terminate_thread (connection may be closed): {e}");
				// Don't treat this as an error - connection might already be closed
			}
		}

		let _ = self.check_pipe_clean("terminate_current_thread");

		// Close file descriptors early to signal clean disconnect to Wine server
		trace!("Closing file descriptors");
		unsafe {
			libc::close(self.request_fd);
			libc::close(self.reply_fd);
		}

		std::thread::sleep(Duration::from_millis(100));

		Ok(())
	}
}

impl Drop for WineClient {
	fn drop(&mut self) {
		debug!("Cleaning up Wine client connection");
		// Send proper termination request to avoid SIGQUIT from Wine server
		let _ = self.terminate_current_thread();
		trace!("Wine client cleanup complete");
	}
}

/// Allocate memory in a Wine process identified by PID
pub fn allocate_in_wine_process(client: &mut WineClient, pid: u32, size: u64) -> io::Result<u64> {
	let wine_pid = client.linux_pid_to_wine_pid(pid)?;
	let process_handle = client.open_process(wine_pid, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)?;

	let (addr, _size) = client.virtual_alloc_ex(process_handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)?;

	Ok(addr)
}
