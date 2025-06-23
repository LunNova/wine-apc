// SPDX-FileCopyrightText: 2025 LunNova
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(target_os = "windows")]
mod win {
	use anyhow::{Context, Result, anyhow, bail};
	use std::mem;
	use std::ptr;
	use winapi::ctypes::c_void;
	use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID, ULONG};
	use winapi::shared::ntstatus::{STATUS_ACCESS_DENIED, STATUS_SUCCESS};
	use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE};

	// NT API function declarations
	extern "system" {
		fn NtOpenProcess(
			process_handle: *mut HANDLE,
			desired_access: ULONG,
			object_attributes: *const OBJECT_ATTRIBUTES,
			client_id: *const CLIENT_ID,
		) -> NTSTATUS;

		fn NtAllocateVirtualMemory(
			process_handle: HANDLE,
			base_address: *mut PVOID,
			zero_bits: ULONG,
			region_size: *mut usize,
			allocation_type: ULONG,
			protect: ULONG,
		) -> NTSTATUS;

		fn NtClose(handle: HANDLE) -> NTSTATUS;
	}

	#[repr(C)]
	struct OBJECT_ATTRIBUTES {
		length: ULONG,
		root_directory: HANDLE,
		object_name: *const UNICODE_STRING,
		attributes: ULONG,
		security_descriptor: PVOID,
		security_quality_of_service: PVOID,
	}

	#[repr(C)]
	struct UNICODE_STRING {
		length: u16,
		maximum_length: u16,
		buffer: *mut u16,
	}

	#[repr(C)]
	struct CLIENT_ID {
		unique_process: HANDLE,
		unique_thread: HANDLE,
	}

	/// Converts NTSTATUS to a human-readable error
	fn ntstatus_to_error(status: NTSTATUS, operation: &str) -> anyhow::Error {
		match status {
			STATUS_ACCESS_DENIED => {
				anyhow!(
					"{} failed: Access denied (0x{:08x}). Try running as administrator",
					operation,
					status
				)
			}
			_ => anyhow!("{} failed with NTSTATUS: 0x{:08x}", operation, status),
		}
	}

	/// Opens a process handle using NT API
	fn open_process(pid: u32) -> Result<HANDLE> {
		let mut process_handle: HANDLE = ptr::null_mut();
		let client_id = CLIENT_ID {
			unique_process: pid as *mut c_void,
			unique_thread: ptr::null_mut(),
		};

		let object_attributes = OBJECT_ATTRIBUTES {
			length: mem::size_of::<OBJECT_ATTRIBUTES>() as ULONG,
			root_directory: ptr::null_mut(),
			object_name: ptr::null(),
			attributes: 0,
			security_descriptor: ptr::null_mut(),
			security_quality_of_service: ptr::null_mut(),
		};

		let status = unsafe {
			NtOpenProcess(
				&mut process_handle,
				PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
				&object_attributes,
				&client_id,
			)
		};

		if status != STATUS_SUCCESS {
			return Err(ntstatus_to_error(status, "NtOpenProcess"));
		}

		Ok(process_handle)
	}

	/// Allocates memory in the target process
	fn allocate_memory(process_handle: HANDLE, size: usize) -> Result<(PVOID, usize)> {
		let mut base_address: PVOID = ptr::null_mut();
		let mut region_size = size;

		let status = unsafe {
			NtAllocateVirtualMemory(
				process_handle,
				&mut base_address,
				0, // zero_bits - let Windows choose the address
				&mut region_size,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE,
			)
		};

		if status != STATUS_SUCCESS {
			return Err(ntstatus_to_error(status, "NtAllocateVirtualMemory"));
		}

		Ok((base_address, region_size))
	}

	/// Auto-closing handle wrapper
	struct AutoHandle(HANDLE);

	impl Drop for AutoHandle {
		fn drop(&mut self) {
			if !self.0.is_null() {
				unsafe {
					NtClose(self.0);
				}
				self.0 = 0;
			}
		}
	}

	impl std::ops::Deref for AutoHandle {
		type Target = HANDLE;
		fn deref(&self) -> &Self::Target {
			&self.0
		}
	}

	pub fn run() -> Result<()> {
		let args: Vec<String> = std::env::args().collect();

		if args.len() != 3 {
			bail!("Usage: {} <target_pid> <allocation_size>\nExample: {} 1234 4096", args[0], args[0]);
		}

		let target_pid: u32 = args[1].parse().with_context(|| format!("Invalid PID '{}'", args[1]))?;

		let size: usize = args[2].parse().with_context(|| format!("Invalid size '{}'", args[2]))?;

		println!("=== Windows NT API VirtualAllocEx Test ===");
		println!("Target PID: {}", target_pid);
		println!("Allocation size: {} bytes", size);
		println!();

		// Step 1: Open the target process using NtOpenProcess
		println!("🔓 Opening target process with NtOpenProcess...");
		let process_handle = open_process(target_pid).with_context(|| format!("Failed to open process {}", target_pid))?;
		let process_handle = AutoHandle(process_handle);
		println!("NtOpenProcess succeeded! Process handle: {:p}", *process_handle);

		// Step 2: Allocate memory using NtAllocateVirtualMemory
		println!("📦 Allocating memory with NtAllocateVirtualMemory...");
		let (base_address, actual_size) = allocate_memory(*process_handle, size).context("Failed to allocate memory in target process")?;

		println!("✅ NtAllocateVirtualMemory succeeded!");
		println!("   Allocated address: {:p}", base_address);
		println!("   Actual size: {} bytes", actual_size);

		// Step 3: Handle is automatically closed by AutoHandle's Drop impl
		println!("🧹 Cleaning up (handle will be closed automatically)...");

		Ok(())
	}
}

fn main() -> anyhow::Result<()> {
	#[cfg(target_os = "windows")]
	{
		win::run()
	}

	#[cfg(not(target_os = "windows"))]
	{
		anyhow::bail!("This example only runs on Windows")
	}
}
