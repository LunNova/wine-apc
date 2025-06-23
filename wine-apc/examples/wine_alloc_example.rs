// SPDX-FileCopyrightText: 2025 LunNova
//
// SPDX-License-Identifier: CC0-1.0

use std::env;
use std::process;

use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use wine_apc::allocate_in_wine_process;

fn main() -> Result<()> {
	// Initialize tracing subscriber for console logging
	tracing_subscriber::registry()
		.with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "wine_apc=debug,wine_alloc_example=info".into()))
		.with(tracing_subscriber::fmt::layer())
		.init();
	let args: Vec<String> = env::args().collect();

	if args.len() != 3 {
		error!("Usage: {} <wine_process_pid> <allocation_size>", args[0]);
		error!("Example: {} 1234 4096", args[0]);
		process::exit(1);
	}

	let pid: u32 = args[1].parse().unwrap_or_else(|_| {
		error!("Invalid PID '{}'", args[1]);
		process::exit(1);
	});

	let size: u64 = args[2].parse().unwrap_or_else(|_| {
		error!("Invalid size '{}'", args[2]);
		process::exit(1);
	});

	info!("Attempting to allocate {} bytes in Wine process with Linux PID {}", size, pid);

	let mut client = wine_apc::WineClient::connect_to_wine_process(pid)?;

	let addr = allocate_in_wine_process(&mut client, pid, size)?;
	info!("Allocated {size} bytes at address 0x{addr:016x} in target process");

	drop(client);

	Ok(())
}

/*
Example usage:

1. Start a Wine process (e.g., notepad.exe):
   $ wine notepad.exe &

2. Find the PID:
   $ pgrep -f notepad.exe
   12345

3. Allocate memory in that process:
   $ cargo run --example wine_alloc_example 12345 4096
   Attempting to allocate 4096 bytes in Wine process PID 12345
   Allocated 4096 bytes at address 0x0000000140000000

This demonstrates external VirtualAllocEx functionality without linking to Wine libraries.
*/
