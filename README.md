<!--
SPDX-FileCopyrightText: 2025 LunNova

SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-License-Identifier: LGPL-2.1-or-later
-->

# wine-apc

wine-apc is a client library for wine's client-server protocol used to communicate with wineserver.

wine-apc is currently a **proof of concept**[^1] which can run APC_VIRTUAL_ALLOC to allocate memory in a targeted wine process. wine-apc works in target_os=Linux rust programs and does not link against any wine libraries.

The API has had no thought put into its design and will be reworked if this project is ever fleshed out. The NtWaitForSingleObject/select implementation is broken and the example relies on sleeping to wait for an APC to complete which is fragile.

## But why?
I want to interact with a wine process via a Win32 API.

winelib[^2] and rust don't mix; so I can't write a rust target_os Linux program which can call (wine) windows APIs in the vaguely supported way.  
One option is to write a target_os=windows program intended to be ran on Linux via wine, but we lose the ability to call any Linux APIs.

## Wineserver Protocol Info

See [wine-REQ-list](./wine-REQ-list.md) for (some) protocol defs and values.

parse_strace.py can get wine request data from an strace log which contains exchanges with a wineserver and show samples of each observed request type.

## Example Output

### wine_alloc_example

```sh
 INFO wine_alloc_example: Attempting to allocate 4096 bytes in Wine process with Linux PID 1750089
DEBUG wine_apc_rs: Connecting to socket: "/tmp/.wine-1000/server-1f-3b133ec/socket"
DEBUG wine_apc_rs: Enabling SO_PASSCRED
DEBUG wine_apc_rs: Performing Wine handshake
DEBUG wine_apc_rs: Received request fd: 4
DEBUG wine_apc_rs: Starting init_first_thread_with_fds - reply_fd: 6, wait_fd: 8
DEBUG wine_apc_rs: Sending FDs to Wine server
DEBUG wine_apc_rs: Sending init_first_thread request
DEBUG wine_apc_rs: Reading init_first_thread reply
 INFO wine_apc_rs: Wine client initialization complete
DEBUG wine_apc_rs: Found 25 Wine processes
DEBUG wine_apc_rs: Found target! Linux PID 1750089 -> Wine PID 4496
DEBUG wine_apc_rs: open_process reply handle: 0x4
DEBUG wine_apc_rs: Queueing APC wine_apc_rs::protocol::VirtualAllocCall
 INFO wine_alloc_example: Allocated 4096 bytes at address 0x0000000001940000 in target process
DEBUG wine_apc_rs: Cleaning up Wine client connection
DEBUG wine_apc_rs: Server acknowledged thread termination (self=1)
```

[^1]: You should not depend on it, it's probably pretty broken.

[^2]: "Winelib is a development toolkit which allows you to compile your Windows applications on Unix. Most of Winelib code consists of the Win32 API implementation. Fortunately this part is 100 percent shared with Wine. The remainder consists of Windows compatible headers and tools like the resource compiler (and even these are used when compiling Wine)." - [winelib-guide](https://fossies.org/linux/misc/old/winelib-guide.html)