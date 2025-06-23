// SPDX-FileCopyrightText: 2025 LunNova
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wine server protocol structures and constants

use std::mem::{offset_of, size_of};

// Type aliases for Wine protocol types
pub type ClientPtr = u64; // client_ptr_t
pub type DataSize = u32; // data_size_t
pub type MemSize = u64; // mem_size_t
pub type Timeout = u64; // timeout_t
pub type ApcParam = u64; // apc_param_t
pub type ObjHandle = u32; // obj_handle_t
pub type ProcessId = u32; // process_id_t
pub type ThreadId = u32; // thread_id_t
pub type FilePos = u64; // file_pos_t
pub type AbsTime = u64; // abstime_t
pub type Affinity = u64; // affinity_t

// Static asserts for basic Wine protocol types
const _: () = {
	// Basic type size assertions from Wine's C_ASSERT declarations
	assert!(size_of::<AbsTime>() == 8); // abstime_t
	assert!(size_of::<Affinity>() == 8); // affinity_t
	assert!(size_of::<ApcParam>() == 8); // apc_param_t
	assert!(size_of::<ClientPtr>() == 8); // client_ptr_t
	assert!(size_of::<DataSize>() == 4); // data_size_t
	assert!(size_of::<FilePos>() == 8); // file_pos_t
	assert!(size_of::<i32>() == 4); // int
	assert!(size_of::<MemSize>() == 8); // mem_size_t
	assert!(size_of::<ObjHandle>() == 4); // obj_handle_t
	assert!(size_of::<ProcessId>() == 4); // process_id_t
	assert!(size_of::<ThreadId>() == 4); // thread_id_t
	assert!(size_of::<Timeout>() == 8); // timeout_t
	assert!(size_of::<u32>() == 4); // unsigned int
};

// Request type constants from Wine's server_protocol.h
pub const REQ_INIT_PROCESS_DONE: i32 = 4;
pub const REQ_INIT_FIRST_THREAD: i32 = 5;
pub const REQ_TERMINATE_THREAD: i32 = 8;
pub const REQ_LIST_PROCESSES: i32 = 76;
pub const REQ_QUEUE_APC: i32 = 19;
pub const REQ_GET_APC_RESULT: i32 = 20;
pub const REQ_OPEN_PROCESS: i32 = 27;
pub const REQ_SELECT: i32 = 29;

// Protocol version from Wine's server_protocol.h
pub const SERVER_PROTOCOL_VERSION: u32 = 872;

// Wine's server protocol requires ALL requests to be exactly this size
// due to union generic_request being sized by request_max_size (16 * 4 = 64 bytes)
pub const WINE_REQUEST_SIZE: usize = 64;

// APC type constants
pub const APC_VIRTUAL_ALLOC: u32 = 3;

// Memory allocation constants
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const PAGE_READWRITE: u32 = 0x04;

// Process access rights
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;

// Common header structures
#[repr(C)]
pub struct RequestHeader {
	pub req: i32,          // request type
	pub request_size: u32, // size of request data (excluding header)
	pub reply_size: u32,   // expected size of reply data (excluding header)
}

#[repr(C)]
pub struct ReplyHeader {
	pub error: u32,      // NTSTATUS error code
	pub reply_size: u32, // size of reply data (can be larger than expected)
}

// Request/Reply pairs
#[repr(C)]
pub struct OpenProcessRequest {
	pub header: RequestHeader,
	pub pid: ProcessId,  // process_id_t
	pub access: u32,     // access rights
	pub attributes: u32, // object attributes
}

#[repr(C)]
pub struct OpenProcessReply {
	pub header: ReplyHeader,
	pub handle: ObjHandle, // obj_handle_t for process
}

#[repr(C)]
pub struct VirtualAllocCall {
	pub apc_type: u32,      // APC_VIRTUAL_ALLOC
	pub op_type: u32,       // MEM_COMMIT | MEM_RESERVE
	pub addr: ClientPtr,    // client_ptr_t - requested address
	pub size: MemSize,      // mem_size_t - allocation size
	pub zero_bits: MemSize, // mem_size_t - address constraints
	pub prot: u32,          // protection flags
	                        // Note: This struct should be 36 bytes + 4 bytes padding = 40 bytes total
}

#[repr(C)]
pub struct VirtualAllocResult {
	pub apc_type: u32,   // APC_VIRTUAL_ALLOC
	pub status: u32,     // NTSTATUS
	pub addr: ClientPtr, // client_ptr_t - resulting address
	pub size: MemSize,   // mem_size_t - resulting size
}

#[repr(C)]
pub struct GetApcResultReply {
	pub header: ReplyHeader,
	pub result: VirtualAllocResult,
}

#[repr(C, packed)]
pub struct InitFirstThreadRequest {
	pub header: RequestHeader,
	pub unix_pid: i32,
	pub unix_tid: i32,
	pub debug_level: i32,
	pub reply_fd: i32,
	pub wait_fd: i32,
}

#[repr(C)]
pub struct InitFirstThreadReply {
	pub header: ReplyHeader,
	pub pid: ProcessId,        // process_id_t
	pub tid: ThreadId,         // thread_id_t
	pub server_start: Timeout, // timeout_t
	pub session_id: u32,
	pub info_size: DataSize, // data_size_t
}

#[repr(C)]
pub struct InitProcessDoneRequest {
	pub header: RequestHeader,
	pub _pad: [u8; 4],       // char __pad_12[4]
	pub teb: ClientPtr,      // client_ptr_t
	pub peb: ClientPtr,      // client_ptr_t
	pub ldt_copy: ClientPtr, // client_ptr_t
}

#[repr(C)]
pub struct InitProcessDoneReply {
	pub header: ReplyHeader,
	pub suspend: i32,  // int
	pub _pad: [u8; 4], // char __pad_12[4]
}

#[repr(C)]
pub struct ListProcessesRequest {
	pub header: RequestHeader,
	pub _pad: [u8; 4], // char __pad_12[4]
}

#[repr(C)]
pub struct ListProcessesReply {
	pub header: ReplyHeader,
	pub info_size: DataSize,      // data_size_t - size of process info array
	pub process_count: i32,       // int - number of processes
	pub total_thread_count: i32,  // int - total number of threads
	pub total_name_len: DataSize, // data_size_t - total length of process names
}

#[repr(C)]
pub struct ProcessInfo {
	pub start_time: Timeout,   // timeout_t
	pub name_len: DataSize,    // data_size_t
	pub thread_count: u32,     // int
	pub priority: i32,         // int
	pub pid: ProcessId,        // process_id_t - Wine process ID
	pub parent_pid: ProcessId, // process_id_t
	pub session_id: u32,       // unsigned int
	pub handle_count: u32,     // unsigned int
	pub unix_pid: i32,         // int - Linux process ID
}

#[repr(C)]
pub struct ThreadInfo {
	pub start_time: Timeout,    // timeout_t
	pub tid: ThreadId,          // thread_id_t
	pub base_priority: i32,     // int
	pub current_priority: i32,  // int
	pub unix_tid: i32,          // int
	pub entry_point: ClientPtr, // client_ptr_t
	pub teb: ClientPtr,         // client_ptr_t
}

#[repr(C)]
pub struct QueueApcRequest {
	pub header: RequestHeader,
	pub handle: ObjHandle, // obj_handle_t for process
}

#[repr(C)]
pub struct QueueApcReply {
	pub header: ReplyHeader,
	pub handle: ObjHandle, // obj_handle_t for APC
	pub self_exec: i32,    // boolean - execute in caller
}

#[repr(C)]
pub struct GetApcResultRequest {
	pub header: RequestHeader,
	pub handle: ObjHandle, // obj_handle_t for APC
}

#[repr(C)]
pub struct TerminateThreadRequest {
	pub header: RequestHeader,
	pub handle: ObjHandle, // obj_handle_t for thread
	pub exit_code: i32,    // thread exit code
	pub _pad: [u8; 4],     // padding to reach 24 bytes
}

#[repr(C)]
pub struct TerminateThreadReply {
	pub header: ReplyHeader,
	pub self_: i32,    // 1 if terminating current thread
	pub _pad: [u8; 4], // char __pad_12[4]
}

#[repr(C)]
pub struct SelectRequest {
	pub header: RequestHeader,
	pub flags: i32,        // select flags
	pub cookie: ClientPtr, // client_ptr_t - user cookie
	pub timeout: AbsTime,  // abstime_t - absolute timeout
	pub size: DataSize,    // data_size_t - size of select operations
	pub prev_apc: ObjHandle, // obj_handle_t - previous APC handle
	                       // VARARG data follows: apc_result, select_op, contexts
}

#[repr(C)]
pub struct SelectReply {
	pub header: ReplyHeader,
	pub apc_handle: ObjHandle, // obj_handle_t - APC handle if signaled
	pub signaled: i32,         // signaled object index
	                           // VARARG data follows: apc_call, contexts
}

// Select operation constants
pub const SELECT_ALERTABLE: i32 = 1;
pub const SELECT_INTERRUPTIBLE: i32 = 2;

// Static asserts for struct sizes based on Wine's C_ASSERT declarations
const _: () = {
	// From wine-REQ-list.md - basic struct sizes
	assert!(size_of::<ProcessInfo>() == 40); // C_ASSERT( sizeof(struct process_info) == 40 );
	assert!(size_of::<ThreadInfo>() == 40); // C_ASSERT( sizeof(struct thread_info) == 40 );

	// union apc_call should be 64 bytes (includes VirtualAllocCall as a variant)
	// C_ASSERT( sizeof(union apc_call) == 64 );
	// Our VirtualAllocCall is 40 bytes, which matches the virtual_alloc variant size

	// union apc_result should be 40 bytes (includes VirtualAllocResult as a variant)
	// C_ASSERT( sizeof(union apc_result) == 40 );
	// Our VirtualAllocResult is 24 bytes, which matches the virtual_alloc variant size

	// InitProcessDone request/reply sizes and offsets from wine-REQ-list.md
	assert!(size_of::<InitProcessDoneRequest>() == 40); // C_ASSERT( sizeof(struct init_process_done_request) == 40 );
	assert!(offset_of!(InitProcessDoneRequest, teb) == 16); // C_ASSERT( offsetof(struct init_process_done_request, teb) == 16 );
	assert!(offset_of!(InitProcessDoneRequest, peb) == 24); // C_ASSERT( offsetof(struct init_process_done_request, peb) == 24 );
	assert!(offset_of!(InitProcessDoneRequest, ldt_copy) == 32); // C_ASSERT( offsetof(struct init_process_done_request, ldt_copy) == 32 );
	assert!(size_of::<InitProcessDoneReply>() == 16); // C_ASSERT( sizeof(struct init_process_done_reply) == 16 );
	assert!(offset_of!(InitProcessDoneReply, suspend) == 8); // C_ASSERT( offsetof(struct init_process_done_reply, suspend) == 8 );

	// InitFirstThread request/reply sizes and offsets from wine-REQ-list.md
	assert!(size_of::<InitFirstThreadRequest>() == 32); // C_ASSERT( sizeof(struct init_first_thread_request) == 32 );
	assert!(offset_of!(InitFirstThreadRequest, unix_pid) == 12); // C_ASSERT( offsetof(struct init_first_thread_request, unix_pid) == 12 );
	assert!(offset_of!(InitFirstThreadRequest, unix_tid) == 16); // C_ASSERT( offsetof(struct init_first_thread_request, unix_tid) == 16 );
	assert!(offset_of!(InitFirstThreadRequest, debug_level) == 20); // C_ASSERT( offsetof(struct init_first_thread_request, debug_level) == 20 );
	assert!(offset_of!(InitFirstThreadRequest, reply_fd) == 24); // C_ASSERT( offsetof(struct init_first_thread_request, reply_fd) == 24 );
	assert!(offset_of!(InitFirstThreadRequest, wait_fd) == 28); // C_ASSERT( offsetof(struct init_first_thread_request, wait_fd) == 28 );
	assert!(size_of::<InitFirstThreadReply>() == 32); // C_ASSERT( sizeof(struct init_first_thread_reply) == 32 );
	assert!(offset_of!(InitFirstThreadReply, pid) == 8); // C_ASSERT( offsetof(struct init_first_thread_reply, pid) == 8 );
	assert!(offset_of!(InitFirstThreadReply, tid) == 12); // C_ASSERT( offsetof(struct init_first_thread_reply, tid) == 12 );
	assert!(offset_of!(InitFirstThreadReply, server_start) == 16); // C_ASSERT( offsetof(struct init_first_thread_reply, server_start) == 16 );
	assert!(offset_of!(InitFirstThreadReply, session_id) == 24); // C_ASSERT( offsetof(struct init_first_thread_reply, session_id) == 24 );
	assert!(offset_of!(InitFirstThreadReply, info_size) == 28); // C_ASSERT( offsetof(struct init_first_thread_reply, info_size) == 28 );

	// ListProcesses request/reply sizes and offsets from wine-REQ-list.md
	assert!(size_of::<ListProcessesRequest>() == 16); // C_ASSERT( sizeof(struct list_processes_request) == 16 );
	assert!(size_of::<ListProcessesReply>() == 24); // C_ASSERT( sizeof(struct list_processes_reply) == 24 );
	assert!(offset_of!(ListProcessesReply, info_size) == 8); // C_ASSERT( offsetof(struct list_processes_reply, info_size) == 8 );
	assert!(offset_of!(ListProcessesReply, process_count) == 12); // C_ASSERT( offsetof(struct list_processes_reply, process_count) == 12 );
	assert!(offset_of!(ListProcessesReply, total_thread_count) == 16); // C_ASSERT( offsetof(struct list_processes_reply, total_thread_count) == 16 );
	assert!(offset_of!(ListProcessesReply, total_name_len) == 20); // C_ASSERT( offsetof(struct list_processes_reply, total_name_len) == 20 );

	// TerminateThread request/reply sizes and offsets from wine-REQ-list.md
	assert!(size_of::<TerminateThreadRequest>() == 24); // C_ASSERT( sizeof(struct terminate_thread_request) == 24 );
	assert!(offset_of!(TerminateThreadRequest, handle) == 12); // C_ASSERT( offsetof(struct terminate_thread_request, handle) == 12 );
	assert!(offset_of!(TerminateThreadRequest, exit_code) == 16); // C_ASSERT( offsetof(struct terminate_thread_request, exit_code) == 16 );
	assert!(size_of::<TerminateThreadReply>() == 16); // C_ASSERT( sizeof(struct terminate_thread_reply) == 16 );
	assert!(offset_of!(TerminateThreadReply, self_) == 8); // C_ASSERT( offsetof(struct terminate_thread_reply, self) == 8 );
};
