<!--
SPDX-FileCopyrightText: 2025 LunNova

SPDX-License-Identifier: LGPL-2.1-or-later
-->

List of requests.
If a request is an APC, it is ran via queue_apc and get_apc_result and not part of this list.
```
enum request
{
    REQ_new_process                          // 0
    REQ_get_new_process_info                 // 1
    REQ_new_thread                           // 2
    REQ_get_startup_info                     // 3
    REQ_init_process_done                    // 4
    REQ_init_first_thread                    // 5
    REQ_init_thread                          // 6
    REQ_terminate_process                    // 7
    REQ_terminate_thread                     // 8
    REQ_get_process_info                     // 9
    REQ_get_process_debug_info               // 10
    REQ_get_process_image_name               // 11
    REQ_get_process_vm_counters              // 12
    REQ_set_process_info                     // 13
    REQ_get_thread_info                      // 14
    REQ_get_thread_times                     // 15
    REQ_set_thread_info                      // 16
    REQ_suspend_thread                       // 17
    REQ_resume_thread                        // 18
    REQ_queue_apc                            // 19
    REQ_get_apc_result                       // 20
    REQ_close_handle                         // 21
    REQ_set_handle_info                      // 22
    REQ_dup_handle                           // 23
    REQ_allocate_reserve_object              // 24
    REQ_compare_objects                      // Ca
    REQ_set_object_permanence                // 26
    REQ_open_process                         // 27
    REQ_open_thread                          // 28
    REQ_select                               // 29
    REQ_create_event                         // 30
    REQ_event_op                             // 31
    REQ_query_event                          // 32
    REQ_open_event                           // 33
    REQ_create_keyed_event                   // 34
    REQ_open_keyed_event                     // 35
    REQ_create_mutex                         // 36
    REQ_release_mutex                        // 37
    REQ_open_mutex                           // 38
    REQ_query_mutex                          // 39
    REQ_create_semaphore                     // 40
    REQ_release_semaphore                    // 41
    REQ_query_semaphore                      // 42
    REQ_open_semaphore                       // 43
    REQ_create_file                          // 44
    REQ_open_file_object                     // 45
    REQ_alloc_file_handle                    // 46
    REQ_get_handle_unix_name                 // 47
    REQ_get_handle_fd                        // 48
    REQ_get_directory_cache_entry            // 49
    REQ_flush                                // 50
    REQ_get_file_info                        // 51
    REQ_get_volume_info                      // 52
    REQ_lock_file                            // 53
    REQ_unlock_file                          // 54
    REQ_recv_socket                          // 55
    REQ_send_socket                          // 56
    REQ_socket_get_events                    // 57
    REQ_socket_send_icmp_id                  // 58
    REQ_socket_get_icmp_id                   // 59
    REQ_get_next_console_request             // 60
    REQ_read_directory_changes               // 61
    REQ_read_change                          // 62
    REQ_create_mapping                       // 63
    REQ_open_mapping                         // 64
    REQ_get_mapping_info                     // 65
    REQ_get_image_map_address                // 66
    REQ_map_view                             // 67
    REQ_map_image_view                       // 68
    REQ_map_builtin_view                     // 69
    REQ_get_image_view_info                  // 70
    REQ_unmap_view                           // 71
    REQ_get_mapping_committed_range          // 72
    REQ_add_mapping_committed_range          // 73
    REQ_is_same_mapping                      // 74
    REQ_get_mapping_filename                 // 75
    REQ_list_processes                       // 76
    REQ_create_debug_obj                     // 77
    REQ_wait_debug_event                     // 78
    REQ_queue_exception_event                // 79
    REQ_get_exception_status                 // 80
    REQ_continue_debug_event                 // 81
    REQ_debug_process                        // 82
    REQ_set_debug_obj_info                   // 83
    REQ_read_process_memory                  // 84
    REQ_write_process_memory                 // 85
    REQ_create_key                           // 86
    REQ_open_key                             // 87
    REQ_delete_key                           // 88
    REQ_flush_key                            // 89
    REQ_enum_key                             // 90
    REQ_set_key_value                        // 91
    REQ_get_key_value                        // 92
    REQ_enum_key_value                       // 93
    REQ_delete_key_value                     // 94
    REQ_load_registry                        // 95
    REQ_unload_registry                      // 96
    REQ_save_registry                        // 97
    REQ_set_registry_notification            // 98
    REQ_rename_key                           // 99
    REQ_create_timer                         // 100
    REQ_open_timer                           // 101
    REQ_set_timer                            // 102
    REQ_cancel_timer                         // 103
    REQ_get_timer_info                       // 104
    REQ_get_thread_context                   // 105
    REQ_set_thread_context                   // 106
    REQ_get_selector_entry                   // 107
    REQ_add_atom                             // 108
    REQ_delete_atom                          // 109
    REQ_find_atom                            // 110
    REQ_get_atom_information                 // 111
    REQ_get_msg_queue_handle                 // 112
    REQ_get_msg_queue                        // 113
    REQ_set_queue_fd                         // 114
    REQ_set_queue_mask                       // 115
    REQ_get_queue_status                     // 116
    REQ_get_process_idle_event               // 117
    REQ_send_message                         // 118
    REQ_post_quit_message                    // 119
    REQ_send_hardware_message                // 120
    REQ_get_message                          // 121
    REQ_reply_message                        // 122
    REQ_accept_hardware_message              // 123
    REQ_get_message_reply                    // 124
    REQ_set_win_timer                        // 125
    REQ_kill_win_timer                       // 126
    REQ_is_window_hung                       // 127
    REQ_get_serial_info                      // 128
    REQ_set_serial_info                      // 129
    REQ_cancel_sync                          // 130
    REQ_register_async                       // 131
    REQ_cancel_async                         // 132
    REQ_get_async_result                     // 133
    REQ_set_async_direct_result              // 134
    REQ_read                                 // 135
    REQ_write                                // 136
    REQ_ioctl                                // 137
    REQ_set_irp_result                       // 138
    REQ_create_named_pipe                    // 139
    REQ_set_named_pipe_info                  // 140
    REQ_create_window                        // 141
    REQ_destroy_window                       // 142
    REQ_get_desktop_window                   // 143
    REQ_set_window_owner                     // 144
    REQ_get_window_info                      // 145
    REQ_init_window_info                     // 146
    REQ_set_window_info                      // 147
    REQ_set_parent                           // 148
    REQ_get_window_parents                   // 149
    REQ_get_window_list                      // 150
    REQ_get_class_windows                    // 151
    REQ_get_window_children_from_point       // 152
    REQ_get_window_tree                      // 153
    REQ_set_window_pos                       // 154
    REQ_get_window_rectangles                // 155
    REQ_get_window_text                      // 156
    REQ_set_window_text                      // 157
    REQ_get_windows_offset                   // 158
    REQ_get_visible_region                   // 159
    REQ_get_window_region                    // 160
    REQ_set_window_region                    // 161
    REQ_get_update_region                    // 162
    REQ_update_window_zorder                 // 163
    REQ_redraw_window                        // 164
    REQ_set_window_property                  // 165
    REQ_remove_window_property               // 166
    REQ_get_window_property                  // 167
    REQ_get_window_properties                // 168
    REQ_create_winstation                    // 169
    REQ_open_winstation                      // 170
    REQ_close_winstation                     // 171
    REQ_set_winstation_monitors              // 172
    REQ_get_process_winstation               // 173
    REQ_set_process_winstation               // 174
    REQ_enum_winstation                      // 175
    REQ_create_desktop                       // 176
    REQ_open_desktop                         // 177
    REQ_open_input_desktop                   // 178
    REQ_set_input_desktop                    // 179
    REQ_close_desktop                        // 180
    REQ_get_thread_desktop                   // 181
    REQ_set_thread_desktop                   // 182
    REQ_set_user_object_info                 // 183
    REQ_register_hotkey                      // 184
    REQ_unregister_hotkey                    // 185
    REQ_attach_thread_input                  // 186
    REQ_get_thread_input                     // 187
    REQ_get_last_input_time                  // 188
    REQ_get_key_state                        // 189
    REQ_set_key_state                        // 190
    REQ_set_foreground_window                // 191
    REQ_set_focus_window                     // 192
    REQ_set_active_window                    // 193
    REQ_set_capture_window                   // 194
    REQ_set_caret_window                     // 195
    REQ_set_caret_info                       // 196
    REQ_set_hook                             // 197
    REQ_remove_hook                          // 198
    REQ_start_hook_chain                     // 199
    REQ_finish_hook_chain                    // 200
    REQ_get_hook_info                        // 201
    REQ_create_class                         // 202
    REQ_destroy_class                        // 203
    REQ_set_class_info                       // 204
    REQ_open_clipboard                       // 205
    REQ_close_clipboard                      // 206
    REQ_empty_clipboard                      // 207
    REQ_set_clipboard_data                   // 208
    REQ_get_clipboard_data                   // 209
    REQ_get_clipboard_formats                // 210
    REQ_enum_clipboard_formats               // 211
    REQ_release_clipboard                    // 212
    REQ_get_clipboard_info                   // 213
    REQ_set_clipboard_viewer                 // 214
    REQ_add_clipboard_listener               // 215
    REQ_remove_clipboard_listener            // 216
    REQ_create_token                         // 217
    REQ_open_token                           // 218
    REQ_set_desktop_shell_windows            // 219
    REQ_adjust_token_privileges              // 220
    REQ_get_token_privileges                 // 221
    REQ_check_token_privileges               // 222
    REQ_duplicate_token                      // 223
    REQ_filter_token                         // 224
    REQ_access_check                         // 225
    REQ_get_token_sid                        // 226
    REQ_get_token_groups                     // 227
    REQ_get_token_default_dacl               // 228
    REQ_set_token_default_dacl               // 229
    REQ_set_security_object                  // 230
    REQ_get_security_object                  // 231
    REQ_get_system_handles                   // 232
    REQ_get_tcp_connections                  // 233
    REQ_get_udp_endpoints                    // 234
    REQ_create_mailslot                      // 235
    REQ_set_mailslot_info                    // 236
    REQ_create_directory                     // 237
    REQ_open_directory                       // 238
    REQ_get_directory_entries                // 239
    REQ_create_symlink                       // 240
    REQ_open_symlink                         // 241
    REQ_query_symlink                        // 242
    REQ_get_object_info                      // 243
    REQ_get_object_name                      // 244
    REQ_get_object_type                      // 245
    REQ_get_object_types                     // 246
    REQ_allocate_locally_unique_id           // 247
    REQ_create_device_manager                // 248
    REQ_create_device                        // 249
    REQ_delete_device                        // 250
    REQ_get_next_device_request              // 251
    REQ_get_kernel_object_ptr                // 252
    REQ_set_kernel_object_ptr                // 253
    REQ_grab_kernel_object                   // 254
    REQ_release_kernel_object                // 255
    REQ_get_kernel_object_handle             // 256
    REQ_make_process_system                  // 257
    REQ_grant_process_admin_token            // 258
    REQ_get_token_info                       // 259
    REQ_create_linked_token                  // 260
    REQ_create_completion                    // 261
    REQ_open_completion                      // 262
    REQ_add_completion                       // 263
    REQ_remove_completion                    // 264
    REQ_get_thread_completion                // 265
    REQ_query_completion                     // 266
    REQ_set_completion_info                  // 267
    REQ_add_fd_completion                    // 268
    REQ_set_fd_completion_mode               // 269
    REQ_set_fd_disp_info                     // 270
    REQ_set_fd_name_info                     // 271
    REQ_set_fd_eof_info                      // 272
    REQ_get_window_layered_info              // 273
    REQ_set_window_layered_info              // 274
    REQ_alloc_user_handle                    // 275
    REQ_free_user_handle                     // 276
    REQ_set_cursor                           // 277
    REQ_get_cursor_history                   // 278
    REQ_get_rawinput_buffer                  // 279
    REQ_update_rawinput_devices              // 280
    REQ_create_job                           // 281
    REQ_open_job                             // 282
    REQ_assign_job                           // 283
    REQ_process_in_job                       // 284
    REQ_set_job_limits                       // 285
    REQ_set_job_completion_port              // 286
    REQ_get_job_info                         // 287
    REQ_terminate_job                        // 288
    REQ_suspend_process                      // 289
    REQ_resume_process                       // 290
    REQ_get_next_process                     // 291
    REQ_get_next_thread                      // 292
    REQ_set_keyboard_repeat                  // 293
    REQ_NB_REQUESTS                          // 294
};
```

APC call numeric IDs:
```
enum apc_type
{
    APC_NONE = 0,
    APC_USER = 1,
    APC_ASYNC_IO = 2,
    APC_VIRTUAL_ALLOC = 3,
    APC_VIRTUAL_ALLOC_EX = 4,
    APC_VIRTUAL_FREE = 5,
    APC_VIRTUAL_QUERY = 6,
    APC_VIRTUAL_PROTECT = 7,
    APC_VIRTUAL_FLUSH = 8,
    APC_VIRTUAL_LOCK = 9,
    APC_VIRTUAL_UNLOCK = 10,
    APC_MAP_VIEW = 11,
    APC_MAP_VIEW_EX = 12,
    APC_UNMAP_VIEW = 13,
    APC_CREATE_THREAD = 14,
    APC_DUP_HANDLE = 15,
};
```

Request structs: (include/wine/server_protocol.h)
```
struct init_process_done_request
{
    struct request_header __header;
    char __pad_12[4];
    client_ptr_t teb;
    client_ptr_t peb;
    client_ptr_t ldt_copy;
};
struct init_process_done_reply
{
    struct reply_header __header;
    int          suspend;
    char __pad_12[4];
};



struct init_first_thread_request
{
    struct request_header __header;
    int          unix_pid;
    int          unix_tid;
    int          debug_level;
    int          reply_fd;
    int          wait_fd;
};
struct init_first_thread_reply
{
    struct reply_header __header;
    process_id_t pid;
    thread_id_t  tid;
    timeout_t    server_start;
    unsigned int session_id;
    data_size_t  info_size;
    /* VARARG(machines,ushorts); */
};


struct list_processes_request
{
    struct request_header __header;
    char __pad_12[4];
};
struct list_processes_reply
{
    struct reply_header __header;
    data_size_t     info_size;
    int             process_count;
    int             total_thread_count;
    data_size_t     total_name_len;
    /* VARARG(data,process_info,info_size); */
};
```

APC call definitions:
```
struct user_apc
{
    enum apc_type    type;     /* APC_USER */
    int              __pad;
    client_ptr_t     func;     /* void (__stdcall *func)(ULONG_PTR,ULONG_PTR,ULONG_PTR); */
    apc_param_t      args[3];  /* arguments for user function */
};

union apc_call
{
    enum apc_type type;
    struct user_apc user;
    struct
    {
        enum apc_type    type;     /* APC_ASYNC_IO */
        unsigned int     status;   /* I/O status */
        client_ptr_t     user;     /* user pointer */
        client_ptr_t     sb;       /* status block */
        data_size_t      result;   /* result size */
    } async_io;
    struct
    {
        enum apc_type    type;         /* APC_VIRTUAL_ALLOC */
        unsigned int     op_type;      /* type of operation */
        client_ptr_t     addr;         /* requested address */
        mem_size_t       size;         /* allocation size */
        mem_size_t       zero_bits;    /* number of zero high bits */
        unsigned int     prot;         /* memory protection flags */
    } virtual_alloc;
    struct
    {
        enum apc_type    type;         /* APC_VIRTUAL_ALLOC */
        unsigned int     op_type;      /* type of operation */
        client_ptr_t     addr;         /* requested address */
        mem_size_t       size;         /* allocation size */
        mem_size_t       limit_low;    /* allocation address limits */
        mem_size_t       limit_high;
        mem_size_t       align;        /* allocation alignment */
        unsigned int     prot;         /* memory protection flags */
        unsigned int     attributes;   /* memory extended attributes */
    } virtual_alloc_ex;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_FREE */
        unsigned int     op_type;   /* type of operation */
        client_ptr_t     addr;      /* requested address */
        mem_size_t       size;      /* allocation size */
    } virtual_free;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_QUERY */
        int              __pad;
        client_ptr_t     addr;      /* requested address */
    } virtual_query;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_PROTECT */
        unsigned int     prot;      /* new protection flags */
        client_ptr_t     addr;      /* requested address */
        mem_size_t       size;      /* requested size */
    } virtual_protect;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_FLUSH */
        int              __pad;
        client_ptr_t     addr;      /* requested address */
        mem_size_t       size;      /* requested size */
    } virtual_flush;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_LOCK */
        int              __pad;
        client_ptr_t     addr;      /* requested address */
        mem_size_t       size;      /* requested size */
    } virtual_lock;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_UNLOCK */
        int              __pad;
        client_ptr_t     addr;      /* requested address */
        mem_size_t       size;      /* requested size */
    } virtual_unlock;
    struct
    {
        enum apc_type    type;         /* APC_MAP_VIEW */
        obj_handle_t     handle;       /* mapping handle */
        client_ptr_t     addr;         /* requested address */
        mem_size_t       size;         /* allocation size */
        file_pos_t       offset;       /* file offset */
        mem_size_t       zero_bits;    /* number of zero high bits */
        unsigned int     alloc_type;   /* allocation type */
        unsigned int     prot;         /* memory protection flags */
    } map_view;
    struct
    {
        enum apc_type    type;         /* APC_MAP_VIEW_EX */
        obj_handle_t     handle;       /* mapping handle */
        client_ptr_t     addr;         /* requested address */
        mem_size_t       size;         /* allocation size */
        file_pos_t       offset;       /* file offset */
        mem_size_t       limit_low;    /* allocation address limits */
        mem_size_t       limit_high;
        unsigned int     alloc_type;   /* allocation type */
        unsigned int     prot;         /* memory protection flags */
        unsigned short   machine;      /* requested machine for image mappings */
        unsigned short   __pad[3];
    } map_view_ex;
    struct
    {
        enum apc_type    type;      /* APC_UNMAP_VIEW */
        unsigned int     flags;     /* unmap flags */
        client_ptr_t     addr;      /* view address */
    } unmap_view;
    struct
    {
        enum apc_type    type;      /* APC_CREATE_THREAD */
        unsigned int     flags;     /* creation flags */
        client_ptr_t     func;      /* void (__stdcall *func)(void*);  start function */
        client_ptr_t     arg;       /* argument for start function */
        mem_size_t       zero_bits; /* number of zero high bits for thread stack */
        mem_size_t       reserve;   /* reserve size for thread stack */
        mem_size_t       commit;    /* commit size for thread stack */
    } create_thread;
    struct
    {
        enum apc_type    type;         /* APC_DUP_HANDLE */
        obj_handle_t     src_handle;   /* src handle to duplicate */
        obj_handle_t     dst_process;  /* dst process handle */
        unsigned int     access;       /* wanted access rights */
        unsigned int     attributes;   /* object attributes */
        unsigned int     options;      /* duplicate options */
    } dup_handle;
};

union apc_result
{
    enum apc_type type;
    struct
    {
        enum apc_type    type;      /* APC_ASYNC_IO */
        unsigned int     status;    /* new status of async operation */
        unsigned int     total;     /* bytes transferred */
    } async_io;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_ALLOC */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
    } virtual_alloc;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_ALLOC_EX */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
    } virtual_alloc_ex;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_FREE */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
    } virtual_free;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_QUERY */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     base;      /* resulting base address */
        client_ptr_t     alloc_base;/* resulting allocation base */
        mem_size_t       size;      /* resulting region size */
        unsigned short   state;     /* resulting region state */
        unsigned short   prot;      /* resulting region protection */
        unsigned short   alloc_prot;/* resulting allocation protection */
        unsigned short   alloc_type;/* resulting region allocation type */
    } virtual_query;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_PROTECT */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
        unsigned int     prot;      /* old protection flags */
    } virtual_protect;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_FLUSH */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
    } virtual_flush;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_LOCK */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
    } virtual_lock;
    struct
    {
        enum apc_type    type;      /* APC_VIRTUAL_UNLOCK */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
    } virtual_unlock;
    struct
    {
        enum apc_type    type;      /* APC_MAP_VIEW */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
    } map_view;
    struct
    {
        enum apc_type    type;      /* APC_MAP_VIEW_EX */
        unsigned int     status;    /* status returned by call */
        client_ptr_t     addr;      /* resulting address */
        mem_size_t       size;      /* resulting size */
    } map_view_ex;
    struct
    {
        enum apc_type    type;      /* APC_UNMAP_VIEW */
        unsigned int     status;    /* status returned by call */
    } unmap_view;
    struct
    {
        enum apc_type    type;      /* APC_CREATE_THREAD */
        unsigned int     status;    /* status returned by call */
        process_id_t     pid;       /* process id */
        thread_id_t      tid;       /* thread id */
        client_ptr_t     teb;       /* thread teb (in process address space) */
        obj_handle_t     handle;    /* handle to new thread */
    } create_thread;
    struct
    {
        enum apc_type    type;      /* APC_DUP_HANDLE */
        unsigned int     status;    /* status returned by call */
        obj_handle_t     handle;    /* duplicated handle in dst process */
    } dup_handle;
    struct
    {
        enum apc_type    type;      /* APC_BREAK_PROCESS */
        unsigned int     status;    /* status returned by call */
    } break_process;
};
```

Size asserts from server/request_handlers.h
We SHOULD assert in rust to match these.
```
C_ASSERT( sizeof(abstime_t) == 8 );
C_ASSERT( sizeof(affinity_t) == 8 );
C_ASSERT( sizeof(apc_param_t) == 8 );
C_ASSERT( sizeof(atom_t) == 4 );
C_ASSERT( sizeof(char) == 1 );
C_ASSERT( sizeof(client_ptr_t) == 8 );
C_ASSERT( sizeof(data_size_t) == 4 );
C_ASSERT( sizeof(file_pos_t) == 8 );
C_ASSERT( sizeof(int) == 4 );
C_ASSERT( sizeof(ioctl_code_t) == 4 );
C_ASSERT( sizeof(lparam_t) == 8 );
C_ASSERT( sizeof(mem_size_t) == 8 );
C_ASSERT( sizeof(mod_handle_t) == 8 );
C_ASSERT( sizeof(obj_handle_t) == 4 );
C_ASSERT( sizeof(object_id_t) == 8 );
C_ASSERT( sizeof(process_id_t) == 4 );
C_ASSERT( sizeof(short int) == 2 );
C_ASSERT( sizeof(struct async_data) == 40 );
C_ASSERT( sizeof(struct context_data) == 1720 );
C_ASSERT( sizeof(struct cursor_pos) == 24 );
C_ASSERT( sizeof(struct filesystem_event) == 12 );
C_ASSERT( sizeof(struct generic_map) == 16 );
C_ASSERT( sizeof(struct handle_info) == 20 );
C_ASSERT( sizeof(struct luid) == 8 );
C_ASSERT( sizeof(struct luid_attr) == 12 );
C_ASSERT( sizeof(struct obj_locator) == 16 );
C_ASSERT( sizeof(struct object_attributes) == 16 );
C_ASSERT( sizeof(struct object_type_info) == 44 );
C_ASSERT( sizeof(struct pe_image_info) == 96 );
C_ASSERT( sizeof(struct process_info) == 40 );
C_ASSERT( sizeof(struct property_data) == 16 );
C_ASSERT( sizeof(struct rawinput_device) == 12 );
C_ASSERT( sizeof(struct rectangle) == 16 );
C_ASSERT( sizeof(struct startup_info_data) == 96 );
C_ASSERT( sizeof(struct thread_info) == 40 );
C_ASSERT( sizeof(struct user_apc) == 40 );
C_ASSERT( sizeof(thread_id_t) == 4 );
C_ASSERT( sizeof(timeout_t) == 8 );
C_ASSERT( sizeof(union apc_call) == 64 );
C_ASSERT( sizeof(union apc_result) == 40 );
C_ASSERT( sizeof(union debug_event_data) == 160 );
C_ASSERT( sizeof(union hw_input) == 40 );
C_ASSERT( sizeof(union irp_params) == 32 );
C_ASSERT( sizeof(union message_data) == 48 );
C_ASSERT( sizeof(union select_op) == 264 );
C_ASSERT( sizeof(union tcp_connection) == 60 );
C_ASSERT( sizeof(union udp_endpoint) == 32 );
C_ASSERT( sizeof(unsigned __int64) == 8 );
C_ASSERT( sizeof(unsigned char) == 1 );
C_ASSERT( sizeof(unsigned int) == 4 );
C_ASSERT( sizeof(unsigned short) == 2 );
C_ASSERT( sizeof(user_handle_t) == 4 );
C_ASSERT( offsetof(struct new_process_request, token) == 12 );
C_ASSERT( offsetof(struct new_process_request, debug) == 16 );
C_ASSERT( offsetof(struct new_process_request, parent_process) == 20 );
C_ASSERT( offsetof(struct new_process_request, flags) == 24 );
C_ASSERT( offsetof(struct new_process_request, socket_fd) == 28 );
C_ASSERT( offsetof(struct new_process_request, access) == 32 );
C_ASSERT( offsetof(struct new_process_request, machine) == 36 );
C_ASSERT( offsetof(struct new_process_request, info_size) == 40 );
C_ASSERT( offsetof(struct new_process_request, handles_size) == 44 );
C_ASSERT( offsetof(struct new_process_request, jobs_size) == 48 );
C_ASSERT( sizeof(struct new_process_request) == 56 );
C_ASSERT( offsetof(struct new_process_reply, info) == 8 );
C_ASSERT( offsetof(struct new_process_reply, pid) == 12 );
C_ASSERT( offsetof(struct new_process_reply, handle) == 16 );
C_ASSERT( sizeof(struct new_process_reply) == 24 );
C_ASSERT( offsetof(struct get_new_process_info_request, info) == 12 );
C_ASSERT( sizeof(struct get_new_process_info_request) == 16 );
C_ASSERT( offsetof(struct get_new_process_info_reply, success) == 8 );
C_ASSERT( offsetof(struct get_new_process_info_reply, exit_code) == 12 );
C_ASSERT( sizeof(struct get_new_process_info_reply) == 16 );
C_ASSERT( offsetof(struct new_thread_request, process) == 12 );
C_ASSERT( offsetof(struct new_thread_request, access) == 16 );
C_ASSERT( offsetof(struct new_thread_request, flags) == 20 );
C_ASSERT( offsetof(struct new_thread_request, request_fd) == 24 );
C_ASSERT( sizeof(struct new_thread_request) == 32 );
C_ASSERT( offsetof(struct new_thread_reply, tid) == 8 );
C_ASSERT( offsetof(struct new_thread_reply, handle) == 12 );
C_ASSERT( sizeof(struct new_thread_reply) == 16 );
C_ASSERT( sizeof(struct get_startup_info_request) == 16 );
C_ASSERT( offsetof(struct get_startup_info_reply, info_size) == 8 );
C_ASSERT( offsetof(struct get_startup_info_reply, machine) == 12 );
C_ASSERT( sizeof(struct get_startup_info_reply) == 16 );
C_ASSERT( offsetof(struct init_process_done_request, teb) == 16 );
C_ASSERT( offsetof(struct init_process_done_request, peb) == 24 );
C_ASSERT( offsetof(struct init_process_done_request, ldt_copy) == 32 );
C_ASSERT( sizeof(struct init_process_done_request) == 40 );
C_ASSERT( offsetof(struct init_process_done_reply, suspend) == 8 );
C_ASSERT( sizeof(struct init_process_done_reply) == 16 );
C_ASSERT( offsetof(struct init_first_thread_request, unix_pid) == 12 );
C_ASSERT( offsetof(struct init_first_thread_request, unix_tid) == 16 );
C_ASSERT( offsetof(struct init_first_thread_request, debug_level) == 20 );
C_ASSERT( offsetof(struct init_first_thread_request, reply_fd) == 24 );
C_ASSERT( offsetof(struct init_first_thread_request, wait_fd) == 28 );
C_ASSERT( sizeof(struct init_first_thread_request) == 32 );
C_ASSERT( offsetof(struct init_first_thread_reply, pid) == 8 );
C_ASSERT( offsetof(struct init_first_thread_reply, tid) == 12 );
C_ASSERT( offsetof(struct init_first_thread_reply, server_start) == 16 );
C_ASSERT( offsetof(struct init_first_thread_reply, session_id) == 24 );
C_ASSERT( offsetof(struct init_first_thread_reply, info_size) == 28 );
C_ASSERT( sizeof(struct init_first_thread_reply) == 32 );
C_ASSERT( offsetof(struct init_thread_request, unix_tid) == 12 );
C_ASSERT( offsetof(struct init_thread_request, reply_fd) == 16 );
C_ASSERT( offsetof(struct init_thread_request, wait_fd) == 20 );
C_ASSERT( offsetof(struct init_thread_request, teb) == 24 );
C_ASSERT( offsetof(struct init_thread_request, entry) == 32 );
C_ASSERT( sizeof(struct init_thread_request) == 40 );
C_ASSERT( offsetof(struct init_thread_reply, suspend) == 8 );
C_ASSERT( sizeof(struct init_thread_reply) == 16 );
C_ASSERT( offsetof(struct terminate_process_request, handle) == 12 );
C_ASSERT( offsetof(struct terminate_process_request, exit_code) == 16 );
C_ASSERT( sizeof(struct terminate_process_request) == 24 );
C_ASSERT( offsetof(struct terminate_process_reply, self) == 8 );
C_ASSERT( sizeof(struct terminate_process_reply) == 16 );
C_ASSERT( offsetof(struct terminate_thread_request, handle) == 12 );
C_ASSERT( offsetof(struct terminate_thread_request, exit_code) == 16 );
C_ASSERT( sizeof(struct terminate_thread_request) == 24 );
C_ASSERT( offsetof(struct terminate_thread_reply, self) == 8 );
C_ASSERT( sizeof(struct terminate_thread_reply) == 16 );
C_ASSERT( offsetof(struct get_process_info_request, handle) == 12 );
C_ASSERT( sizeof(struct get_process_info_request) == 16 );
C_ASSERT( offsetof(struct get_process_info_reply, pid) == 8 );
C_ASSERT( offsetof(struct get_process_info_reply, ppid) == 12 );
C_ASSERT( offsetof(struct get_process_info_reply, affinity) == 16 );
C_ASSERT( offsetof(struct get_process_info_reply, peb) == 24 );
C_ASSERT( offsetof(struct get_process_info_reply, start_time) == 32 );
C_ASSERT( offsetof(struct get_process_info_reply, end_time) == 40 );
C_ASSERT( offsetof(struct get_process_info_reply, session_id) == 48 );
C_ASSERT( offsetof(struct get_process_info_reply, exit_code) == 52 );
C_ASSERT( offsetof(struct get_process_info_reply, priority) == 56 );
C_ASSERT( offsetof(struct get_process_info_reply, base_priority) == 60 );
C_ASSERT( offsetof(struct get_process_info_reply, machine) == 62 );
...
C_ASSERT( sizeof(struct list_processes_request) == 16 );
C_ASSERT( offsetof(struct list_processes_reply, info_size) == 8 );
C_ASSERT( offsetof(struct list_processes_reply, process_count) == 12 );
C_ASSERT( offsetof(struct list_processes_reply, total_thread_count) == 16 );
C_ASSERT( offsetof(struct list_processes_reply, total_name_len) == 20 );
C_ASSERT( sizeof(struct list_processes_reply) == 24 );
```