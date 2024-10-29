// File: block_open.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "block_open.h"

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 256

// Map to store the list of filenames to monitor
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, u8);
} monitored_files SEC(".maps");

// Define the ring buffer map for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename_ptr;
    char filename[MAX_FILENAME_LEN] = {};
    u8 *value;
    int ret;

    // Get the filename argument (second argument of openat syscall)
    filename_ptr = (const char *)ctx->args[1];

    // Read the filename from userspace memory
    ret = bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
    if (ret <= 0) {
        return 0; // Failed to read filename
    }

    // Check if the filename is in the monitored_files map
    value = bpf_map_lookup_elem(&monitored_files, filename);
    if (value) {
        // Report the access event
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            return 0;
        }
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(&e->filename, filename, sizeof(e->filename));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int handle_sys_enter_open(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename_ptr;
    char filename[MAX_FILENAME_LEN] = {};
    u8 *value;
    int ret;

    // Get the filename argument (second argument of openat syscall)
    filename_ptr = (const char *)ctx->args[1];

    // Read the filename from userspace memory
    ret = bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
    if (ret <= 0) {
        return 0; // Failed to read filename
    }

    // Check if the filename is in the monitored_files map
    value = bpf_map_lookup_elem(&monitored_files, filename);
    if (value) {
        // Report the access event
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            return 0;
        }
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(&e->filename, filename, sizeof(e->filename));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
