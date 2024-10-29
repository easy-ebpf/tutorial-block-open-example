// SPDX-License-Identifier: GPL-2.0-or-later
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include "block_open.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, u8);
} blocked_files SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(block_open, struct file *file)
{
    struct dentry *dentry;
    const char* filename;
    u8 *value;
    struct blocked_event *event;
    u32 pid;
    int err;

    filename = dentry->d_name.name;
    bpf_printk("%s, %s\n", filename, dentry->d_name.name);

    value = bpf_map_lookup_elem(&blocked_files, &filename);
    if (value) {
        // Report the blocking event
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            pid = bpf_get_current_pid_tgid() >> 32;
            event->pid = pid;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(&event->filename, &filename, sizeof(event->filename));
            bpf_ringbuf_submit(event, 0);
        }
        return -EACCES; // Block the open operation
    }
    return 0; // Allow the open operation
}

