// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "write_tracer.h"

struct trace_event_raw_sys_enter_write {
    struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    char *buf;
    __u64 count;
};


// Data structure to pass data to userspace
struct event {
    __u64 len;
    __u64 chunk_len;
    __u32 pid;
    
    char content[MAX_CHUNK_SIZE];
    char comm[TASK_COMM_LEN];        
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");


volatile __u32 filter_pid = 0;


SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter_write *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = ctx->fd;
    __u64 len = ctx->count;

    if (pid == filter_pid) {
        return 0;
    }
    if (fd != 1) {
        return 0;
    }
    if (len == 0) {
        return 0;
    }

    __u32 offset = 0;
    for (__u32 i = 0; i < 20; i++) {
        if (offset >= len) {
            break;
        }
        __u32 remain = len - offset;
        __u64 chunk_len = MIN(remain, MAX_CHUNK_SIZE);

        struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event) return 0;

        event->pid = pid;
        event->len = len;
        event->chunk_len = chunk_len;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));

        bpf_probe_read_user(event->content, MAX_CHUNK_SIZE, ctx->buf + offset);

        /* emit event */
        bpf_ringbuf_submit(event, 0);

        offset += MAX_CHUNK_SIZE;
    }
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
