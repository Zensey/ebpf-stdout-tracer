#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/signal.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX_CHUNK_SIZE 128
#define MAX_CHUNKS 16

#define PID_FILTER {{PID}}

// Data structure to pass data to userspace
struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];

    u64 len;
    u64 chunk_len;
    char content[MAX_CHUNK_SIZE];
};

BPF_PERF_OUTPUT(open_event);

//int trace_write2(struct tracepoint__syscalls__sys_enter_write *ctx) {
TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;    
    u32 fd = args->fd;
    size_t len = args->count;
    if (pid == PID_FILTER) {
        return 0;
    }
    if (fd != 1) {
        return 0;
    }
    if (len == 0) {
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.len = len;

    u32 offset = 0;
    for (u32 i = 0; i < 20; i++) {
        if (offset >= len) {
            break;
        }
        u32 remain = len - offset;
        data.chunk_len = MIN(remain, MAX_CHUNK_SIZE);
        
        bpf_probe_read_user(data.content, MAX_CHUNK_SIZE, args->buf + offset);
        open_event.perf_submit(args, &data, sizeof(data));

        offset += MAX_CHUNK_SIZE;
    }
    return 0;
}
