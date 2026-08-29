#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "types.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->timestamp = bpf_ktime_get_ns();
	e->operation = OP_CONNECT;
	e->fd = (__s32)ctx->args[0];
	e->ret = 0;
	e->data_len = 0;
	e->remote_addr = 0;
	e->remote_port = 0;

	struct sockaddr_in addr = {};
	void *uservaddr = (void *)ctx->args[1];
	if (bpf_probe_read_user(&addr, sizeof(addr), uservaddr) == 0 &&
	    addr.sin_family == AF_INET) {
		e->remote_addr = addr.sin_addr.s_addr;
		e->remote_port = bpf_ntohs(addr.sin_port);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
