#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "types.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

/* 0 means "match nothing" -- there is never a real userspace PID 0, so an
 * unset target_pid safely traces zero processes instead of the whole box. */
const volatile __u32 target_pid = 0;

static __always_inline bool pid_matches(void)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	return target_pid != 0 && pid == target_pid;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct read_args {
	__u64 buf;
	__s32 fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct read_args);
} read_stash SEC(".maps");

static __always_inline void fill_common(struct event *e, __u32 op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->timestamp = bpf_ktime_get_ns();
	e->operation = op;
	e->ret = 0;
	e->remote_addr = 0;
	e->remote_port = 0;
	e->data_len = 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	if (!pid_matches())
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, OP_CONNECT);
	e->fd = (__s32)ctx->args[0];

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

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	if (!pid_matches())
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, OP_WRITE);
	e->fd = (__s32)ctx->args[0];

	__u64 count = ctx->args[2];
	__u32 len = count < sizeof(e->data) ? (__u32)count : sizeof(e->data);
	if (bpf_probe_read_user(e->data, len, (void *)ctx->args[1]) == 0)
		e->data_len = len;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	if (!pid_matches())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct read_args args = {
		.buf = ctx->args[1],
		.fd = (__s32)ctx->args[0],
	};
	bpf_map_update_elem(&read_stash, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	if (!pid_matches())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct read_args *args = bpf_map_lookup_elem(&read_stash, &pid_tgid);
	if (!args)
		return 0;

	/* Stash the values we need before deleting the map entry, since
	 * args points into map memory that becomes invalid after delete. */
	__u64 buf = args->buf;
	__s32 fd = args->fd;
	bpf_map_delete_elem(&read_stash, &pid_tgid);

	if (ctx->ret <= 0)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, OP_READ);
	e->fd = fd;
	e->ret = (__s32)ctx->ret;

	__u64 count = ctx->ret;
	__u32 len = count < sizeof(e->data) ? (__u32)count : sizeof(e->data);
	if (bpf_probe_read_user(e->data, len, (void *)buf) == 0)
		e->data_len = len;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	if (!pid_matches())
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, OP_CLOSE);
	e->fd = (__s32)ctx->args[0];

	bpf_ringbuf_submit(e, 0);
	return 0;
}
