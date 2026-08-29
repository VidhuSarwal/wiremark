#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "types.h"
#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Same guard as syscall.bpf.c's target_pid -- a separate global in this
 * separate BPF object, since each bpf2go-generated object gets its own
 * rodata section. Belt-and-suspenders here: the uprobe is also attached
 * with link.UprobeOptions{PID: ...} on the Go side, which filters at
 * attach time rather than per-call, so this program never even runs for
 * another process's SSL_write/SSL_read -- this check is what stops a
 * *different* traced PID's stale-but-still-loaded program from matching,
 * not what prevents a system-wide flood. */
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

/* SSL_read's buffer isn't populated until the call returns -- the same
 * reason sys_enter_read/sys_exit_read need an entry+exit pair -- so stash
 * {ssl, buf} at entry keyed by pid_tgid and read it back at return, using
 * the real return value as the actual decrypted length. */
struct ssl_read_args {
	__u64 ssl;
	__u64 buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct ssl_read_args);
} ssl_read_stash SEC(".maps");

/* int SSL_write(SSL *ssl, const void *buf, int num) -- data is present at
 * entry (the caller is handing plaintext to OpenSSL to encrypt and send),
 * so this is single-probe like sys_enter_write. */
SEC("uprobe/SSL_write")
int BPF_KPROBE(trace_ssl_write, void *ssl, void *buf, int num)
{
	if (!pid_matches())
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, OP_SSL_WRITE);
	e->fd = -1;
	e->ssl_ptr = (__u64)ssl;
	e->total_len = (__u32)num;

	__u32 len = (__u32)num;
	if (len > DATA_CAP - 1)
		len = DATA_CAP - 1;
	len &= (DATA_CAP - 1);
	if (bpf_probe_read_user(e->data, len, buf) == 0)
		e->data_len = len;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* int SSL_read(SSL *ssl, void *buf, int num) */
SEC("uprobe/SSL_read")
int BPF_KPROBE(trace_ssl_read_enter, void *ssl, void *buf, int num)
{
	if (!pid_matches())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ssl_read_args args = {
		.ssl = (__u64)ssl,
		.buf = (__u64)buf,
	};
	bpf_map_update_elem(&ssl_read_stash, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int BPF_KRETPROBE(trace_ssl_read_exit, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_stash, &pid_tgid);
	if (!args)
		return 0;

	/* Stash the values we need before deleting the map entry, since args
	 * points into map memory that becomes invalid after delete. */
	__u64 ssl = args->ssl;
	__u64 buf = args->buf;
	bpf_map_delete_elem(&ssl_read_stash, &pid_tgid);

	if (!pid_matches() || ret <= 0)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, OP_SSL_READ);
	e->fd = -1;
	e->ssl_ptr = ssl;
	e->ret = ret;
	e->total_len = (__u32)ret;

	__u32 len = (__u32)ret;
	if (len > DATA_CAP - 1)
		len = DATA_CAP - 1;
	len &= (DATA_CAP - 1);
	if (bpf_probe_read_user(e->data, len, (void *)buf) == 0)
		e->data_len = len;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
