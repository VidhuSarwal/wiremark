#ifndef COMMON_BPF_H
#define COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "types.h"

/* Shared by every BPF program (syscall.bpf.c, tls.bpf.c): bpf_ringbuf_reserve
 * does not zero the memory it returns -- it's whatever a previous record
 * left behind after the ring wraps around. Every field not explicitly set
 * by the caller right after this call must be zeroed here, or it silently
 * leaks stale bytes from an unrelated earlier event. (Found the hard way:
 * adding ssl_ptr to struct event without adding it here would have leaked
 * garbage into every syscall-sourced event's SSLPtr field.) */
static __always_inline void fill_common(struct event *e, __u32 op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->timestamp = bpf_ktime_get_ns();
	e->fd = 0;
	e->operation = op;
	e->ret = 0;
	e->ssl_ptr = 0;
	e->remote_addr = 0;
	e->remote_port = 0;
	e->total_len = 0;
	e->data_len = 0;
}

#endif
