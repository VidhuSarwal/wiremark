package bpfgen

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" Syscall ../../bpf/syscall.bpf.c -- -I../../bpf

// tls.bpf.c's uprobes use bpf_tracing.h's PT_REGS_PARMn/PT_REGS_RC macros
// (uprobe args/return value aren't tracepoint ctx->args[N] fields), which
// dispatch on an arch macro bpf2go doesn't set automatically -- without it,
// clang fails with "Must specify a BPF target arch via __TARGET_ARCH_xxx"
// rather than silently generating wrong offsets. Same uname->macro mapping
// libbpf-bootstrap's Makefiles use, so this regenerates correctly on
// whatever box it's run on, matching how bpf/vmlinux.h is already
// regenerated per-box rather than assumed.
//go:generate sh -c "go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags \"-O2 -g -Wall -D__TARGET_ARCH_$(uname -m | sed -e s/x86_64/x86/ -e s/aarch64/arm64/ -e s/ppc64le/powerpc/ -e 's/mips.*/mips/' -e s/riscv64/riscv/ -e s/loongarch64/loongarch/)\" Tls ../../bpf/tls.bpf.c -- -I../../bpf"
