package bpfgen

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" Syscall ../../bpf/syscall.bpf.c -- -I../../bpf
