#ifndef TYPES_H
#define TYPES_H

#define OP_CONNECT 0
#define OP_READ    1
#define OP_WRITE   2
#define OP_CLOSE   3

struct event {
	__u32 pid;
	__u32 tid;
	__u64 timestamp;
	__s32 fd;
	__u32 operation;
	__s32 ret;
	__u32 remote_addr; /* network byte order IPv4; valid for OP_CONNECT */
	__u16 remote_port; /* host byte order; valid for OP_CONNECT */
	__u32 data_len;
	char data[256];
};

#endif
