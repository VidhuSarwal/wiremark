#ifndef TYPES_H
#define TYPES_H

#define OP_CONNECT   0
#define OP_READ      1
#define OP_WRITE     2
#define OP_CLOSE     3
#define OP_SSL_WRITE 4
#define OP_SSL_READ  5

/* data[] captures up to this many bytes of a read/write's payload for
 * content decoding; total_len carries the syscall's true byte count (the
 * requested count for write, the actual return value for read) even when
 * the payload itself is truncated. data_len < total_len means truncated. */
#define DATA_CAP 4096

struct event {
	__u32 pid;
	__u32 tid;
	__u64 timestamp;
	__s32 fd;          /* -1 for OP_SSL_*: no fd is recoverable in-kernel
	                    * from an SSL* alone, so ssl_ptr is the connection
	                    * identity for those ops instead. */
	__u32 operation;
	__s32 ret;
	__u64 ssl_ptr;     /* SSL* identity; valid for OP_SSL_WRITE/OP_SSL_READ */
	__u32 remote_addr; /* network byte order IPv4; valid for OP_CONNECT */
	__u16 remote_port; /* host byte order; valid for OP_CONNECT */
	__u32 total_len;   /* true byte count; valid for OP_READ/OP_WRITE/OP_SSL_* */
	__u32 data_len;    /* captured (possibly truncated) length of data[] */
	char data[DATA_CAP];
};

#endif
