//go:build ignore

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Self-contained declarations for the PMG enforcement programs. The file
 * replaces vmlinux.h and the libbpf headers, so the build depends on clang
 * alone and the committed object is reproducible.
 *
 * The uapi structs are copied from include/uapi/linux/bpf.h. The kernel
 * structs hold only the fields the programs read. CO-RE relocates each
 * field by name at load time, so the layout here does not have to match
 * the running kernel.
 */
#ifndef PMG_BPF_H
#define PMG_BPF_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 dev_t;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* CO-RE queries, as libbpf's bpf_core_read.h defines them. */
#define BPF_FIELD_BYTE_OFFSET 0
#define BPF_TYPE_SIZE 1
#define bpf_core_field_offset(field) __builtin_preserve_field_info(field, BPF_FIELD_BYTE_OFFSET)
#define bpf_core_type_size(type) __builtin_preserve_type_info(*(typeof(type) *)0, BPF_TYPE_SIZE)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)
#endif

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_SK_STORAGE_GET_F_CREATE (1ULL << 0)
#define BPF_SOCK_OPS_TCP_CONNECT_CB 3

#define __bpf_md_ptr(type, name) \
	union {                  \
		type name;       \
		__u64 : 64;      \
	} __attribute__((aligned(8)))

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;
	__be16 dst_port;
	__u16 : 16;
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	__bpf_md_ptr(struct bpf_sock *, sk);
};

struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 is_fullsock;
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 bpf_sock_ops_cb_flags;
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__bpf_md_ptr(void *, skb_data);
	__bpf_md_ptr(void *, skb_data_end);
	__u32 skb_len;
	__u32 skb_tcp_flags;
	__u64 skb_hwtstamp;
};

/* Kernel structs. Only the fields the programs read, relocated by CO-RE. */
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
struct super_block {
	dev_t s_dev;
};

struct inode {
	struct super_block *i_sb;
	unsigned long i_ino;
};

struct file {
	struct inode *f_inode;
};

struct mm_struct {
	struct file *exe_file;
};

struct ns_common {
	unsigned int inum; /* the inode of /proc/<pid>/ns/pid */
};

struct pid_namespace {
	struct ns_common ns;
};

struct upid {
	int nr;
	struct pid_namespace *ns;
};

/* The kernel declares numbers as a flexible array with level + 1 entries,
 * one per namespace from the initial one inwards. */
struct pid {
	unsigned int level;
	struct upid numbers[1];
};

struct task_struct {
	struct mm_struct *mm;
	struct task_struct *group_leader;
	struct pid *thread_pid;
};

struct linux_binprm {
	struct file *file;
};
#pragma clang attribute pop

/* Helpers, by their uapi number. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static void *(*bpf_sk_storage_get)(void *map, void *sk, void *value, __u64 flags) = (void *)107;
static __u64 (*bpf_get_netns_cookie)(void *ctx) = (void *)122;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static struct task_struct *(*bpf_get_current_task_btf)(void) = (void *)158;

#endif /* PMG_BPF_H */
