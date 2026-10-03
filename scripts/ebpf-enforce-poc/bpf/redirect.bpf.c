// POC: force eligible processes' TCP 80/443 connections through the PMG proxy.
// Attach points: cgroup/connect4 (rewrite destination) and cgroup/sockops
// (publish the original destination keyed by the client's source port so the
// proxy can recover it after accept()).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define LOOPBACK_NET 0x7f000000 /* 127.0.0.0/8 host order */

struct cfg {
	__u32 proxy_ip4;   /* network order */
	__u16 proxy_port;  /* network order */
	__u16 _pad;
	__u64 netns_cookie; /* only sockets in the proxy's netns are redirected */
	__u32 ctr_ip4;      /* network order; 0 = leave other netns alone */
	__u32 _pad2;
};

struct exe_key {
	__u64 dev;  /* kernel dev_t: MKDEV(major, minor) */
	__u64 ino;
};

struct dst {
	__u32 ip4;   /* network order */
	__u16 port;  /* network order */
	__u16 _pad;
};

struct event {
	__u32 tgid;
	__u32 uid;
	__u32 dst_ip4;
	__u16 dst_port;
	__u8  action;   /* 0 pass(not eligible port/loopback) 1 exempt-pid 2 exempt-exe 3 exempt-uid 4 redirected */
	__u8  _pad;
	__u64 exe_dev;
	__u64 exe_ino;
	char  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg);
} pmg_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} exempt_tgid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} exempt_uid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct exe_key);
	__type(value, __u8);
} exempt_exe SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u16);
	__type(value, __u8);
} redirect_ports SEC(".maps");  /* key: dport host order */

/* Per-socket original destination, written at connect(), read in sockops. */
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct dst);
} orig_dst_sk SEC(".maps");

/* Original destination keyed by the client's local (source) port, host order. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct dst);
} orig_dst_by_sport SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline void emit(struct event *e)
{
	struct event *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r)
		return;
	__builtin_memcpy(r, e, sizeof(*r));
	bpf_ringbuf_submit(r, 0);
}

static __always_inline void fill_exe(struct event *e)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct mm_struct *mm = t->mm;
	if (!mm)
		return;
	struct file *f = mm->exe_file;
	if (!f)
		return;
	struct inode *in = f->f_inode;
	if (!in)
		return;
	e->exe_ino = in->i_ino;
	e->exe_dev = in->i_sb->s_dev;
}

static __always_inline int is_eligible(struct bpf_sock_addr *ctx, struct event *e);

/* UDP to a redirect port (QUIC / HTTP3) cannot be proxied, so an eligible
 * process is denied (EPERM) instead of bypassing the proxy. */
static __always_inline int udp_guard(struct bpf_sock_addr *ctx)
{
	struct event e = {};
	__u32 dst_host = bpf_ntohl(ctx->user_ip4);
	if ((dst_host & 0xff000000) == LOOPBACK_NET)
		return 1;
	__u16 dport = bpf_ntohs(ctx->user_port);
	if (!bpf_map_lookup_elem(&redirect_ports, &dport))
		return 1;
	e.tgid = bpf_get_current_pid_tgid() >> 32;
	e.uid = bpf_get_current_uid_gid();
	e.dst_ip4 = ctx->user_ip4;
	e.dst_port = dport;
	bpf_get_current_comm(e.comm, sizeof(e.comm));
	if (bpf_map_lookup_elem(&exempt_tgid, &e.tgid) || bpf_map_lookup_elem(&exempt_uid, &e.uid))
		return 1;
	fill_exe(&e);
	struct exe_key ek = { .dev = e.exe_dev, .ino = e.exe_ino };
	if (bpf_map_lookup_elem(&exempt_exe, &ek))
		return 1;
	e.action = 5;
	emit(&e);
	return 0;
}

SEC("cgroup/sendmsg4")
int pmg_sendmsg4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET || ctx->protocol != IPPROTO_UDP)
		return 1;
	return udp_guard(ctx);
}

SEC("cgroup/connect4")
int pmg_connect4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET)
		return 1;
	if (ctx->protocol == IPPROTO_UDP)
		return udp_guard(ctx);
	if (ctx->protocol != IPPROTO_TCP)
		return 1;

	struct event e = {};
	e.tgid = bpf_get_current_pid_tgid() >> 32;
	e.uid = bpf_get_current_uid_gid();
	e.dst_ip4 = ctx->user_ip4;
	e.dst_port = bpf_ntohs(ctx->user_port);
	bpf_get_current_comm(e.comm, sizeof(e.comm));

	__u32 dst_host = bpf_ntohl(ctx->user_ip4);
	if ((dst_host & 0xff000000) == LOOPBACK_NET)
		return 1;

	__u16 dport = e.dst_port;
	if (!bpf_map_lookup_elem(&redirect_ports, &dport))
		return 1;

	__u32 key0 = 0;
	struct cfg *c = bpf_map_lookup_elem(&pmg_cfg, &key0);
	if (!c || !c->proxy_port)
		return 1;
	__u32 target_ip = c->proxy_ip4;
	if (c->netns_cookie && bpf_get_netns_cookie(ctx) != c->netns_cookie) {
		if (!c->ctr_ip4) {
			e.action = 6;
			emit(&e);
			return 1;
		}
		target_ip = c->ctr_ip4;
		e.action = 7;
	}

	if (bpf_map_lookup_elem(&exempt_tgid, &e.tgid)) {
		e.action = 1;
		emit(&e);
		return 1;
	}
	if (bpf_map_lookup_elem(&exempt_uid, &e.uid)) {
		e.action = 3;
		emit(&e);
		return 1;
	}

	fill_exe(&e);
	struct exe_key ek = { .dev = e.exe_dev, .ino = e.exe_ino };
	if (bpf_map_lookup_elem(&exempt_exe, &ek)) {
		e.action = 2;
		emit(&e);
		return 1;
	}

	struct dst *d = bpf_sk_storage_get(&orig_dst_sk, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (d) {
		d->ip4 = ctx->user_ip4;
		d->port = ctx->user_port;
	}

	ctx->user_ip4 = target_ip;
	ctx->user_port = c->proxy_port;

	if (!e.action)
		e.action = 4;
	emit(&e);
	return 1;
}

SEC("sockops")
int pmg_sockops(struct bpf_sock_ops *skops)
{
	if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 1;
	if (skops->family != AF_INET)
		return 1;
	struct bpf_sock *sk = skops->sk;
	if (!sk)
		return 1;

	struct dst *d = bpf_sk_storage_get(&orig_dst_sk, sk, 0, 0);
	if (!d)
		return 1;

	__u32 sport = skops->local_port;
	bpf_map_update_elem(&orig_dst_by_sport, &sport, d, BPF_ANY);
	return 1;
}
