//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * PMG network enforcement. Attached to a cgroup, these programs route the
 * TCP connections of eligible processes to the PMG proxy and deny their UDP
 * to the same ports, so a QUIC client falls back to TCP.
 *
 * The decision for each connect, after the destination port is known to be
 * enforced:
 *
 *   1. another network namespace than the proxy: pass
 *   2. destination in the skip list: pass
 *   3. the daemon's own pid: pass
 *   4. exempt uid, or not an eligible uid: pass
 *   5. exempt executable (dev, inode): pass
 *   6. store the original destination, rewrite to the proxy
 *
 * The kernel requires a GPL-compatible licence for bpf_get_current_task_btf.
 * The Go code around these programs stays Apache-2.0.
 */
#include "pmg_bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define CFG_TRACE (1 << 0)
#define CFG_HAS_PROXY6 (1 << 1)
#define CFG_DENY_UDP (1 << 2)
#define CFG_ELIGIBLE_UIDS (1 << 3)

enum action {
	ACT_OTHER_NETNS = 1,
	ACT_SKIP_DST = 2,
	ACT_EXEMPT_DAEMON = 3,
	ACT_EXEMPT_UID = 4,
	ACT_NOT_ELIGIBLE_UID = 5,
	ACT_EXEMPT_EXE = 6,
	ACT_REDIRECT = 7,
	ACT_DENY_UDP = 8,
	ACT_DENY_IPV6 = 9,
	ACT_MAX = 16,
};

struct cfg {
	__u32 proxy_ip4;    /* network order */
	__u16 proxy_port;   /* network order */
	__u16 flags;        /* CFG_* */
	__u32 daemon_tgid;  /* the only pid that is exempt */
	__u32 _pad;
	__u64 netns_cookie; /* only sockets in this namespace are routed */
	__u32 proxy_ip6[4]; /* network order, valid with CFG_HAS_PROXY6 */
};

struct exe_key {
	__u64 dev; /* kernel dev_t: major << 20 | minor */
	__u64 ino;
};

struct skip4_key {
	__u32 prefixlen;
	__u32 addr; /* network order */
};

struct skip6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

/* The destination a client asked for, before the rewrite. */
struct dst {
	__u16 family; /* AF_INET also for an IPv4-mapped IPv6 destination */
	__u16 port;   /* network order */
	__u8 addr[16];
};

struct dst_key {
	__u16 family; /* dst.family */
	__u16 sport;  /* host order */
};

struct exec_event {
	__u64 dev;
	__u64 ino;
};

struct event {
	__u32 tgid;
	__u32 uid;
	__u16 family;
	__u16 dport; /* host order */
	__u8 action;
	__u8 proto;
	__u8 _pad[2];
	__u8 dst[16];
	__u64 exe_dev;
	__u64 exe_ino;
	char comm[16];
};

/* Ring buffer records are not map values, so BTF only keeps their types
 * when something else references them. bpf2go needs both. */
const struct event *unused_event __attribute__((unused));
const struct exec_event *unused_exec_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg);
} pmg_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, __u8);
} ports SEC(".maps"); /* key: destination port, host order */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} eligible_uid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} exempt_uid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct exe_key);
	__type(value, __u8);
} exempt_exe SEC(".maps");

/* Executables already reported to the daemon, so each is reported once. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct exe_key);
	__type(value, __u8);
} seen_exe SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 256);
	__type(key, struct skip4_key);
	__type(value, __u8);
} skip4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 256);
	__type(key, struct skip6_key);
	__type(value, __u8);
} skip6 SEC(".maps");

/* Per-socket original destination, written at connect, read in sockops. */
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct dst);
} orig_dst_sk SEC(".maps");

/* Original destination by (family, source port). The proxy reads and
 * deletes an entry after accept. The LRU evicts entries of connections that
 * never reached the proxy. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct dst_key);
	__type(value, struct dst);
} orig_dst SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} exec_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ACT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline struct cfg *get_cfg(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&pmg_cfg, &key);
}

static __always_inline void count(__u32 action)
{
	__u64 *n = bpf_map_lookup_elem(&stats, &action);
	if (n)
		*n += 1;
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

static __always_inline void finish(struct cfg *c, struct event *e, __u8 action)
{
	e->action = action;
	count(action);
	if (!(c->flags & CFG_TRACE))
		return;
	struct event *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r)
		return;
	__builtin_memcpy(r, e, sizeof(*r));
	bpf_ringbuf_submit(r, 0);
}

static __always_inline int is_mapped_v4(const __u32 ip6[4])
{
	return ip6[0] == 0 && ip6[1] == 0 && ip6[2] == bpf_htonl(0xffff);
}

static __always_inline int in_skip4(__u32 addr)
{
	struct skip4_key k = { .prefixlen = 32, .addr = addr };
	return bpf_map_lookup_elem(&skip4, &k) != 0;
}

/* The address comes from a copy on the stack. A memcpy from the context
 * would be a modified ctx pointer, which the verifier rejects. */
static __always_inline int in_skip6(const __u32 ip6[4])
{
	struct skip6_key k = { .prefixlen = 128 };
	__builtin_memcpy(k.addr, ip6, 16);
	return bpf_map_lookup_elem(&skip6, &k) != 0;
}

/* decide runs steps 1 to 5 and returns 0 when the connection passes. On a
 * return of 1 the caller routes or denies. The event holds the trace data.
 */
static __always_inline int decide(struct bpf_sock_addr *ctx, struct cfg *c, struct event *e, int skipped)
{
	if (c->netns_cookie && bpf_get_netns_cookie(ctx) != c->netns_cookie) {
		finish(c, e, ACT_OTHER_NETNS);
		return 0;
	}
	if (skipped) {
		finish(c, e, ACT_SKIP_DST);
		return 0;
	}

	e->tgid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	if (e->tgid == c->daemon_tgid) {
		finish(c, e, ACT_EXEMPT_DAEMON);
		return 0;
	}
	if (bpf_map_lookup_elem(&exempt_uid, &e->uid)) {
		finish(c, e, ACT_EXEMPT_UID);
		return 0;
	}
	if ((c->flags & CFG_ELIGIBLE_UIDS) && !bpf_map_lookup_elem(&eligible_uid, &e->uid)) {
		finish(c, e, ACT_NOT_ELIGIBLE_UID);
		return 0;
	}

	fill_exe(e);
	struct exe_key ek = { .dev = e->exe_dev, .ino = e->exe_ino };
	if (bpf_map_lookup_elem(&exempt_exe, &ek)) {
		finish(c, e, ACT_EXEMPT_EXE);
		return 0;
	}
	return 1;
}

static __always_inline int enforced_port(struct bpf_sock_addr *ctx, struct event *e)
{
	__u16 dport = bpf_ntohs(ctx->user_port);
	e->dport = dport;
	return bpf_map_lookup_elem(&ports, &dport) != 0;
}

static __always_inline void store_dst(struct bpf_sock_addr *ctx, __u16 family, const void *addr, int len)
{
	struct dst *d = bpf_sk_storage_get(&orig_dst_sk, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!d)
		return;
	d->family = family;
	d->port = ctx->user_port;
	__builtin_memcpy(d->addr, addr, len);
}

/* handle4 covers an IPv4 socket and an IPv4-mapped destination on an IPv6
 * socket. The caller passes the address words to rewrite. */
static __always_inline int handle4(struct bpf_sock_addr *ctx, __u32 *addr_word, __u32 addr)
{
	struct event e = {};
	e.family = AF_INET;
	e.proto = ctx->protocol;
	__builtin_memcpy(e.dst, &addr, 4);

	if (!enforced_port(ctx, &e))
		return 1;
	struct cfg *c = get_cfg();
	if (!c || !c->proxy_port)
		return 1;
	if (!decide(ctx, c, &e, in_skip4(addr)))
		return 1;

	if (ctx->protocol == IPPROTO_UDP) {
		if (!(c->flags & CFG_DENY_UDP))
			return 1;
		finish(c, &e, ACT_DENY_UDP);
		return 0;
	}

	store_dst(ctx, AF_INET, &addr, 4);
	*addr_word = c->proxy_ip4;
	ctx->user_port = c->proxy_port;
	finish(c, &e, ACT_REDIRECT);
	return 1;
}

static __always_inline int handle6(struct bpf_sock_addr *ctx)
{
	__u32 ip6[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
	if (is_mapped_v4(ip6))
		return handle4(ctx, &ctx->user_ip6[3], ip6[3]);

	struct event e = {};
	e.family = AF_INET6;
	e.proto = ctx->protocol;
	__builtin_memcpy(e.dst, ip6, 16);

	if (!enforced_port(ctx, &e))
		return 1;
	struct cfg *c = get_cfg();
	if (!c || !c->proxy_port)
		return 1;
	if (!decide(ctx, c, &e, in_skip6(ip6)))
		return 1;

	if (ctx->protocol == IPPROTO_UDP) {
		if (!(c->flags & CFG_DENY_UDP))
			return 1;
		finish(c, &e, ACT_DENY_UDP);
		return 0;
	}

	/* Without an IPv6 listener the client gets EPERM and falls back to IPv4. */
	if (!(c->flags & CFG_HAS_PROXY6)) {
		finish(c, &e, ACT_DENY_IPV6);
		return 0;
	}

	store_dst(ctx, AF_INET6, ip6, 16);
	ctx->user_ip6[0] = c->proxy_ip6[0];
	ctx->user_ip6[1] = c->proxy_ip6[1];
	ctx->user_ip6[2] = c->proxy_ip6[2];
	ctx->user_ip6[3] = c->proxy_ip6[3];
	ctx->user_port = c->proxy_port;
	finish(c, &e, ACT_REDIRECT);
	return 1;
}

SEC("cgroup/connect4")
int pmg_connect4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET)
		return 1;
	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;
	return handle4(ctx, &ctx->user_ip4, ctx->user_ip4);
}

SEC("cgroup/connect6")
int pmg_connect6(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET6)
		return 1;
	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;
	return handle6(ctx);
}

/* sendmsg on an unconnected UDP socket never calls connect, so the QUIC
 * guard needs these two hooks too. handle4 and handle6 only deny for UDP. */
SEC("cgroup/sendmsg4")
int pmg_sendmsg4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET || ctx->protocol != IPPROTO_UDP)
		return 1;
	return handle4(ctx, &ctx->user_ip4, ctx->user_ip4);
}

SEC("cgroup/sendmsg6")
int pmg_sendmsg6(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET6 || ctx->protocol != IPPROTO_UDP)
		return 1;
	return handle6(ctx);
}

/* The kernel assigns the source port after connect4/6 ran. This hook copies
 * the stored destination into the map the proxy reads. */
SEC("sockops")
int pmg_sockops(struct bpf_sock_ops *skops)
{
	if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 1;
	struct bpf_sock *sk = skops->sk;
	if (!sk)
		return 1;

	struct dst *d = bpf_sk_storage_get(&orig_dst_sk, sk, 0, 0);
	if (!d)
		return 1;

	struct dst_key k = { .family = d->family, .sport = skops->local_port };
	bpf_map_update_elem(&orig_dst, &k, d, BPF_ANY);
	return 1;
}

/* Every exec reports the (dev, inode) of the new image once, so the daemon
 * can match a binary that appeared after it started against the exempt
 * globs. The daemon never reads /proc for this. */
SEC("tp_btf/sched_process_exec")
int pmg_exec(__u64 *ctx)
{
	struct linux_binprm *bprm = (struct linux_binprm *)ctx[2];
	struct file *f = bprm->file;
	if (!f)
		return 0;
	struct inode *in = f->f_inode;
	if (!in)
		return 0;

	struct exe_key k = { .dev = in->i_sb->s_dev, .ino = in->i_ino };
	__u8 one = 1;
	if (bpf_map_update_elem(&seen_exe, &k, &one, BPF_NOEXIST) != 0)
		return 0;

	struct exec_event *ev = bpf_ringbuf_reserve(&exec_events, sizeof(*ev), 0);
	if (!ev)
		return 0;
	ev->dev = k.dev;
	ev->ino = k.ino;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}
