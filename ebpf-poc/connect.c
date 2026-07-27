//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define IPPROTO_TCP 6

// Only HTTPS is a candidate for redirect. Every other destination port is left
// alone, otherwise ssh, dns, postgres and everything else on the host would be
// steered into a proxy that cannot speak their protocol.
#define REDIRECT_DPORT 443

// What the hook decided. Recorded on every event so the ladder stays auditable:
// a connection that was not redirected always reports which check stopped it.
#define ACTION_REDIRECT      0
#define ACTION_SKIP_PROTO    1
#define ACTION_SKIP_LOOPBACK 2
#define ACTION_SKIP_EXEMPT   3
#define ACTION_SKIP_DPORT    4
#define ACTION_SKIP_NOTARGET 5

struct event {
  __u32 pid;
  __u32 uid;
  __u32 daddr;
  __u16 dport;
  __u8  proto;
  __u8  action;
  __u8  comm[16]; // command
};

struct event *unused_event __attribute__((unused));

// target is the redirect destination, written from userspace once the proxy is
// listening. Keeping it in a map means a proxy restart on a different port is
// one map update rather than a reload of the program.
struct target {
  __u32 ip;   // network byte order, same layout as ctx->user_ip4
  __u16 port; // host byte order, converted when written back to ctx
};

struct target *unused_target __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct target);
} target_map SEC(".maps");

// Uids whose traffic is never redirected. The proxy's own upstream fetches live
// here. Without this the rewrite sends the proxy back into itself forever.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8);
  __type(key, __u32);
  __type(value, __u8);
} exempt_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline __u8 decide(struct bpf_sock_addr *ctx, __u32 uid, __u16 dport) {
  if (ctx->protocol != IPPROTO_TCP)
    return ACTION_SKIP_PROTO;

  // Loopback is never registry traffic, and this also covers clients already
  // configured to reach the proxy directly.
  if ((bpf_ntohl(ctx->user_ip4) >> 24) == 127)
    return ACTION_SKIP_LOOPBACK;

  if (bpf_map_lookup_elem(&exempt_map, &uid))
    return ACTION_SKIP_EXEMPT;

  if (dport != REDIRECT_DPORT)
    return ACTION_SKIP_DPORT;

  __u32 key = 0;
  struct target *t = bpf_map_lookup_elem(&target_map, &key);
  if (!t || t->port == 0)
    return ACTION_SKIP_NOTARGET;

  return ACTION_REDIRECT;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
  __u32 uid = bpf_get_current_uid_gid();
  __u16 dport = bpf_ntohs(ctx->user_port);
  __u8 action = decide(ctx, uid, dport);

  // A full ring buffer costs an event, never a change in behaviour.
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e) {
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = uid;
    e->daddr = ctx->user_ip4;
    e->dport = dport;
    e->proto = ctx->protocol;
    e->action = action;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
  }

  if (action == ACTION_REDIRECT) {
    __u32 key = 0;
    struct target *t = bpf_map_lookup_elem(&target_map, &key);
    if (!t || t->port == 0) {
      return 1;
    }

    // t->ip is already network byte order, the same layout as user_ip4, so it
    // is copied as is. Byte swapping here would corrupt the address. Only the
    // port is converted, since it is stored host order for the userspace side.
    ctx->user_ip4 = t->ip;
    ctx->user_port = bpf_htons(t->port);
  }

  return 1;
}
