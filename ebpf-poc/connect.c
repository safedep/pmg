//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
  __u32 pid;
  __u32 uid;
  __u32 daddr;
  __u16 dport;
  __u8  comm[16]; // command
};

struct event *unused_event __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 1;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->daddr = ctx->user_ip4;
  e->dport = bpf_ntohs(ctx->user_port);
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_ringbuf_submit(e, 0);
  return 1;
}
