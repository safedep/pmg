//go:build linux

// Package bpf holds the enforcement programs and the loader code that bpf2go
// generates from them. The compiled object is committed, so a release build
// needs no clang. `go generate ./internal/netenforce/bpf` rebuilds it, and CI
// fails when the result differs from the committed object.
//
// The programs are built CO-RE against the kernel types in pmg_bpf.h, so
// one object runs on every supported kernel. The C source is dual licensed
// BSD-2-Clause or GPL-2.0-only, because the kernel admits only a
// GPL-compatible program to bpf_get_current_task_btf. The Go code stays
// Apache-2.0.
package bpf

//go:generate go tool bpf2go -target bpfel -tags linux -type cfg -type dst -type dst_key -type exe_key -type skip4_key -type skip6_key -type event -type exec_event Enforce enforce.bpf.c -- -I. -O2 -g -Wall -Werror
