# Throwaway POC. Needs root, clang, a kernel with BTF and cgroup v2.
# Run with GOWORK=off: this module is not part of the repo go.work on purpose.
LIBBPF_VER ?= v1.5.0
BPFTOOL_VER ?= v7.5.0
HDR := hdr/bpf/bpf_helpers.h hdr/bpf/bpf_helper_defs.h hdr/bpf/bpf_core_read.h hdr/bpf/bpf_endian.h hdr/bpf/bpf_tracing.h

all: pmgpoc maplookup/maplookup bpf/redirect.bpf.o

hdr/bpf/%.h:
	mkdir -p hdr/bpf
	curl -fsSL -o $@ https://raw.githubusercontent.com/libbpf/libbpf/$(LIBBPF_VER)/src/$*.h

bpftool:
	curl -fsSL -o bpftool.tgz https://github.com/libbpf/bpftool/releases/download/$(BPFTOOL_VER)/bpftool-$(BPFTOOL_VER)-amd64.tar.gz
	tar xzf bpftool.tgz bpftool && chmod +x bpftool

hdr/vmlinux.h: bpftool
	./bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf/redirect.bpf.o: bpf/redirect.bpf.c hdr/vmlinux.h $(HDR)
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I hdr -c $< -o $@

pmgpoc: main.go go.mod
	GOWORK=off go build -o $@ .

maplookup/maplookup: maplookup/main.go
	GOWORK=off go build -o $@ ./maplookup

clean:
	rm -rf hdr bpf/*.o pmgpoc maplookup/maplookup bpftool bpftool.tgz poc-ca.pem poc.log

.PHONY: all clean
