module ebpf-poc

go 1.25.1

require github.com/cilium/ebpf v0.22.0

require (
	github.com/safedep/dry v0.0.0-20260716095238-84cd2b3cd3a4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

require github.com/safedep/pmg v0.0.0

replace github.com/safedep/pmg => ..
