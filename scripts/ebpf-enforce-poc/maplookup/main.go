// Unprivileged reader: open a pinned map read-only and iterate it.
package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

func main() {
	m, err := ebpf.LoadPinnedMap(os.Args[1], &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		fmt.Println("open pinned map failed:", err)
		os.Exit(1)
	}
	defer m.Close()
	var k uint32
	var v [8]byte
	n := 0
	it := m.Iterate()
	for it.Next(&k, &v) {
		n++
	}
	fmt.Printf("uid=%d opened pinned map %s type=%s entries=%d iterate_err=%v\n", os.Getuid(), os.Args[1], m.Type(), n, it.Err())
}
