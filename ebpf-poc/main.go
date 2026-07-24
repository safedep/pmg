//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf connect.c -- -I/usr/include/aarch64-linux-gnu

package main

func main() {
	// err := rlimit.RemoveMemlock()
	// if err != nil {
	// 	fmt.Printf("Failed to remove mem lock: %v\n", err)
	// 	return
	// }

	// var objs bpfObjects
	// err = loadBpfObjects(&objs, nil)
	// if err != nil {
	// 	fmt.Printf("Failed to load bpf objects: %v\n", err)
	// 	return
	// }

	// defer objs.Close()

	// rootCgroup := "/sys/fs/cgroup"

	// l, err := link.AttachCgroup(link.CgroupOptions{
	// 	Path:    rootCgroup,
	// 	Attach:  ebpf.AttachCGroupInet4Connect,
	// 	Program: objs.Connect4,
	// })
	// if err != nil {
	// 	fmt.Printf("Failed to attach cgroup: %v\n", err)
	// 	return
	// }
	// defer l.Close()

	// rd, err := ringbuf.NewReader(objs.Events)
	// if err != nil {
	// 	fmt.Printf("Failed to create ringbuf reader: %v\n", err)
	// 	return
	// }
	// defer rd.Close()

	// ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// defer stop() // Cleans up resources allocated by the signal package

	// fmt.Println("Application started. Press Ctrl+C to exit.")

	// go func() {
	// 	<-ctx.Done()
	// 	fmt.Println("\nSignal received, detaching and cleaning up...")
	// 	rd.Close()
	// }()

	// var e bpfEvent
	// for {
	// 	rec, err := rd.Read()
	// 	if err != nil {
	// 		if errors.Is(err, ringbuf.ErrClosed) {
	// 			return
	// 		}
	// 		fmt.Printf("failed to read raw event: %v\n", err)
	// 		continue
	// 	}

	// 	err = binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e)
	// 	if err != nil {
	// 		fmt.Printf("failed to read event: %v\n", err)
	// 		continue
	// 	}

	// 	ip := make(net.IP, 4)
	// 	binary.LittleEndian.PutUint32(ip, e.Daddr)

	// 	name := e.Comm[:]
	// 	if i := bytes.IndexByte(name, 0); i != -1 {
	// 		name = name[:i] // keep bytes before the first NUL
	// 	}
	// 	comm := string(name)

	// 	proto := ""
	// 	switch e.Proto {
	// 	case syscall.IPPROTO_TCP:
	// 		proto = "TCP"
	// 	case syscall.IPPROTO_UDP:
	// 		proto = "UDP"
	// 	}

	// 	fmt.Println()
	// 	fmt.Printf("PID: %v\nUID: %v\ndAddr: %v\ndPort: %v\nProto: %v\nCommand: %v\n", e.Pid, e.Uid, ip, e.Dport, proto, comm)
	// }
}
