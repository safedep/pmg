// POC loader for docs/specs/2026-10-03-ebpf-proxy-enforcement-design.md.
// This code is throwaway. It attaches the connect4/sockops programs to a cgroup, publishes the
// proxy address and exemptions, and runs a transparent listener that recovers
// the original destination, sniffs TLS vs plain HTTP, terminates TLS with a
// per-SNI certificate from a POC CA, and answers every request.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type cfg struct {
	ProxyIP4    uint32
	ProxyPort   uint16
	_           uint16
	NetnsCookie uint64
	CtrIP4      uint32
	_           uint32
}

type exeKey struct {
	Dev uint64
	Ino uint64
}

type dst struct {
	IP4  uint32
	Port uint16
	_    uint16
}

type event struct {
	Tgid    uint32
	UID     uint32
	DstIP4  uint32
	DstPort uint16
	Action  uint8
	_       uint8
	ExeDev  uint64
	ExeIno  uint64
	Comm    [16]byte
}

var actionNames = map[uint8]string{1: "EXEMPT-PID", 2: "EXEMPT-EXE", 3: "EXEMPT-UID", 4: "REDIRECT", 5: "DENY-UDP", 6: "OTHER-NETNS", 7: "REDIRECT-CTR"}

var certsForCtr *certCache

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	var (
		cgroupPath = flag.String("cgroup", "/sys/fs/cgroup/unified", "cgroup v2 path to attach to")
		listen     = flag.String("listen", "127.0.0.1:0", "transparent listener address")
		obj        = flag.String("obj", "bpf/redirect.bpf.o", "compiled BPF object")
		caOut      = flag.String("ca-out", "poc-ca.pem", "where to write the POC CA cert")
		exemptExe  stringList
		exemptPid  stringList
		exemptUID  stringList
		pinDir     = flag.String("pin-dir", "", "pin orig_dst_by_sport map under this bpffs dir (mode 0644)")
		ctrIP      = flag.String("container-target", "", "redirect other netns to this host IPv4 (e.g. docker0 address)")
	)
	flag.Var(&exemptExe, "exempt-exe", "executable path to exempt (repeatable)")
	flag.Var(&exemptPid, "exempt-pid", "pid to exempt (repeatable)")
	flag.Var(&exemptUID, "exempt-uid", "uid to exempt (repeatable)")
	flag.Parse()

	if err := run(*cgroupPath, *listen, *obj, *caOut, *pinDir, *ctrIP, exemptExe, exemptPid, exemptUID); err != nil {
		log.Fatal(err)
	}
}

func run(cgroupPath, listen, obj, caOut, pinDir, ctrIP string, exemptExe, exemptPid, exemptUID []string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("verifier: %+v", ve)
		}
		return fmt.Errorf("new collection: %w", err)
	}
	defer coll.Close()

	ca, caKey, err := newCA()
	if err != nil {
		return err
	}
	if err := os.WriteFile(caOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		return err
	}

	certsForCtr = &certCache{ca: ca, caKey: caKey, m: map[string]*tls.Certificate{}}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	addr := ln.Addr().(*net.TCPAddr)
	log.Printf("transparent listener on %s", addr)

	// Publish config and exemptions BEFORE attaching so there is no window
	// where an eligible connect sees a half-configured policy.
	var ipb [4]byte
	copy(ipb[:], addr.IP.To4())
	var portb [2]byte
	binary.BigEndian.PutUint16(portb[:], uint16(addr.Port))
	cookie, err := netnsCookie(ln)
	if err != nil {
		return err
	}
	log.Printf("proxy netns cookie %d", cookie)
	c := cfg{ProxyIP4: binary.LittleEndian.Uint32(ipb[:]), ProxyPort: binary.LittleEndian.Uint16(portb[:]), NetnsCookie: cookie}
	if ctrIP != "" {
		c.CtrIP4 = binary.LittleEndian.Uint32(net.ParseIP(ctrIP).To4())
		ctrLn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ctrIP, addr.Port))
		if err != nil {
			return err
		}
		log.Printf("container listener on %s", ctrLn.Addr())
		go func() {
			for {
				conn, err := ctrLn.Accept()
				if err != nil {
					return
				}
				go handle(conn, coll.Maps["orig_dst_by_sport"], certsForCtr)
			}
		}()
	}
	if err := coll.Maps["pmg_cfg"].Put(uint32(0), c); err != nil {
		return err
	}
	for _, p := range []uint16{80, 443} {
		if err := coll.Maps["redirect_ports"].Put(p, uint8(1)); err != nil {
			return err
		}
	}
	self := uint32(os.Getpid())
	if err := coll.Maps["exempt_tgid"].Put(self, uint8(1)); err != nil {
		return err
	}
	for _, s := range exemptPid {
		p, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		if err := coll.Maps["exempt_tgid"].Put(uint32(p), uint8(1)); err != nil {
			return err
		}
	}
	for _, s := range exemptUID {
		u, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		if err := coll.Maps["exempt_uid"].Put(uint32(u), uint8(1)); err != nil {
			return err
		}
	}
	for _, p := range exemptExe {
		k, err := exeKeyFor(p)
		if err != nil {
			return err
		}
		log.Printf("exempt exe %s dev=%d ino=%d", p, k.Dev, k.Ino)
		if err := coll.Maps["exempt_exe"].Put(k, uint8(1)); err != nil {
			return err
		}
	}

	if pinDir != "" {
		if err := os.MkdirAll(pinDir, 0o755); err != nil {
			return err
		}
		pin := pinDir + "/orig_dst"
		_ = os.Remove(pin)
		if err := coll.Maps["orig_dst_by_sport"].Pin(pin); err != nil {
			return fmt.Errorf("pin: %w", err)
		}
		if err := os.Chmod(pin, 0o644); err != nil {
			return err
		}
		log.Printf("pinned orig_dst_by_sport at %s", pin)
	}
	l3, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: ebpf.AttachCGroupUDP4Sendmsg, Program: coll.Programs["pmg_sendmsg4"]})
	if err != nil {
		return fmt.Errorf("attach sendmsg4: %w", err)
	}
	defer l3.Close()
	l1, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: ebpf.AttachCGroupInet4Connect, Program: coll.Programs["pmg_connect4"]})
	if err != nil {
		return fmt.Errorf("attach connect4: %w", err)
	}
	defer l1.Close()
	l2, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: ebpf.AttachCGroupSockOps, Program: coll.Programs["pmg_sockops"]})
	if err != nil {
		return fmt.Errorf("attach sockops: %w", err)
	}
	defer l2.Close()
	log.Printf("attached connect4+sockops to %s (self pid %d exempt)", cgroupPath, self)

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return err
	}
	defer rd.Close()
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}
			var e event
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
				continue
			}
			comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
			log.Printf("[bpf] %-10s tgid=%d uid=%d comm=%s dst=%s:%d exe=dev:%d/ino:%d",
				actionNames[e.Action], e.Tgid, e.UID, comm, ip4(e.DstIP4), e.DstPort, e.ExeDev, e.ExeIno)
		}
	}()

	origDst := coll.Maps["orig_dst_by_sport"]
	certs := certsForCtr

	sig := make(chan os.Signal, 1)
	signalNotify(sig)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn, origDst, certs)
		}
	}()
	<-sig
	return nil
}

func handle(conn net.Conn, origDst *ebpf.Map, certs *certCache) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	sport := uint32(conn.RemoteAddr().(*net.TCPAddr).Port)
	var d dst
	orig := "unknown"
	if err := origDst.Lookup(sport, &d); err == nil {
		orig = fmt.Sprintf("%s:%d", ip4(d.IP4), ntohs(d.Port))
		_ = origDst.Delete(sport)
	}

	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	var rw net.Conn = &peekedConn{Conn: conn, r: br}
	kind := "http"
	sni := ""
	if first[0] == 0x16 {
		kind = "tls"
		tc := tls.Server(rw, &tls.Config{
			NextProtos: []string{"http/1.1"},
			GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sni = h.ServerName
				return certs.get(h.ServerName)
			},
		})
		if err := tc.Handshake(); err != nil {
			log.Printf("[proxy] tls handshake from :%d orig=%s sni=%q failed: %v", sport, orig, sni, err)
			return
		}
		rw = tc
		br = bufio.NewReader(tc)
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("[proxy] read request (%s) orig=%s: %v", kind, orig, err)
		return
	}
	log.Printf("[proxy] %s peer=%s orig_dst=%s sni=%q host=%q %s %s", kind, conn.RemoteAddr(), orig, sni, req.Host, req.Method, req.URL.Path)

	body := fmt.Sprintf("intercepted-by-pmg-poc kind=%s orig_dst=%s sni=%s host=%s path=%s\n", kind, orig, sni, req.Host, req.URL.Path)
	resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": {"text/plain"}, "Connection": {"close"}}, ContentLength: int64(len(body)), Body: nopCloser{strings.NewReader(body)}, Close: true}
	_ = resp.Write(rw)
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }

type certCache struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	mu    sync.Mutex
	m     map[string]*tls.Certificate
}

func (c *certCache) get(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if host == "" {
		host = "unknown.invalid"
	}
	if cert, ok := c.m[host]; ok {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, c.ca.Raw}, PrivateKey: key}
	c.m[host] = cert
	return cert, nil
}

func newCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PMG POC CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// exeKeyFor converts userspace st_dev (new_encode_dev layout) to the kernel
// dev_t layout MKDEV(major, minor) = major<<20 | minor used by sb->s_dev.
func exeKeyFor(path string) (exeKey, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return exeKey{}, fmt.Errorf("stat %s: %w", path, err)
	}
	maj := unix.Major(st.Dev)
	min := unix.Minor(st.Dev)
	return exeKey{Dev: uint64(maj)<<20 | uint64(min), Ino: st.Ino}, nil
}

func ip4(v uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IP(b)
}

func ntohs(v uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(&v))
	return binary.BigEndian.Uint16(b[:])
}

// netnsCookie returns the kernel's cookie for the listener's network namespace
// (SO_NETNS_COOKIE, Linux 5.14+).
func netnsCookie(ln net.Listener) (uint64, error) {
	raw, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		return 0, err
	}
	var cookie uint64
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cookie, gerr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	}); err != nil {
		return 0, err
	}
	return cookie, gerr
}

func signalNotify(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}
