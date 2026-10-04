// Throwaway POC for the TPROXY alternative to the container redirect spec.
// See README.md. Delete it when a design lands.
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
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

func main() {
	mode := flag.String("mode", "proxy", "proxy | origin | origin-plain")
	listen := flag.String("listen", "127.0.0.1:18443", "listen address")
	certOut := flag.String("cert-out", "", "origin: write the self-signed certificate PEM here")
	keypair := flag.String("keypair", "", "origin: reuse the certificate and key in this PEM file, create it when absent")
	flag.Parse()

	switch *mode {
	case "proxy":
		runProxy(*listen)
	case "origin":
		runOrigin(*listen, *certOut, *keypair, true)
	case "origin-plain":
		runOrigin(*listen, "", "", false)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

// runProxy listens with IP_TRANSPARENT so TPROXY can steer connections to
// it without rewriting them. A steered connection's LocalAddr is the
// client's original destination. The proxy logs it, sniffs the server name
// or Host, and splices to the original destination, so the client sees the
// real server end to end.
func runProxy(listen string) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	ln, err := lc.Listen(nil, "tcp", listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("proxy listening on %s with IP_TRANSPARENT", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go handle(conn, ln.Addr().String())
	}
}

func handle(conn net.Conn, own string) {
	defer conn.Close()
	local := conn.LocalAddr().String()
	steered := local != own
	if od := originalDst(conn); od != "" && od != local {
		local, steered = od, true
	}
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		log.Printf("conn remote=%s local=%s steered=%v peek: %v", conn.RemoteAddr(), local, steered, err)
		return
	}
	var name string
	if first[0] == 0x16 {
		name = sniFrom(br)
		log.Printf("TLS  remote=%s origdst=%s steered=%v sni=%q", conn.RemoteAddr(), local, steered, name)
	} else {
		name = hostFrom(br)
		log.Printf("HTTP remote=%s origdst=%s steered=%v host=%q", conn.RemoteAddr(), local, steered, name)
	}
	if !steered {
		fmt.Fprint(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nnot a steered connection\n")
		return
	}
	up, err := net.DialTimeout("tcp", local, 5*time.Second)
	if err != nil {
		log.Printf("dial origdst %s: %v", local, err)
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
	<-done
}

// originalDst asks conntrack for the destination before DNAT. It returns
// "" when the connection was not translated. This is the SO_ORIGINAL_DST
// path that the redirect mode uses in place of IP_TRANSPARENT.
func originalDst(conn net.Conn) string {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return ""
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return ""
	}
	var out string
	_ = rc.Control(func(fd uintptr) {
		const soOriginalDst = 80
		m, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, soOriginalDst)
		if err != nil {
			return
		}
		port := int(m.Multiaddr[2])<<8 | int(m.Multiaddr[3])
		out = fmt.Sprintf("%d.%d.%d.%d:%d", m.Multiaddr[4], m.Multiaddr[5], m.Multiaddr[6], m.Multiaddr[7], port)
	})
	return out
}

// sniFrom reads the ClientHello server name without consuming it.
func sniFrom(br *bufio.Reader) string {
	hdr, err := br.Peek(5)
	if err != nil {
		return ""
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	rec, err := br.Peek(5 + n)
	if err != nil {
		return ""
	}
	var name string
	_ = tls.Server(readOnlyConn{bytes.NewReader(rec)}, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name = h.ServerName
		return nil, fmt.Errorf("sniffed")
	}}).Handshake()
	return name
}

type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (c readOnlyConn) Close() error                     { return nil }
func (c readOnlyConn) LocalAddr() net.Addr              { return nil }
func (c readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (c readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

func hostFrom(br *bufio.Reader) string {
	buf, _ := br.Peek(br.Buffered())
	if len(buf) < 4 {
		buf, _ = br.Peek(2048)
	}
	for _, line := range strings.Split(string(buf), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

// runOrigin plays the external server. It answers every request with a line
// that names the server name and the port the request came in on, so a
// test can prove the destination survived the path.
func runOrigin(listen, certOut, keypair string, useTLS bool) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sni := ""
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		fmt.Fprintf(w, "origin ok listen=%s host=%s sni=%s path=%s\n", listen, r.Host, sni, r.URL.Path)
	})
	srv := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	if !useTLS {
		log.Printf("plain origin on %s", listen)
		log.Fatal(srv.ListenAndServe())
	}
	cert, certPEM := loadOrCreateKeypair(keypair)
	if certOut != "" {
		if err := os.WriteFile(certOut, certPEM, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	log.Printf("TLS origin on %s", listen)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func loadOrCreateKeypair(path string) (tls.Certificate, []byte) {
	if path == "" {
		cert, certPEM, _ := selfSigned()
		return cert, certPEM
	}
	if data, err := os.ReadFile(path); err == nil {
		cert, err := tls.X509KeyPair(data, data)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(data)
		return cert, pem.EncodeToMemory(block)
	}
	cert, certPEM, keyPEM := selfSigned()
	if err := os.WriteFile(path, append(certPEM, keyPEM...), 0o600); err != nil {
		log.Fatal(err)
	}
	return cert, certPEM
}

func selfSigned() (tls.Certificate, []byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tproxy-poc origin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"origin.poc", "registry.poc", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("10.99.0.2"), net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return cert, certPEM, keyPEM
}
