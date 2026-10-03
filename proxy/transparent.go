package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/safedep/dry/log"
)

// OriginalDestinationResolver returns where a redirected client wanted to
// connect, keyed by the client's address and source port. The kernel
// enforcement layer implements it. The proxy only consumes it.
type OriginalDestinationResolver interface {
	OriginalDestination(client netip.AddrPort) (netip.AddrPort, bool)
}

const (
	// sniffTimeout bounds how long a redirected client may stay silent before
	// it sends its first bytes. A TLS client sends the ClientHello at once.
	sniffTimeout = 10 * time.Second

	// maxClientHello bounds the bytes the sniffer peeks for one ClientHello.
	// A record carries at most 16 KiB, and a ClientHello that needs more
	// than four records is not one a package manager sends.
	maxClientHello = 64 * 1024

	// tlsHandshakeClientHello is the handshake message type of a ClientHello.
	tlsHandshakeClientHello = 0x01
)

type originalDestinationKey struct{}

// transparentConn carries the recovered original destination from the
// listener to the request handler through http.Server.ConnContext.
type transparentConn struct {
	net.Conn
	r    *bufio.Reader
	orig netip.AddrPort
}

func (c *transparentConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// transparentListener accepts redirected and proxy-aware clients on one
// port. It sniffs the first bytes of each connection. Proxy requests and
// plain HTTP go to the http.Server unchanged. TLS to a registry host is
// terminated with the certificate manager so the request lands in the
// server too. Every other TLS connection is spliced to its destination.
type transparentListener struct {
	net.Listener
	ps *proxyServer

	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
	err    error
	errMu  sync.Mutex
}

func newTransparentListener(inner net.Listener, ps *proxyServer) *transparentListener {
	l := &transparentListener{
		Listener: inner,
		ps:       ps,
		conns:    make(chan net.Conn),
		closed:   make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *transparentListener) acceptLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.errMu.Lock()
			l.err = err
			l.errMu.Unlock()
			l.once.Do(func() { close(l.closed) })
			return
		}
		go l.classify(conn)
	}
}

// Accept returns the next connection the http.Server should serve. The sniff
// runs in a goroutine per connection, so a silent client never blocks the
// others.
func (l *transparentListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		l.errMu.Lock()
		defer l.errMu.Unlock()
		if l.err != nil {
			return nil, l.err
		}
		return nil, net.ErrClosed
	}
}

func (l *transparentListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func (l *transparentListener) deliver(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.closed:
		if err := c.Close(); err != nil {
			log.Debugf("transparent: close after listener shutdown: %v", err)
		}
	}
}

func (l *transparentListener) classify(raw net.Conn) {
	tc := &transparentConn{Conn: raw, r: bufio.NewReaderSize(raw, maxClientHello)}
	tc.orig = l.ps.lookupOriginalDestination(raw)

	if err := raw.SetReadDeadline(time.Now().Add(sniffTimeout)); err != nil {
		l.drop(raw, "set sniff deadline", err)
		return
	}

	first, err := tc.r.Peek(1)
	if err != nil {
		l.drop(raw, "peek first byte", err)
		return
	}

	if first[0] == tlsHandshakeRecord {
		l.classifyTLS(tc)
		return
	}
	if err := raw.SetReadDeadline(time.Time{}); err != nil {
		l.drop(raw, "clear sniff deadline", err)
		return
	}

	// Plain HTTP. A proxy-aware client sends CONNECT or an absolute URI, and
	// goproxy handles both. A redirected client sends an origin-form request,
	// which lands in the NonproxyHandler.
	l.deliver(tc)
}

const tlsHandshakeRecord = 0x16

func (l *transparentListener) classifyTLS(tc *transparentConn) {
	hello, err := peekClientHello(tc.r)
	if err != nil {
		l.drop(tc.Conn, "peek ClientHello", err)
		return
	}
	if err := tc.SetReadDeadline(time.Time{}); err != nil {
		l.drop(tc.Conn, "clear sniff deadline", err)
		return
	}

	// Without a name the interceptors cannot decide, so the connection must
	// not be spliced: a client could reach a registry by IP without analysis.
	// The same holds for Encrypted ClientHello, whose outer name is a decoy.
	// A destination that must stay reachable this way belongs in the skip
	// list, where the kernel never redirects it.
	sni, ech := clientHelloServerName(hello)
	if sni == "" || ech {
		log.Warnf("transparent: dropping TLS connection from %s to %s: no server name to decide on (ech=%t)",
			tc.RemoteAddr(), tc.orig, ech)
		l.drop(tc.Conn, "TLS without a server name", io.EOF)
		return
	}

	host, port := l.ps.transparentTarget(sni, tc.orig, 443)
	if l.ps.shouldMITM(net.JoinHostPort(host, strconv.Itoa(int(port))), "transparent TLS") {
		tlsConfig, err := l.ps.config.CertManager.GetTLSConfig(host)
		if err != nil {
			l.drop(tc.Conn, fmt.Sprintf("certificate for %s", host), err)
			return
		}
		l.deliver(tls.Server(tc, tlsConfig))
		return
	}

	go l.ps.splice(tc, host, port)
}

func (l *transparentListener) drop(c net.Conn, what string, err error) {
	if !errors.Is(err, io.EOF) {
		log.Debugf("transparent: %s from %s: %v", what, c.RemoteAddr(), err)
	}
	if cerr := c.Close(); cerr != nil {
		log.Debugf("transparent: close %s: %v", c.RemoteAddr(), cerr)
	}
}

// lookupOriginalDestination asks the resolver where the client wanted to
// go. A miss is normal for a proxy-aware client, which was never redirected.
func (ps *proxyServer) lookupOriginalDestination(c net.Conn) netip.AddrPort {
	if ps.config.OriginalDestination == nil {
		return netip.AddrPort{}
	}
	peer, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	orig, found := ps.config.OriginalDestination.OriginalDestination(peer.AddrPort())
	if !found {
		return netip.AddrPort{}
	}
	return orig
}

// transparentTarget pairs the name the client sent with the port it
// connected to. The interceptors match registry names, so the name decides.
// The original destination supplies the port, because the name does not
// carry one. defaultPort applies when the kernel entry is gone.
func (ps *proxyServer) transparentTarget(name string, orig netip.AddrPort, defaultPort uint16) (string, uint16) {
	port := defaultPort
	if orig.IsValid() {
		port = orig.Port()
	}
	return name, port
}

// splice copies bytes between a redirected client and its real destination.
// The dial goes through the same ConnectDial as a CONNECT tunnel, so an
// upstream corporate proxy applies here too.
func (ps *proxyServer) splice(client *transparentConn, host string, port uint16) {
	defer func() {
		if err := client.Close(); err != nil {
			log.Debugf("transparent: close client %s: %v", client.RemoteAddr(), err)
		}
	}()

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upstream, err := ps.proxy.ConnectDial("tcp", addr)
	if err != nil {
		log.Warnf("transparent: dial %s for %s failed: %v", addr, client.RemoteAddr(), err)
		return
	}
	defer func() {
		if err := upstream.Close(); err != nil {
			log.Debugf("transparent: close upstream %s: %v", addr, err)
		}
	}()

	log.Debugf("transparent: splicing %s to %s", client.RemoteAddr(), addr)

	done := make(chan struct{}, 2)
	copyHalf := func(dst io.Writer, src io.Reader, halfClose func()) {
		if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debugf("transparent: splice %s: %v", addr, err)
		}
		halfClose()
		done <- struct{}{}
	}
	go copyHalf(upstream, client, func() { closeWrite(upstream) })
	go copyHalf(client, upstream, func() { closeWrite(client.Conn) })
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debugf("transparent: half-close %s: %v", c.RemoteAddr(), err)
		}
	}
}

// transparentConnContext stores the original destination for the requests
// that arrive on a redirected connection. A TLS connection hides the
// transparentConn one level down.
func transparentConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	tc, ok := c.(*transparentConn)
	if !ok || !tc.orig.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, originalDestinationKey{}, tc.orig)
}

func originalDestinationFromContext(ctx context.Context) (netip.AddrPort, bool) {
	orig, ok := ctx.Value(originalDestinationKey{}).(netip.AddrPort)
	return orig, ok
}

// serveTransparentRequest handles an origin-form request from a redirected
// client. It rebuilds the absolute URL the interceptors need and hands the
// request back to goproxy, so the interceptors, the block rendering and the
// upstream retries run unchanged. The Host header names the registry. A
// request without one is refused: the interceptors match names, and an IP
// would pass a registry without analysis. The original destination supplies
// the port when the Host header carries none.
func (ps *proxyServer) serveTransparentRequest(w http.ResponseWriter, req *http.Request) {
	if !ps.config.Transparent {
		http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", http.StatusInternalServerError)
		return
	}

	scheme := "http"
	defaultPort := uint16(80)
	if req.TLS != nil {
		scheme = "https"
		defaultPort = 443
	}

	if req.Host == "" {
		http.Error(w, "PMG proxy: a redirected request needs a Host header", http.StatusBadRequest)
		return
	}
	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		orig, _ := originalDestinationFromContext(req.Context())
		_, port := ps.transparentTarget(host, orig, defaultPort)
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}

	// The kernel never redirects a loopback destination, so a redirected
	// request cannot legitimately name the proxy. A request that does would
	// make the proxy forward to itself without limit.
	if ps.targetsSelf(host) {
		http.Error(w, "PMG proxy: a redirected request cannot target the proxy itself", http.StatusBadRequest)
		return
	}

	req.URL.Scheme = scheme
	req.URL.Host = host
	req.RequestURI = ""
	ps.proxy.ServeHTTP(w, req)
}

// targetsSelf reports whether host:port is loopback or one of the proxy's
// own listeners.
func (ps *proxyServer) targetsSelf(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if addr.Unmap().IsLoopback() {
		return true
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return false
	}
	return ps.isOwnAddress(netip.AddrPortFrom(addr.Unmap(), uint16(p)))
}

// peekClientHello returns every record of the ClientHello without consuming
// them. A handshake message may span several records. A parser that saw
// only the first would miss the SNI, and the connection would be spliced
// past the interceptors. The handshake header in the first record gives
// the message length, and the peek grows record by record until the
// records hold it.
func peekClientHello(r *bufio.Reader) ([]byte, error) {
	head, err := r.Peek(9)
	if err != nil {
		return nil, err
	}
	if head[5] != tlsHandshakeClientHello {
		return nil, fmt.Errorf("TLS handshake type %#x is not a ClientHello", head[5])
	}
	need := 4 + (int(head[6])<<16 | int(head[7])<<8 | int(head[8]))

	total, have := 0, 0
	for have < need {
		buf, err := r.Peek(total + 5)
		if err != nil {
			return nil, err
		}
		record := buf[total:]
		if record[0] != tlsHandshakeRecord {
			return nil, fmt.Errorf("TLS record type %#x inside the ClientHello", record[0])
		}
		n := int(record[3])<<8 | int(record[4])
		total += 5 + n
		have += n
		if total > maxClientHello {
			return nil, fmt.Errorf("ClientHello of %d bytes exceeds %d", total, maxClientHello)
		}
	}
	return r.Peek(total)
}

// extensionEncryptedClientHello is the TLS extension id of ECH. The outer
// ClientHello then carries a public name, not the real one.
const extensionEncryptedClientHello = 0xfe0d

// clientHelloServerName extracts the SNI from a raw ClientHello and reports
// whether the hello carries Encrypted ClientHello. It drives crypto/tls over
// the bytes and stops the handshake in GetConfigForClient, which runs before
// the version is negotiated, so there is no second parser to maintain and no
// protocol version to accept. An empty name means the client sent no SNI,
// or the bytes are not a ClientHello.
func clientHelloServerName(record []byte) (string, bool) {
	var serverName string
	var ech bool
	conn := tls.Server(readOnlyConn{r: bytes.NewReader(record)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = hello.ServerName
			ech = slices.Contains(hello.Extensions, uint16(extensionEncryptedClientHello))
			return nil, errStopHandshake
		},
	})
	if err := conn.Handshake(); err != nil && !errors.Is(err, errStopHandshake) {
		log.Debugf("transparent: ClientHello parse: %v", err)
	}
	return serverName, ech
}

var errStopHandshake = errors.New("stop after ClientHello")

// readOnlyConn feeds recorded bytes to crypto/tls and swallows its writes.
type readOnlyConn struct {
	r io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (c readOnlyConn) Close() error                     { return nil }
func (c readOnlyConn) LocalAddr() net.Addr              { return nil }
func (c readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (c readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
