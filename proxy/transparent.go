package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/safedep/dry/log"
)

// tlsHandshakeRecord is the first byte of a TLS handshake record. No HTTP
// method starts with it, so it cleanly separates a redirected client (which
// speaks TLS immediately) from an explicit proxy client (which sends CONNECT).
const tlsHandshakeRecord = 0x16

// transparentPort is the port used for the synthesised CONNECT. A connect
// rewrite overwrites the destination before the connection is made, so the
// original port is not recoverable here. Only 443 is redirected today.
const transparentPort = 443

// maxConnectResponseBytes bounds how much of the proxy's CONNECT response is
// buffered while looking for its terminator, so a malformed response cannot
// grow the buffer without limit.
const maxConnectResponseBytes = 8 << 10

// defaultSniffTimeout bounds how long a freshly accepted connection may take
// to reveal whether it is HTTP or TLS.
const defaultSniffTimeout = 30 * time.Second

var (
	errSniffOnly = errors.New("proxy: client hello sniff completed")
	errNoSNI     = errors.New("proxy: client hello carries no server name")
)

// transparentListener accepts both explicit proxy clients and redirected
// clients on one listener. A redirected client believes it reached the real
// registry, so it never sends CONNECT. Its destination is recovered from the
// ClientHello's SNI and handed to the proxy handler as a CONNECT request,
// which keeps every downstream decision on the existing code path.
type transparentListener struct {
	net.Listener

	handler      http.Handler
	sniffTimeout time.Duration
}

func newTransparentListener(inner net.Listener, handler http.Handler) net.Listener {
	return &transparentListener{
		Listener:     inner,
		handler:      handler,
		sniffTimeout: defaultSniffTimeout,
	}
}

// Accept returns explicit clients to the http.Server as usual. Redirected
// clients are served on their own goroutine and never returned, because
// http.Server issues a background read while a handler runs and would consume
// the first byte of the replayed ClientHello.
func (l *transparentListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		explicit, redirected, err := l.classify(conn)
		if err != nil {
			log.Debugf("Transparent listener dropped connection from %s: %v", conn.RemoteAddr(), err)
			closeConn(conn)

			continue
		}

		if explicit != nil {
			return explicit, nil
		}

		go l.serveRedirected(redirected)
	}
}

// redirectedConn is an accepted connection whose destination was recovered
// from its ClientHello.
type redirectedConn struct {
	conn *transparentConn
	host string
}

func (l *transparentListener) classify(conn net.Conn) (net.Conn, *redirectedConn, error) {
	if err := conn.SetReadDeadline(time.Now().Add(l.sniffTimeout)); err != nil {
		return nil, nil, fmt.Errorf("failed to set sniff deadline: %w", err)
	}

	buffered := bufio.NewReader(conn)

	first, err := buffered.Peek(1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to peek first byte: %w", err)
	}

	if first[0] != tlsHandshakeRecord {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, nil, fmt.Errorf("failed to clear sniff deadline: %w", err)
		}

		return &bufferedConn{Conn: conn, reader: buffered}, nil, nil
	}

	host, hello, err := sniffServerName(conn, buffered)
	if err != nil {
		return nil, nil, err
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, nil, fmt.Errorf("failed to clear sniff deadline: %w", err)
	}

	replay := &transparentConn{
		Conn: conn,
		body: io.MultiReader(bytes.NewReader(hello), buffered),
	}

	return nil, &redirectedConn{conn: replay, host: host}, nil
}

// serveRedirected drives the proxy handler for a redirected connection by
// synthesising the CONNECT request the client never sent.
func (l *transparentListener) serveRedirected(redirected *redirectedConn) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Panic serving redirected connection: %v", r)
			closeConn(redirected.conn)
		}
	}()

	hostPort := net.JoinHostPort(redirected.host, strconv.Itoa(transparentPort))

	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       hostPort,
		URL:        &url.URL{Host: hostPort},
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RemoteAddr: redirected.conn.RemoteAddr().String(),
		Body:       http.NoBody,
	}

	writer := &hijackWriter{conn: redirected.conn, header: make(http.Header)}

	log.Debugf("Serving redirected connection from %s as CONNECT %s",
		redirected.conn.RemoteAddr(), hostPort)

	l.handler.ServeHTTP(writer, req)

	// The proxy hijacks on the paths that matter and owns the connection from
	// then on. Anything that returns without hijacking has nothing more to say.
	if !writer.hijacked {
		closeConn(redirected.conn)
	}
}

func closeConn(conn net.Conn) {
	if err := conn.Close(); err != nil {
		log.Debugf("Failed to close connection: %v", err)
	}
}

// hijackWriter is the minimal http.ResponseWriter the proxy handler needs. The
// CONNECT path immediately hijacks and writes to the connection directly.
type hijackWriter struct {
	conn     net.Conn
	header   http.Header
	hijacked bool
}

func (w *hijackWriter) Header() http.Header { return w.header }

func (w *hijackWriter) Write(p []byte) (int, error) { return w.conn.Write(p) }

func (w *hijackWriter) WriteHeader(int) {}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

// bufferedConn serves reads from a bufio.Reader so bytes consumed while
// sniffing are not lost. Explicit proxy clients take this path unchanged.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// sniffConn feeds the TLS handshake from src while recording every byte it
// consumes, so the ClientHello can be replayed afterwards. Writes are refused
// to abort the handshake once the server name has been read.
type sniffConn struct {
	net.Conn
	src      io.Reader
	consumed bytes.Buffer
}

func (c *sniffConn) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if n > 0 {
		c.consumed.Write(p[:n])
	}

	return n, err
}

func (c *sniffConn) Write(_ []byte) (int, error) {
	return 0, errSniffOnly
}

// sniffServerName reads just far enough into the TLS handshake to learn the
// requested server name. GetConfigForClient fires after the ClientHello is
// parsed, so returning an error there stops the handshake before anything is
// sent back to the client.
func sniffServerName(conn net.Conn, src io.Reader) (string, []byte, error) {
	sniffer := &sniffConn{Conn: conn, src: src}

	var serverName string
	config := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = hello.ServerName
			return nil, errSniffOnly
		},
	}

	// The handshake is expected to fail, that is how it is stopped. Only treat
	// it as an error when no server name was recovered.
	handshakeErr := tls.Server(sniffer, config).Handshake()
	if serverName == "" {
		return "", nil, fmt.Errorf("%w: %v", errNoSNI, handshakeErr)
	}

	return serverName, sniffer.consumed.Bytes(), nil
}

// transparentConn replays the ClientHello consumed during sniffing and hides
// the CONNECT response from a client that never sent a CONNECT.
type transparentConn struct {
	net.Conn

	body io.Reader

	responseDropped bool
	pending         bytes.Buffer
}

func (c *transparentConn) Read(p []byte) (int, error) {
	return c.body.Read(p)
}

// Write drops the proxy's response to the synthetic CONNECT. The client is
// mid TLS handshake and expects a ServerHello, so those bytes would be read
// as a malformed TLS record and kill the connection. Everything after the
// response terminator is the real handshake and passes straight through.
func (c *transparentConn) Write(p []byte) (int, error) {
	if c.responseDropped {
		return c.Conn.Write(p)
	}

	c.pending.Write(p)

	terminator := bytes.Index(c.pending.Bytes(), []byte("\r\n\r\n"))
	if terminator < 0 {
		if c.pending.Len() > maxConnectResponseBytes {
			return 0, errors.New("proxy: CONNECT response exceeded buffer before terminator")
		}

		return len(p), nil
	}

	c.responseDropped = true

	remainder := bytes.Clone(c.pending.Bytes()[terminator+4:])
	c.pending.Reset()

	if len(remainder) > 0 {
		if _, err := c.Conn.Write(remainder); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}
