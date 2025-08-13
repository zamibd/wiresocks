package http

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/shahradelahi/wiresocks/log"
	"github.com/shahradelahi/wiresocks/proxy/statute"
)

const (
	// Default ports
	defaultHTTPPort  = "80"
	defaultHTTPSPort = "443"

	// HTTP headers
	connectionHeader      = "Connection"
	upgradeHeader         = "Upgrade"
	capsuleProtocolHeader = "Capsule-Protocol"

	// HTTP header values
	connectIP = "connect-ip"
	upgrade   = "upgrade"

	// HTTP responses
	httpConnectionEstablished = "HTTP/1.1 200 Connection Established" + CRLF + CRLF
	httpSwitchingProtocols    = "HTTP/1.1 101 Switching Protocols" + CRLF +
		"Connection: Upgrade" + CRLF +
		"Upgrade: connect-ip" + CRLF +
		"Capsule-Protocol: ?1" + CRLF + CRLF
)

type Server struct {
	// Bind is the address to listen on
	Bind string

	Listener net.Listener

	// ProxyDial specifies the optional proxyDial function for
	// establishing the transport connection.
	ProxyDial statute.ProxyDialFunc
	// UserConnectHandle gives the user control to handle the TCP CONNECT requests
	UserConnectHandle statute.UserConnectHandler
	// Context is default context
	Context context.Context
	// BytesPool getting and returning temporary bytes for use by io.CopyBuffer
	BytesPool statute.BytesPool
}

func NewServer(options ...ServerOption) *Server {
	s := &Server{
		Bind:      statute.DefaultBindAddress,
		ProxyDial: statute.DefaultProxyDial(),
		Context:   statute.DefaultContext(),
	}

	for _, option := range options {
		option(s)
	}

	return s
}

func (s *Server) ListenAndServe() error {
	// Create a new listener
	if s.Listener == nil {
		ln, err := net.Listen("tcp", s.Bind)
		if err != nil {
			return err // Return error if binding was unsuccessful
		}
		s.Listener = ln
	}

	s.Bind = s.Listener.Addr().(*net.TCPAddr).String()

	// ensure listener will be closed
	defer func() {
		_ = s.Listener.Close()
	}()

	log.Infof("HTTP proxy server listening on %s", s.Bind)

	// Create a cancelable context based on s.Context
	ctx, cancel := context.WithCancel(s.Context)
	defer cancel() // Ensure resources are cleaned up

	// Start to accept connections and serve them
	for {
		select {
		case <-ctx.Done():
			log.Infof("HTTP proxy server shutting down: %v", ctx.Err())
			return ctx.Err()
		default:
			conn, err := s.Listener.Accept()
			if err != nil {
				log.Errorf("Failed to accept incoming HTTP connection: %v", err)
				continue
			}
			log.Debugf("Accepted new HTTP connection from %s", conn.RemoteAddr())

			// Start a new goroutine to handle each connection
			// This way, the server can handle multiple connections concurrently
			go func() {
				defer func() {
					log.Debugf("Closing HTTP connection from %s", conn.RemoteAddr())
					_ = conn.Close()
				}()
				err := s.ServeConn(conn)
				if err != nil && err != io.EOF {
					log.Errorf("Error serving HTTP connection from %s: %v", conn.RemoteAddr(), err)
				}
			}()
		}
	}
}

func (s *Server) ServeConn(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err == io.EOF {
			log.Debugf("HTTP connection closed by client: %v", err)
			return nil
		}
		log.Errorf("Failed to read HTTP request from %s: %v", conn.RemoteAddr(), err)
		return err
	}

	log.Debugf("Received HTTP request: Method=%s, Host=%s, URL=%s from %s", req.Method, req.Host, req.URL.String(), conn.RemoteAddr())

	// Handle IP proxying requests (RFC 9484)
	if req.Method == http.MethodGet &&
		strings.EqualFold(req.Header.Get(connectionHeader), upgrade) &&
		strings.EqualFold(req.Header.Get(upgradeHeader), connectIP) {
		log.Infof("Handling IP proxying request from %s to %s", conn.RemoteAddr(), req.URL.String())
		return s.handleIPProxy(conn, req)
	}

	// Handle standard HTTP proxy requests
	log.Infof("Handling standard HTTP proxy request from %s: Method=%s, Host=%s", conn.RemoteAddr(), req.Method, req.URL.Host)
	return s.handleHTTP(conn, req, req.Method == http.MethodConnect)
}

// handleIPProxy handles IP proxying over HTTP (RFC 9484).
func (s *Server) handleIPProxy(conn net.Conn, req *http.Request) error {
	// As per RFC 9484, the "Capsule-Protocol" header must be present.
	if req.Header.Get(capsuleProtocolHeader) != "?1" {
		log.Warnf("Missing or invalid Capsule-Protocol header from %s. Value: %s", conn.RemoteAddr(), req.Header.Get(capsuleProtocolHeader))
		w := NewHTTPResponseWriter(conn)
		http.Error(w, "Capsule-Protocol header required for connect-ip", http.StatusBadRequest)
		return errors.New("missing Capsule-Protocol header")
	}

	// Respond with 101 Switching Protocols to establish the tunnel.
	log.Debugf("Sending 101 Switching Protocols to %s", conn.RemoteAddr())
	if _, err := conn.Write([]byte(httpSwitchingProtocols)); err != nil {
		log.Errorf("Failed to write 101 Switching Protocols to %s: %v", conn.RemoteAddr(), err)
		return err
	}

	log.Infof("IP proxy tunnel established for %s. Waiting for client to close.", conn.RemoteAddr())

	// TODO: Implement full IP proxying with capsule and datagram handling.
	// For now, we just keep the connection open to represent the tunnel.
	// This will block until the client closes the connection.
	_, err := io.Copy(io.Discard, conn)
	if err != nil && err != io.EOF {
		log.Errorf("Error during IP proxy tunnel data discard for %s: %v", conn.RemoteAddr(), err)
	}
	log.Infof("IP proxy tunnel for %s closed.", conn.RemoteAddr())
	return err
}

func (s *Server) handleHTTP(conn net.Conn, req *http.Request, isConnectMethod bool) error {
	if s.UserConnectHandle == nil {
		log.Debugf("Using embedded HTTP connect handler for %s", conn.RemoteAddr())
		return s.embedHandleHTTP(conn, req, isConnectMethod)
	}

	if isConnectMethod {
		log.Debugf("Sending 200 Connection Established for CONNECT method to %s", conn.RemoteAddr())
		if _, err := conn.Write([]byte(httpConnectionEstablished)); err != nil {
			log.Errorf("Failed to write 200 Connection Established to %s: %v", conn.RemoteAddr(), err)
			return err
		}
	} else {
		// For non-CONNECT methods, we wrap the connection to prepend the request data.
		log.Debugf("Wrapping connection for non-CONNECT method for %s", conn.RemoteAddr())
		conn = &customConn{
			Conn: conn,
			req:  req,
		}
	}

	host, portStr, targetAddr := getTarget(req, isConnectMethod)
	log.Debugf("Resolved target for %s: host=%s, port=%s, addr=%s", conn.RemoteAddr(), host, portStr, targetAddr)

	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		log.Errorf("Failed to parse port %s for %s: %v", portStr, conn.RemoteAddr(), err)
		return err
	}

	proxyReq := &statute.ProxyRequest{
		Conn:        conn,
		Reader:      io.Reader(conn),
		Writer:      io.Writer(conn),
		Network:     "tcp",
		Destination: targetAddr,
		DestHost:    host,
		DestPort:    int32(portInt),
	}

	log.Infof("Invoking user connect handler for %s to %s", conn.RemoteAddr(), targetAddr)
	return s.UserConnectHandle(proxyReq)
}

func (s *Server) embedHandleHTTP(conn net.Conn, req *http.Request, isConnectMethod bool) error {
	_, _, targetAddr := getTarget(req, isConnectMethod)
	log.Debugf("Attempting to dial target %s for %s", targetAddr, conn.RemoteAddr())
	target, err := s.ProxyDial(s.Context, "tcp", targetAddr)
	if err != nil {
		log.Errorf("Failed to dial target %s for %s: %v", targetAddr, conn.RemoteAddr(), err)
		http.Error(
			NewHTTPResponseWriter(conn),
			err.Error(),
			http.StatusServiceUnavailable,
		)
		return err
	}
	defer func() {
		log.Debugf("Closing target connection to %s for %s", targetAddr, conn.RemoteAddr())
		_ = target.Close()
	}()

	if isConnectMethod {
		log.Debugf("Sending 200 Connection Established for CONNECT method to %s", conn.RemoteAddr())
		if _, err = conn.Write([]byte(httpConnectionEstablished)); err != nil {
			log.Errorf("Failed to write 200 Connection Established to %s: %v", conn.RemoteAddr(), err)
			return err
		}
	} else {
		log.Debugf("Writing request to target %s for %s", targetAddr, conn.RemoteAddr())
		if err = req.Write(target); err != nil {
			log.Errorf("Failed to write request to target %s for %s: %v", targetAddr, conn.RemoteAddr(), err)
			return err
		}
	}

	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
		log.Debugf("Using pooled buffers for tunneling between %s and %s", conn.RemoteAddr(), targetAddr)
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
		log.Debugf("Using default buffers for tunneling between %s and %s", conn.RemoteAddr(), targetAddr)
	}
	log.Debugf("Tunneling data between %s and %s", conn.RemoteAddr(), targetAddr)
	return statute.Tunnel(s.Context, target, conn, buf1, buf2)
}

// getTarget extracts the host, port, and full address from an HTTP request.
// It uses default ports for HTTP and HTTPS if not specified.
func getTarget(req *http.Request, isConnect bool) (host, port, addr string) {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		host = req.URL.Host
		if req.URL.Scheme == "https" || isConnect {
			port = defaultHTTPSPort
		} else {
			port = defaultHTTPPort
		}
		log.Debugf("Using default port %s for host %s (isConnect: %t, scheme: %s)", port, host, isConnect, req.URL.Scheme)
	}
	addr = net.JoinHostPort(host, port)
	return
}
