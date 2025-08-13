package socks5

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"

	"github.com/shahradelahi/wiresocks/log"
	"github.com/shahradelahi/wiresocks/proxy/statute"
)

// Server is accepting connections and handling the details of the SOCKS5 protocol
type Server struct {
	// bind is the address to listen on
	Bind string

	Listener net.Listener

	// ProxyDial specifies the optional proxyDial function for
	// establishing the transport connection.
	ProxyDial statute.ProxyDialFunc
	// ProxyListenPacket specifies the optional proxyListenPacket function for
	// establishing the transport connection.
	ProxyListenPacket statute.ProxyListenPacket
	// PacketForwardAddress specifies the packet forwarding address
	PacketForwardAddress statute.PacketForwardAddress
	// UserConnectHandle gives the user control to handle the TCP CONNECT requests
	UserConnectHandle statute.UserConnectHandler
	// UserAssociateHandle gives the user control to handle the UDP ASSOCIATE requests
	UserAssociateHandle statute.UserAssociateHandler
	// Credentials provided for username/password authentication
	Credentials CredentialStore
	// Context is default context
	Context context.Context
	// BytesPool getting and returning temporary bytes for use by io.CopyBuffer
	BytesPool statute.BytesPool
}

func NewServer(options ...ServerOption) *Server {
	s := &Server{
		Bind:                 statute.DefaultBindAddress,
		ProxyDial:            statute.DefaultProxyDial(),
		ProxyListenPacket:    statute.DefaultProxyListenPacket(),
		PacketForwardAddress: defaultReplyPacketForwardAddress,
		Context:              statute.DefaultContext(),
		Credentials:          nil,
	}

	for _, option := range options {
		option(s)
	}

	return s
}

func (s *Server) ListenAndServe() error {
	log.Infof("SOCKS5 proxy server listening on %s", s.Bind)

	// ensure listener will be closed
	defer func() {
		log.Infof("Closing SOCKS5 listener on %s", s.Listener.Addr().String())
		_ = s.Listener.Close()
	}()

	// Create a cancelable context based on s.Context
	ctx, cancel := context.WithCancel(s.Context)
	defer cancel() // Ensure resources are cleaned up

	// Start to accept connections and serve them
	for {
		select {
		case <-ctx.Done():
			log.Infof("SOCKS5 proxy server shutting down: %v", ctx.Err())
			return ctx.Err()
		default:
			conn, err := s.Listener.Accept()
			if err != nil {
				log.Errorf("Failed to accept SOCKS5 connection: %v", err)
				continue
			}
			log.Debugf("Accepted new SOCKS5 connection from %s", conn.RemoteAddr())

			// Start a new goroutine to handle each connection
			// This way, the server can handle multiple connections concurrently
			go func() {
				defer func() {
					log.Debugf("Closing SOCKS5 connection from %s", conn.RemoteAddr())
					_ = conn.Close()
				}()
				err := s.ServeConn(conn)
				if err != nil {
					log.Errorf("Error serving SOCKS5 connection from %s: %v", conn.RemoteAddr(), err)
				}
			}()
		}
	}
}

func (s *Server) ServeConn(conn net.Conn) error {
	log.Debugf("Serving SOCKS5 connection from %s", conn.RemoteAddr())
	version, err := readByte(conn)
	if err != nil {
		log.Errorf("Failed to read SOCKS version from %s: %v", conn.RemoteAddr(), err)
		return err
	}
	if version != socks5Version {
		log.Warnf("Unsupported SOCKS version %d from %s", version, conn.RemoteAddr())
		return fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	log.Debugf("Authenticating SOCKS5 connection from %s", conn.RemoteAddr())
	if err := s.authenticate(conn); err != nil {
		log.Errorf("SOCKS5 authentication failed for %s: %v", conn.RemoteAddr(), err)
		return err
	}
	log.Debugf("SOCKS5 authentication successful for %s", conn.RemoteAddr())

	log.Debugf("Handling SOCKS5 request from %s", conn.RemoteAddr())
	return s.handleRequest(conn)
}

func (s *Server) authenticate(conn net.Conn) error {
	methods, err := readBytes(conn)
	if err != nil {
		log.Errorf("Failed to read authentication methods from %s: %v", conn.RemoteAddr(), err)
		return err
	}
	log.Debugf("Received SOCKS5 authentication methods from %s: %v", conn.RemoteAddr(), methods)

	// GSSAPI authentication
	if bytes.IndexByte(methods, byte(gssapiAuth)) != -1 {
		log.Warnf("GSSAPI authentication requested by %s, but not supported.", conn.RemoteAddr())
		if _, err := conn.Write([]byte{socks5Version, byte(gssapiAuth)}); err != nil {
			log.Errorf("Failed to write GSSAPI auth response to %s: %v", conn.RemoteAddr(), err)
			return err
		}
		return fmt.Errorf("GSSAPI authentication is not supported")
	}

	// Prefer username/password if supported by both
	if s.Credentials != nil && bytes.IndexByte(methods, byte(usernamePasswordAuth)) != -1 {
		log.Debugf("Username/Password authentication selected for %s", conn.RemoteAddr())
		if _, err := conn.Write([]byte{socks5Version, byte(usernamePasswordAuth)}); err != nil {
			log.Errorf("Failed to write Username/Password auth response to %s: %v", conn.RemoteAddr(), err)
			return err
		}
		return s.handleUsernamePasswordAuth(conn)
	}

	// Fallback to no-auth
	if bytes.IndexByte(methods, byte(noAuth)) != -1 {
		log.Debugf("No authentication required selected for %s", conn.RemoteAddr())
		_, err := conn.Write([]byte{socks5Version, byte(noAuth)})
		return err
	}

	// No acceptable methods
	log.Warnf("No acceptable authentication methods found for %s. Methods: %v", conn.RemoteAddr(), methods)
	_, err = conn.Write([]byte{socks5Version, byte(noAcceptable)})
	if err != nil {
		log.Errorf("Failed to write no acceptable methods response to %s: %v", conn.RemoteAddr(), err)
		return err
	}
	return errNoSupportedAuth
}

func (s *Server) handleUsernamePasswordAuth(conn net.Conn) error {
	log.Debugf("Handling Username/Password authentication for %s", conn.RemoteAddr())
	version, err := readByte(conn)
	if err != nil {
		log.Errorf("Failed to read auth version from %s: %v", conn.RemoteAddr(), err)
		return err
	}
	if version != 1 {
		log.Warnf("Unsupported auth version %d from %s", version, conn.RemoteAddr())
		return fmt.Errorf("unsupported auth version: %d", version)
	}

	username, err := readBytes(conn)
	if err != nil {
		log.Errorf("Failed to read username from %s: %v", conn.RemoteAddr(), err)
		return err
	}

	password, err := readBytes(conn)
	if err != nil {
		log.Errorf("Failed to read password from %s: %v", conn.RemoteAddr(), err)
		return err
	}

	log.Debugf("Authenticating user '%s' from %s", string(username), conn.RemoteAddr())
	if s.Credentials.Valid(string(username), string(password)) {
		log.Infof("User '%s' authenticated successfully from %s", string(username), conn.RemoteAddr())
		_, err := conn.Write([]byte{1, 0}) // success
		return err
	}

	log.Warnf("Invalid username or password for user '%s' from %s", string(username), conn.RemoteAddr())
	_, err = conn.Write([]byte{1, 1}) // failure
	if err != nil {
		log.Errorf("Failed to write auth failure response to %s: %v", conn.RemoteAddr(), err)
		return err
	}
	return fmt.Errorf("invalid username or password")
}

func (s *Server) handleRequest(conn net.Conn) error {
	req := &request{
		Version: socks5Version,
		Conn:    conn,
	}

	var header [3]byte
	_, err := io.ReadFull(conn, header[:])
	if err != nil {
		log.Errorf("Failed to read request header from %s: %v", conn.RemoteAddr(), err)
		return err
	}

	if header[0] != socks5Version {
		log.Warnf("Unsupported SOCKS5 command version %d from %s", header[0], conn.RemoteAddr())
		return fmt.Errorf("unsupported Command version: %d", header[0])
	}

	req.Command = Command(header[1])
	log.Debugf("Received SOCKS5 command %s from %s", req.Command, conn.RemoteAddr())

	dest, err := readAddr(conn)
	if err != nil {
		log.Errorf("Failed to read destination address from %s: %v", conn.RemoteAddr(), err)
		if err == errUnrecognizedAddrType {
			log.Warnf("Unrecognized address type from %s. Sending addrTypeNotSupported reply.", conn.RemoteAddr())
			err := sendReply(conn, addrTypeNotSupported, nil)
			if err != nil {
				log.Errorf("Failed to send addrTypeNotSupported reply to %s: %v", conn.RemoteAddr(), err)
			}
		}
		return err
	}
	req.DestinationAddr = dest
	log.Debugf("Destination address for %s: %s", conn.RemoteAddr(), req.DestinationAddr.String())
	err = s.handle(req)
	if err != nil {
		log.Errorf("Error handling SOCKS5 request from %s: %v", conn.RemoteAddr(), err)
		return err
	}

	return nil
}

func (s *Server) handle(req *request) error {
	switch req.Command {
	case ConnectCommand:
		log.Debugf("Handling SOCKS5 CONNECT command for %s to %s", req.Conn.RemoteAddr(), req.DestinationAddr.String())
		return s.handleConnect(req)
	case BindCommand:
		log.Debugf("Handling SOCKS5 BIND command for %s to %s", req.Conn.RemoteAddr(), req.DestinationAddr.String())
		return s.handleBind(req)
	case AssociateCommand:
		log.Debugf("Handling SOCKS5 UDP ASSOCIATE command for %s to %s", req.Conn.RemoteAddr(), req.DestinationAddr.String())
		return s.handleAssociate(req)
	default:
		log.Warnf("Unsupported SOCKS5 command %s from %s", req.Command, req.Conn.RemoteAddr())
		if err := sendReply(req.Conn, commandNotSupported, nil); err != nil {
			log.Errorf("Failed to send commandNotSupported reply to %s: %v", req.Conn.RemoteAddr(), err)
			return err
		}
		return fmt.Errorf("unsupported Command: %v", req.Command)
	}
}

func (s *Server) handleConnect(req *request) error {
	if s.UserConnectHandle == nil {
		log.Debugf("Using embedded SOCKS5 connect handler for %s to %s", req.Conn.RemoteAddr(), req.DestinationAddr.String())
		return s.embedHandleConnect(req)
	}

	log.Debugf("Invoking user connect handler for SOCKS5 CONNECT from %s to %s", req.Conn.RemoteAddr(), req.DestinationAddr.String())
	if err := sendReply(req.Conn, successReply, nil); err != nil {
		log.Errorf("Failed to send SOCKS5 success reply to %s: %v", req.Conn.RemoteAddr(), err)
		return fmt.Errorf("failed to send reply: %v", err)
	}
	host := req.DestinationAddr.IP.String()
	if req.DestinationAddr.Name != "" {
		host = req.DestinationAddr.Name
	}

	proxyReq := &statute.ProxyRequest{
		Conn:        req.Conn,
		Reader:      io.Reader(req.Conn),
		Writer:      io.Writer(req.Conn),
		Network:     "tcp",
		Destination: req.DestinationAddr.String(),
		DestHost:    host,
		DestPort:    int32(req.DestinationAddr.Port),
	}

	return s.UserConnectHandle(proxyReq)
}

func (s *Server) embedHandleConnect(req *request) error {
	log.Debugf("Attempting to dial target %s for SOCKS5 CONNECT from %s", req.DestinationAddr.Address(), req.Conn.RemoteAddr())
	target, err := s.ProxyDial(s.Context, "tcp", req.DestinationAddr.Address())
	if err != nil {
		log.Errorf("Failed to dial target %s for SOCKS5 CONNECT from %s: %v", req.DestinationAddr.Address(), req.Conn.RemoteAddr(), err)
		if err := sendReply(req.Conn, errToReply(err), nil); err != nil {
			log.Errorf("Failed to send SOCKS5 error reply to %s: %v", req.Conn.RemoteAddr(), err)
		}
		return fmt.Errorf("connect to %v failed: %w", req.DestinationAddr, err)
	}
	defer func() {
		log.Debugf("Closing target connection to %s for SOCKS5 CONNECT from %s", req.DestinationAddr.Address(), req.Conn.RemoteAddr())
		_ = target.Close()
	}()

	localAddr := target.LocalAddr()
	local, ok := localAddr.(*net.TCPAddr)
	if !ok {
		log.Errorf("Failed to get local TCP address for %s: %s://%s", req.Conn.RemoteAddr(), localAddr.Network(), localAddr.String())
		return fmt.Errorf("connect to %v failed: local address is %s://%s", req.DestinationAddr, localAddr.Network(), localAddr.String())
	}
	bind := address{IP: local.IP, Port: local.Port}
	log.Debugf("Sending SOCKS5 success reply to %s with bind address %s", req.Conn.RemoteAddr(), bind.String())
	if err := sendReply(req.Conn, successReply, &bind); err != nil {
		log.Errorf("Failed to send SOCKS5 success reply to %s: %v", req.Conn.RemoteAddr(), err)
		return fmt.Errorf("failed to send reply: %v", err)
	}

	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
		log.Debugf("Using pooled buffers for tunneling between %s and %s", req.Conn.RemoteAddr(), req.DestinationAddr.Address())
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
		log.Debugf("Using default buffers for tunneling between %s and %s", req.Conn.RemoteAddr(), req.DestinationAddr.Address())
	}
	log.Infof("Tunneling data between %s and %s for SOCKS5 CONNECT", req.Conn.RemoteAddr(), req.DestinationAddr.Address())
	return statute.Tunnel(s.Context, target, req.Conn, buf1, buf2)
}

func (s *Server) handleBind(req *request) error {
	log.Debugf("Using embedded SOCKS5 bind handler for %s to %s", req.Conn.RemoteAddr(), req.DestinationAddr.String())
	return s.embedHandleBind(req)
}

func (s *Server) embedHandleBind(req *request) error {
	ctx, cancel := context.WithCancel(s.Context)
	defer cancel()

	// Create a listener
	listenIP := req.Conn.LocalAddr().(*net.TCPAddr).IP
	log.Debugf("Attempting to listen for SOCKS5 BIND on %s for %s", listenIP.String(), req.Conn.RemoteAddr())
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: listenIP})
	if err != nil {
		log.Errorf("Failed to listen for SOCKS5 BIND for %s: %v", req.Conn.RemoteAddr(), err)
		if err := sendReply(req.Conn, serverFailure, nil); err != nil {
			log.Errorf("Failed to send SOCKS5 serverFailure reply to %s: %v", req.Conn.RemoteAddr(), err)
		}
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer func() {
		log.Debugf("Closing SOCKS5 BIND listener on %s for %s", listener.Addr().String(), req.Conn.RemoteAddr())
		if err := listener.Close(); err != nil {
			log.Errorf("Failed to close SOCKS5 BIND listener on %s for %s: %v", listener.Addr().String(), req.Conn.RemoteAddr(), err)
		}
	}()

	// Send first reply
	listenAddr := listener.Addr().(*net.TCPAddr)
	bindAddr := address{IP: listenAddr.IP, Port: listenAddr.Port}
	log.Debugf("Sending SOCKS5 success reply (first) to %s with bind address %s", req.Conn.RemoteAddr(), bindAddr.String())
	if err := sendReply(req.Conn, successReply, &bindAddr); err != nil {
		log.Errorf("Failed to send SOCKS5 success reply (first) to %s: %v", req.Conn.RemoteAddr(), err)
		return fmt.Errorf("failed to send first reply: %v", err)
	}

	// Wait for incoming connection
	var remoteConn net.Conn
	acceptChan := make(chan error, 1)
	go func() {
		var err error
		log.Debugf("Waiting for incoming connection on SOCKS5 BIND listener %s for %s", listener.Addr().String(), req.Conn.RemoteAddr())
		remoteConn, err = listener.Accept()
		acceptChan <- err
	}()

	select {
	case err := <-acceptChan:
		if err != nil {
			log.Errorf("Failed to accept incoming connection for SOCKS5 BIND for %s: %v", req.Conn.RemoteAddr(), err)
			if err := sendReply(req.Conn, serverFailure, nil); err != nil {
				log.Errorf("Failed to send SOCKS5 serverFailure reply (second) to %s: %v", req.Conn.RemoteAddr(), err)
			}
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		log.Debugf("Accepted incoming connection from %s for SOCKS5 BIND for %s", remoteConn.RemoteAddr().String(), req.Conn.RemoteAddr())
	case <-ctx.Done():
		log.Warnf("SOCKS5 BIND accept timeout for %s: %v", req.Conn.RemoteAddr(), ctx.Err())
		if err := sendReply(req.Conn, serverFailure, nil); err != nil {
			log.Errorf("Failed to send SOCKS5 serverFailure reply (second) to %s: %v", req.Conn.RemoteAddr(), err)
		}
		return fmt.Errorf("bind accept timeout: %w", ctx.Err())
	}
	defer func() {
		log.Debugf("Closing remote connection from %s for SOCKS5 BIND for %s", remoteConn.RemoteAddr().String(), req.Conn.RemoteAddr())
		if err := remoteConn.Close(); err != nil {
			log.Errorf("Failed to close remote connection from %s for SOCKS5 BIND for %s: %v", remoteConn.RemoteAddr().String(), req.Conn.RemoteAddr(), err)
		}
	}()

	remoteTCPAddr := remoteConn.RemoteAddr().(*net.TCPAddr)
	if req.DestinationAddr.IP != nil && !req.DestinationAddr.IP.IsUnspecified() {
		log.Debugf("Checking bind address mismatch for %s: remote IP %s, requested IP %s", req.Conn.RemoteAddr(), remoteTCPAddr.IP, req.DestinationAddr.IP)
		if !remoteTCPAddr.IP.Equal(req.DestinationAddr.IP) {
			log.Warnf("SOCKS5 BIND address mismatch for %s: got %s, want %s", req.Conn.RemoteAddr(), remoteTCPAddr.IP, req.DestinationAddr.IP)
			if err := sendReply(req.Conn, ruleFailure, nil); err != nil {
				log.Errorf("Failed to send SOCKS5 ruleFailure reply (second) to %s: %v", req.Conn.RemoteAddr(), err)
			}
			return fmt.Errorf("bind address mismatch: got %s, want %s", remoteTCPAddr.IP, req.DestinationAddr.IP)
		}
	}

	// Send second reply
	remoteAddr := address{IP: remoteTCPAddr.IP, Port: remoteTCPAddr.Port}
	log.Debugf("Sending SOCKS5 success reply (second) to %s with remote address %s", req.Conn.RemoteAddr(), remoteAddr.String())
	if err := sendReply(req.Conn, successReply, &remoteAddr); err != nil {
		log.Errorf("Failed to send SOCKS5 success reply (second) to %s: %v", req.Conn.RemoteAddr(), err)
		return fmt.Errorf("failed to send second reply: %v", err)
	}

	// Tunnel data
	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
		log.Debugf("Using pooled buffers for tunneling between %s and %s", req.Conn.RemoteAddr(), remoteConn.RemoteAddr().String())
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
		log.Debugf("Using default buffers for tunneling between %s and %s", req.Conn.RemoteAddr(), remoteConn.RemoteAddr().String())
	}
	log.Infof("Tunneling data between %s and %s for SOCKS5 BIND", req.Conn.RemoteAddr(), remoteConn.RemoteAddr().String())
	return statute.Tunnel(s.Context, remoteConn, req.Conn, buf1, buf2)
}

func (s *Server) handleAssociate(req *request) error {
	destinationAddr := req.DestinationAddr.String()
	log.Debugf("Attempting to listen for SOCKS5 UDP ASSOCIATE on %s for %s", destinationAddr, req.Conn.RemoteAddr())
	udpConn, err := s.ProxyListenPacket(s.Context, "udp", destinationAddr)
	if err != nil {
		log.Errorf("Failed to listen for SOCKS5 UDP ASSOCIATE on %s for %s: %v", destinationAddr, req.Conn.RemoteAddr(), err)
		if err := sendReply(req.Conn, errToReply(err), nil); err != nil {
			log.Errorf("Failed to send SOCKS5 error reply to %s: %v", req.Conn.RemoteAddr(), err)
		}
		return fmt.Errorf("connect to %v failed: %w", req.DestinationAddr, err)
	}
	log.Debugf("SOCKS5 UDP ASSOCIATE listener started on %s for %s", udpConn.LocalAddr().String(), req.Conn.RemoteAddr())

	ip, port, err := s.PacketForwardAddress(s.Context, destinationAddr, udpConn, req.Conn)
	if err != nil {
		log.Errorf("Failed to get packet forward address for %s: %v", req.Conn.RemoteAddr(), err)
		return err
	}
	bind := address{IP: ip, Port: port}
	log.Debugf("Sending SOCKS5 success reply to %s with UDP bind address %s", req.Conn.RemoteAddr(), bind.String())
	if err := sendReply(req.Conn, successReply, &bind); err != nil {
		log.Errorf("Failed to send SOCKS5 success reply to %s: %v", req.Conn.RemoteAddr(), err)
		return fmt.Errorf("failed to send reply: %v", err)
	}

	if s.UserAssociateHandle == nil {
		log.Debugf("Using embedded SOCKS5 UDP ASSOCIATE handler for %s to %s", req.Conn.RemoteAddr(), req.DestinationAddr.String())
		return s.embedHandleAssociate(req, udpConn)
	}

	cConn := &udpCustomConn{
		PacketConn:   udpConn,
		assocTCPConn: req.Conn,
		frc:          make(chan bool),
		packetQueue:  make(chan *readStruct),
	}

	cConn.asyncReadPackets()

	// wait for first packet so that target sender and receiver get known
	log.Debugf("Waiting for first UDP packet for SOCKS5 UDP ASSOCIATE from %s", req.Conn.RemoteAddr())
	<-cConn.frc
	log.Debugf("First UDP packet received for SOCKS5 UDP ASSOCIATE from %s. Target: %s", req.Conn.RemoteAddr(), cConn.targetAddr.String())

	proxyReq := &statute.ProxyRequest{
		Conn:        cConn,
		Reader:      cConn,
		Writer:      cConn,
		Network:     "udp",
		Destination: cConn.targetAddr.String(),
		DestHost:    cConn.targetAddr.(*net.UDPAddr).IP.String(),
		DestPort:    int32(cConn.targetAddr.(*net.UDPAddr).Port),
	}

	log.Debugf("Invoking user associate handler for SOCKS5 UDP ASSOCIATE from %s to %s", req.Conn.RemoteAddr(), cConn.targetAddr.String())
	return s.UserAssociateHandle(proxyReq)
}

func (s *Server) embedHandleAssociate(req *request, udpConn net.PacketConn) error {
	log.Debugf("Starting embedded SOCKS5 UDP ASSOCIATE handler for %s", req.Conn.RemoteAddr())
	defer func() {
		log.Debugf("Closing UDP connection for SOCKS5 UDP ASSOCIATE for %s", req.Conn.RemoteAddr())
		_ = udpConn.Close()
	}()

	go func() {
		var buf [1]byte
		for {
			_, err := req.Conn.Read(buf[:])
			if err != nil {
				log.Debugf("Associated TCP connection for SOCKS5 UDP ASSOCIATE closed by %s: %v", req.Conn.RemoteAddr(), err)
				_ = udpConn.Close()
				break
			}
		}
	}()

	var (
		sourceAddr  net.Addr
		wantSource  string
		targetAddr  net.Addr
		wantTarget  string
		replyPrefix []byte
		buf         [maxUdpPacket]byte
	)

	for {
		n, addr, err := udpConn.ReadFrom(buf[:])
		if err != nil {
			log.Errorf("Error reading from UDP connection for SOCKS5 UDP ASSOCIATE for %s: %v", req.Conn.RemoteAddr(), err)
			return err
		}

		if sourceAddr == nil {
			sourceAddr = addr
			wantSource = sourceAddr.String()
			log.Debugf("First UDP packet from %s for SOCKS5 UDP ASSOCIATE from %s", sourceAddr.String(), req.Conn.RemoteAddr())
		}

		gotAddr := addr.String()
		if wantSource == gotAddr {
			// Packet from client to target
			if n < 3 {
				log.Warnf("Received short UDP packet from %s for SOCKS5 UDP ASSOCIATE from %s (length %d)", sourceAddr.String(), req.Conn.RemoteAddr(), n)
				continue
			}
			reader := bytes.NewBuffer(buf[3:n])
			addr, err := readAddr(reader)
			if err != nil {
				log.Debugf("Failed to read address in SOCKS5 UDP association from %s: %v", sourceAddr.String(), err)
				continue
			}
			if targetAddr == nil {
				targetAddr = &net.UDPAddr{
					IP:   addr.IP,
					Port: addr.Port,
				}
				wantTarget = targetAddr.String()
				log.Debugf("Determined target address for SOCKS5 UDP ASSOCIATE: %s", wantTarget)
			}
			if addr.String() != wantTarget {
				log.Debugf("Ignoring UDP packet from %s for SOCKS5 UDP ASSOCIATE to non-target address: %s (expected %s)", sourceAddr.String(), addr.String(), wantTarget)
				continue
			}
			log.Debugf("Forwarding UDP packet from %s to %s (size: %d)", sourceAddr.String(), targetAddr.String(), len(reader.Bytes()))
			_, err = udpConn.WriteTo(reader.Bytes(), targetAddr)
			if err != nil {
				log.Errorf("Failed to write UDP packet to target %s for SOCKS5 UDP ASSOCIATE: %v", targetAddr.String(), err)
				return err
			}
		} else if targetAddr != nil && wantTarget == gotAddr {
			// Packet from target to client
			if replyPrefix == nil {
				b := bytes.NewBuffer(make([]byte, 3, 16))
				err = writeAddrWithStr(b, wantTarget)
				if err != nil {
					log.Errorf("Failed to create reply prefix for SOCKS5 UDP ASSOCIATE: %v", err)
					return err
				}
				replyPrefix = b.Bytes()
				log.Debugf("Created reply prefix for SOCKS5 UDP ASSOCIATE: %v", replyPrefix)
			}
			copy(buf[len(replyPrefix):len(replyPrefix)+n], buf[:n])
			copy(buf[:len(replyPrefix)], replyPrefix)
			log.Debugf("Forwarding UDP packet from %s to %s (size: %d)", targetAddr.String(), sourceAddr.String(), len(buf[:len(replyPrefix)+n]))
			_, err = udpConn.WriteTo(buf[:len(replyPrefix)+n], sourceAddr)
			if err != nil {
				log.Errorf("Failed to write UDP packet to source %s for SOCKS5 UDP ASSOCIATE: %v", sourceAddr.String(), err)
				return err
			}
		} else {
			log.Warnf("Ignoring UDP packet from unknown source %s for SOCKS5 UDP ASSOCIATE", addr.String())
		}
	}
}

func sendReply(w io.Writer, resp reply, addr *address) error {
	log.Debugf("Sending SOCKS5 reply %s with address %s", resp.String(), addr.String())
	_, err := w.Write([]byte{socks5Version, byte(resp), 0})
	if err != nil {
		log.Errorf("Failed to write SOCKS5 reply header: %v", err)
		return err
	}
	err = writeAddr(w, addr)
	if err != nil {
		log.Errorf("Failed to write SOCKS5 reply address %s: %v", addr.String(), err)
	}
	return err
}

type request struct {
	Version         uint8
	Command         Command
	DestinationAddr *address
	Username        string
	Password        string
	Conn            net.Conn
}

func defaultReplyPacketForwardAddress(_ context.Context, destinationAddr string, packet net.PacketConn, conn net.Conn) (net.IP, int, error) {
	udpLocal := packet.LocalAddr()
	udpLocalAddr, ok := udpLocal.(*net.UDPAddr)
	if !ok {
		log.Errorf("Failed to get local UDP address for destination %s: %s://%s", destinationAddr, udpLocal.Network(), udpLocal.String())
		return nil, 0, fmt.Errorf("connect to %v failed: local address is %s://%s", destinationAddr, udpLocal.Network(), udpLocal.String())
	}

	tcpLocal := conn.LocalAddr()
	tcpLocalAddr, ok := tcpLocal.(*net.TCPAddr)
	if !ok {
		log.Errorf("Failed to get local TCP address for destination %s: %s://%s", destinationAddr, tcpLocal.Network(), tcpLocal.String())
		return nil, 0, fmt.Errorf("connect to %v failed: local address is %s://%s", destinationAddr, tcpLocal.Network(), tcpLocal.String())
	}
	log.Debugf("Default packet forward address: TCP IP %s, UDP Port %d", tcpLocalAddr.IP.String(), udpLocalAddr.Port)
	return tcpLocalAddr.IP, udpLocalAddr.Port, nil
}
