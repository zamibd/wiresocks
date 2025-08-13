package socks4

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/shahradelahi/wiresocks/log"
	"github.com/shahradelahi/wiresocks/proxy/statute"
)

// Server is accepting connections and handling the details of the SOCKS4 protocol
type Server struct {
	// Bind is the address to listen on
	Bind string
	// Listener is the net.Listener for the server
	Listener net.Listener
	// ProxyDial specifies the optional proxyDial function for
	// establishing the transport connection.
	ProxyDial statute.ProxyDialFunc
	// UserConnectHandle gives the user control to handle the TCP CONNECT requests
	UserConnectHandle statute.UserConnectHandler
	// UserBindHandle gives the user control to handle the TCP BIND requests
	UserBindHandle statute.UserBindHandler
	// Context is default context
	Context context.Context
	// BytesPool getting and returning temporary bytes for use by io.CopyBuffer
	BytesPool statute.BytesPool
}

// NewServer creates a new SOCKS4 server
func NewServer(options ...ServerOption) *Server {
	s := &Server{
		ProxyDial: statute.DefaultProxyDial(),
		Context:   statute.DefaultContext(),
	}

	for _, option := range options {
		option(s)
	}

	return s
}

// ListenAndServe starts the SOCKS4 server
func (s *Server) ListenAndServe() error {
	log.Infof("SOCKS4 proxy server listening on %s", s.Bind)

	defer func() {
		log.Infof("Closing SOCKS4 listener on %s", s.Listener.Addr().String())
		_ = s.Listener.Close()
	}()

	ctx, cancel := context.WithCancel(s.Context)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			log.Infof("SOCKS4 proxy server shutting down: %v", ctx.Err())
			return ctx.Err()
		default:
			conn, err := s.Listener.Accept()
			if err != nil {
				log.Errorf("Failed to accept SOCKS4 connection: %v", err)
				continue
			}
			log.Debugf("Accepted new SOCKS4 connection from %s", conn.RemoteAddr())

			go func() {
				defer func() {
					log.Debugf("Closing SOCKS4 connection from %s", conn.RemoteAddr())
					_ = conn.Close()
				}()
				if err := s.ServeConn(conn); err != nil {
					log.Errorf("Error serving SOCKS4 connection from %s: %v", conn.RemoteAddr(), err)
				}
			}()
		}
	}
}

// ServeConn handles a single SOCKS4 connection
func (s *Server) ServeConn(conn net.Conn) error {
	log.Debugf("Serving SOCKS4 connection from %s", conn.RemoteAddr())
	req, err := NewRequest(conn)
	if err != nil {
		log.Errorf("Failed to read SOCKS4 request from %s: %v", conn.RemoteAddr(), err)
		return err
	}

	log.Debugf("SOCKS4 request from %s: Command=%s, Destination=%s, User=%s", conn.RemoteAddr(), req.Command, req.DestAddr.String(), req.User)

	switch req.Command {
	case ConnectCommand:
		log.Infof("Handling SOCKS4 CONNECT command for %s to %s", conn.RemoteAddr(), req.DestAddr.String())
		return s.handleConnect(conn, req)
	case BindCommand:
		log.Infof("Handling SOCKS4 BIND command for %s to %s", conn.RemoteAddr(), req.DestAddr.String())
		return s.handleBind(conn, req)
	default:
		log.Warnf("Unsupported SOCKS4 command %s from %s", req.Command, conn.RemoteAddr())
		return fmt.Errorf("unsupported command: %v", req.Command)
	}
}

func (s *Server) handleConnect(conn net.Conn, req *Request) error {
	if s.UserConnectHandle != nil {
		log.Debugf("Invoking user connect handler for SOCKS4 CONNECT from %s to %s", conn.RemoteAddr(), req.DestAddr.String())
		return s.UserConnectHandle(&statute.ProxyRequest{
			Conn:        conn,
			Reader:      io.Reader(conn),
			Writer:      io.Writer(conn),
			Network:     "tcp",
			Destination: req.DestAddr.String(),
			DestHost:    req.DestAddr.Name,
			DestPort:    int32(req.DestAddr.Port),
		})
	}
	log.Debugf("Using embedded connect handler for SOCKS4 CONNECT from %s to %s", conn.RemoteAddr(), req.DestAddr.String())
	return s.embedHandleConnect(conn, req)
}

func (s *Server) embedHandleConnect(conn net.Conn, req *Request) error {
	log.Debugf("Attempting to dial target %s for SOCKS4 CONNECT from %s", req.DestAddr.String(), conn.RemoteAddr())
	target, err := s.ProxyDial(s.Context, "tcp", req.DestAddr.String())
	if err != nil {
		log.Errorf("Failed to dial target %s for SOCKS4 CONNECT from %s: %v", req.DestAddr.String(), conn.RemoteAddr(), err)
		if err := WriteReply(conn, RejectedReply, nil); err != nil {
			log.Errorf("Failed to write SOCKS4 RejectedReply to %s: %v", conn.RemoteAddr(), err)
		}
		return fmt.Errorf("connect to %v failed: %w", req.DestAddr, err)
	}
	defer func() {
		log.Debugf("Closing target connection to %s for SOCKS4 CONNECT from %s", req.DestAddr.String(), conn.RemoteAddr())
		_ = target.Close()
	}()

	local := target.LocalAddr().(*net.TCPAddr)
	bind := &Address{IP: local.IP, Port: local.Port}
	log.Debugf("Sending SOCKS4 GrantedReply to %s with bind address %s", conn.RemoteAddr(), bind.String())
	if err := WriteReply(conn, GrantedReply, bind); err != nil {
		log.Errorf("Failed to write SOCKS4 GrantedReply to %s: %v", conn.RemoteAddr(), err)
		return fmt.Errorf("failed to write reply: %v", err)
	}

	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
		log.Debugf("Using pooled buffers for tunneling between %s and %s", conn.RemoteAddr(), req.DestAddr.String())
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
		log.Debugf("Using default buffers for tunneling between %s and %s", conn.RemoteAddr(), req.DestAddr.String())
	}
	log.Infof("Tunneling data between %s and %s for SOCKS4 CONNECT", conn.RemoteAddr(), req.DestAddr.String())
	return statute.Tunnel(s.Context, target, conn, buf1, buf2)
}

func (s *Server) handleBind(conn net.Conn, req *Request) error {
	if s.UserBindHandle != nil {
		log.Debugf("Invoking user bind handler for SOCKS4 BIND from %s to %s", conn.RemoteAddr(), req.DestAddr.String())
		return s.UserBindHandle(&statute.ProxyRequest{
			Conn:        conn,
			Reader:      io.Reader(conn),
			Writer:      io.Writer(conn),
			Network:     "tcp",
			Destination: req.DestAddr.String(),
			DestHost:    req.DestAddr.Name,
			DestPort:    int32(req.DestAddr.Port),
		})
	}
	log.Debugf("Using embedded bind handler for SOCKS4 BIND from %s to %s", conn.RemoteAddr(), req.DestAddr.String())
	return s.embedHandleBind(conn, req)
}

func (s *Server) embedHandleBind(conn net.Conn, req *Request) error {
	log.Debugf("Attempting to listen for SOCKS4 BIND on 0.0.0.0:0 for %s", conn.RemoteAddr())
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		log.Errorf("Failed to listen for SOCKS4 BIND for %s: %v", conn.RemoteAddr(), err)
		if err := WriteReply(conn, RejectedReply, nil); err != nil {
			log.Errorf("Failed to write SOCKS4 RejectedReply to %s: %v", conn.RemoteAddr(), err)
		}
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer func() {
		log.Debugf("Closing SOCKS4 BIND listener on %s for %s", ln.Addr().String(), conn.RemoteAddr())
		_ = ln.Close()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	bind := &Address{IP: addr.IP, Port: addr.Port}
	log.Debugf("Sending SOCKS4 GrantedReply (first reply) to %s with bind address %s", conn.RemoteAddr(), bind.String())
	if err := WriteReply(conn, GrantedReply, bind); err != nil {
		log.Errorf("Failed to write SOCKS4 GrantedReply (first reply) to %s: %v", conn.RemoteAddr(), err)
		return fmt.Errorf("failed to write reply: %v", err)
	}

	log.Debugf("Waiting for incoming connection for SOCKS4 BIND on %s for %s", ln.Addr().String(), conn.RemoteAddr())
	target, err := ln.Accept()
	if err != nil {
		log.Errorf("Failed to accept incoming connection for SOCKS4 BIND on %s for %s: %v", ln.Addr().String(), conn.RemoteAddr(), err)
		if err := WriteReply(conn, RejectedReply, nil); err != nil {
			log.Errorf("Failed to write SOCKS4 RejectedReply (second reply) to %s: %v", conn.RemoteAddr(), err)
		}
		return fmt.Errorf("failed to accept: %w", err)
	}
	defer func() {
		log.Debugf("Closing target connection from %s for SOCKS4 BIND for %s", target.RemoteAddr().String(), conn.RemoteAddr())
		_ = target.Close()
	}()

	remote := target.RemoteAddr().(*net.TCPAddr)
	bind = &Address{IP: remote.IP, Port: remote.Port}
	log.Debugf("Sending SOCKS4 GrantedReply (second reply) to %s with remote address %s", conn.RemoteAddr(), bind.String())
	if err := WriteReply(conn, GrantedReply, bind); err != nil {
		log.Errorf("Failed to write SOCKS4 GrantedReply (second reply) to %s: %v", conn.RemoteAddr(), err)
		return fmt.Errorf("failed to write reply: %v", err)
	}

	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
		log.Debugf("Using pooled buffers for tunneling between %s and %s", conn.RemoteAddr(), target.RemoteAddr().String())
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
		log.Debugf("Using default buffers for tunneling between %s and %s", conn.RemoteAddr(), target.RemoteAddr().String())
	}
	log.Debugf("Tunneling data between %s and %s for SOCKS4 BIND", conn.RemoteAddr(), target.RemoteAddr().String())
	return statute.Tunnel(s.Context, target, conn, buf1, buf2)
}
