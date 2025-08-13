package socks

import (
	"bufio"
	"context"
	"fmt"
	"net"

	"github.com/shahradelahi/wiresocks/log"
	"github.com/shahradelahi/wiresocks/proxy/socks/socks4"
	"github.com/shahradelahi/wiresocks/proxy/socks/socks5"
	"github.com/shahradelahi/wiresocks/proxy/statute"
)

type Server struct {
	// bind is the address to listen on
	bind string

	listener net.Listener

	// socks5Proxy is a socks5 server with tcp and udp support
	socks5Proxy *socks5.Server
	// socks4Proxy is a socks4 server with tcp support
	socks4Proxy *socks4.Server
	// userConnectHandle is a user handler for tcp and udp requests(its general handler)
	userConnectHandler  statute.UserConnectHandler
	userAssociateHandle statute.UserAssociateHandler
	// overwrite dial functions of http, socks4, socks5
	userDialFunc statute.ProxyDialFunc
	// ctx is default context
	ctx context.Context
}

func NewServer(options ...Option) *Server {
	s := &Server{
		bind:         statute.DefaultBindAddress,
		socks5Proxy:  socks5.NewServer(),
		socks4Proxy:  socks4.NewServer(),
		userDialFunc: statute.DefaultProxyDial(),
		ctx:          statute.DefaultContext(),
	}

	for _, option := range options {
		option(s)
	}

	return s
}

// SwitchConn wraps a net.Conn and a bufio.Reader
type SwitchConn struct {
	net.Conn
	*bufio.Reader
}

// NewSwitchConn creates a new SwitchConn
func NewSwitchConn(conn net.Conn) *SwitchConn {
	return &SwitchConn{
		Conn:   conn,
		Reader: bufio.NewReaderSize(conn, 2048),
	}
}

// Read reads data into p, first from the bufio.Reader, then from the net.Conn
func (c *SwitchConn) Read(p []byte) (n int, err error) {
	return c.Reader.Read(p)
}

func (s *Server) ListenAndServe() error {
	log.Debugf("SOCKS proxy server listening on %s", s.bind)

	// ensure listener will be closed
	defer func() {
		log.Debugf("Closing SOCKS listener on %s", s.listener.Addr().String())
		_ = s.listener.Close()
	}()

	// Create a cancelable context based on p.Context
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel() // Ensure resources are cleaned up

	// Start to accept connections and serve them
	for {
		select {
		case <-ctx.Done():
			log.Infof("SOCKS proxy server shutting down: %v", ctx.Err())
			return ctx.Err()
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				log.Errorf("Failed to accept incoming SOCKS connection: %v", err)
				continue
			}
			log.Debugf("Accepted new SOCKS connection from %s", conn.RemoteAddr())

			// Start a new goroutine to handle each connection
			// This way, the server can handle multiple connections concurrently
			go func() {
				defer func() {
					log.Debugf("Closing SOCKS connection from %s", conn.RemoteAddr())
					_ = conn.Close()
				}()
				err := s.handleConnection(conn)
				if err != nil {
					log.Errorf("Error handling SOCKS connection from %s: %v", conn.RemoteAddr(), err)
				}
			}()
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) error {
	// Create a SwitchConn
	switchConn := NewSwitchConn(conn)

	// Peek one byte to determine the protocol
	buf, err := switchConn.Peek(1)
	if err != nil {
		log.Errorf("Failed to peek first byte from %s: %v", conn.RemoteAddr(), err)
		return err
	}

	switch buf[0] {
	case 5:
		log.Debugf("Detected SOCKS5 protocol from %s", conn.RemoteAddr())
		err = s.socks5Proxy.ServeConn(switchConn)
	case 4:
		log.Debugf("Detected SOCKS4 protocol from %s", conn.RemoteAddr())
		err = s.socks4Proxy.ServeConn(switchConn)
	default:
		log.Warnf("Unsupported SOCKS version %d from %s", buf[0], conn.RemoteAddr())
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	return err
}
