package socks4

import (
	"context"

	"github.com/shahradelahi/wiresocks/proxy/statute"
)

// ServerOption is a function that configures a SOCKS4 server.
type ServerOption func(*Server)

// WithBind sets the bind address for the server
func WithBind(bindAddress string) ServerOption {
	return func(s *Server) {
		s.Bind = bindAddress
	}
}

// WithConnectHandle sets the connect handler for the server
func WithConnectHandle(handler statute.UserConnectHandler) ServerOption {
	return func(s *Server) {
		s.UserConnectHandle = handler
	}
}

// WithBindHandle sets the bind handler for the server
func WithBindHandle(handler statute.UserBindHandler) ServerOption {
	return func(s *Server) {
		s.UserBindHandle = handler
	}
}

// WithProxyDial sets the proxy dial function for the server
func WithProxyDial(proxyDial statute.ProxyDialFunc) ServerOption {
	return func(s *Server) {
		s.ProxyDial = proxyDial
	}
}

// WithContext sets the context for the server
func WithContext(ctx context.Context) ServerOption {
	return func(s *Server) {
		s.Context = ctx
	}
}

// WithBytesPool sets the bytes pool for the server
func WithBytesPool(bytesPool statute.BytesPool) ServerOption {
	return func(s *Server) {
		s.BytesPool = bytesPool
	}
}
