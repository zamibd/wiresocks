package socks

import (
	"context"
	"net"

	"github.com/shahradelahi/wiresocks/proxy/statute"
)

type Option func(*Server)

func WithBindAddress(binAddress string) Option {
	return func(s *Server) {
		s.bind = binAddress
		s.socks5Proxy.Bind = binAddress
		s.socks4Proxy.Bind = binAddress
	}
}

func WithListener(ln net.Listener) Option {
	return func(s *Server) {
		s.listener = ln
		s.socks5Proxy.Listener = ln
		s.socks4Proxy.Listener = ln
	}
}

func WithConnectHandler(handler statute.UserConnectHandler) Option {
	return func(s *Server) {
		s.userConnectHandler = handler
		s.socks5Proxy.UserConnectHandle = handler
		s.socks4Proxy.UserConnectHandle = handler
	}
}

func WithAssociateHandler(handler statute.UserAssociateHandler) Option {
	return func(s *Server) {
		s.userAssociateHandle = handler
		s.socks5Proxy.UserAssociateHandle = handler
	}
}

func WithUserDialFunc(proxyDial statute.ProxyDialFunc) Option {
	return func(s *Server) {
		s.userDialFunc = proxyDial
		s.socks5Proxy.ProxyDial = proxyDial
		s.socks4Proxy.ProxyDial = proxyDial
	}
}

func WithUserListenPacketFunc(proxyListenPacket statute.ProxyListenPacket) Option {
	return func(s *Server) {
		s.socks5Proxy.ProxyListenPacket = proxyListenPacket
	}
}

func WithUserForwardAddressFunc(packetForwardAddress statute.PacketForwardAddress) Option {
	return func(s *Server) {
		s.socks5Proxy.PacketForwardAddress = packetForwardAddress
	}
}

func WithContext(ctx context.Context) Option {
	return func(s *Server) {
		s.ctx = ctx
		s.socks5Proxy.Context = ctx
		s.socks4Proxy.Context = ctx
	}
}

func WithBytesPool(bytesPool statute.BytesPool) Option {
	return func(s *Server) {
		s.socks5Proxy.BytesPool = bytesPool
		s.socks4Proxy.BytesPool = bytesPool
	}
}
