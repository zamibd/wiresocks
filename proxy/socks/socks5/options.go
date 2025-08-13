package socks5

import (
	"context"

	"github.com/shahradelahi/wiresocks/proxy/statute"
)

type ServerOption func(*Server)

func WithBind(bindAddress string) ServerOption {
	return func(s *Server) {
		s.Bind = bindAddress
	}
}

func WithConnectHandle(handler statute.UserConnectHandler) ServerOption {
	return func(s *Server) {
		s.UserConnectHandle = handler
	}
}

func WithAssociateHandle(handler statute.UserAssociateHandler) ServerOption {
	return func(s *Server) {
		s.UserAssociateHandle = handler
	}
}

func WithProxyDial(proxyDial statute.ProxyDialFunc) ServerOption {
	return func(s *Server) {
		s.ProxyDial = proxyDial
	}
}

func WithProxyListenPacket(proxyListenPacket statute.ProxyListenPacket) ServerOption {
	return func(s *Server) {
		s.ProxyListenPacket = proxyListenPacket
	}
}

func WithPacketForwardAddress(packetForwardAddress statute.PacketForwardAddress) ServerOption {
	return func(s *Server) {
		s.PacketForwardAddress = packetForwardAddress
	}
}

func WithCredentials(creds CredentialStore) ServerOption {
	return func(s *Server) {
		s.Credentials = creds
	}
}

func WithContext(ctx context.Context) ServerOption {
	return func(s *Server) {
		s.Context = ctx
	}
}

func WithBytesPool(bytesPool statute.BytesPool) ServerOption {
	return func(s *Server) {
		s.BytesPool = bytesPool
	}
}
