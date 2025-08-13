package wiresocks

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/sagernet/sing/common/buf"

	"github.com/shahradelahi/wiresocks/log"
	"github.com/shahradelahi/wiresocks/proxy/http"
	"github.com/shahradelahi/wiresocks/proxy/socks"
	"github.com/shahradelahi/wiresocks/proxy/statute"
)

// ProxyOptions holds the configuration for the proxies.
type ProxyOptions struct {
	SocksBindAddress *netip.AddrPort
	HttpBindAddress  *netip.AddrPort
}

// ProxyServer is a struct that manages the proxy servers.
type ProxyServer struct {
	opts    *ProxyOptions
	tnet    *netstack.Net
	ctx     context.Context
	cancel  context.CancelFunc
	vt      *virtualTun
	httpLn  net.Listener
	socksLn net.Listener
}

// NewProxyServer creates a new ProxyServer.
func NewProxyServer(tnet *netstack.Net, opts *ProxyOptions) *ProxyServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProxyServer{
		opts:   opts,
		tnet:   tnet,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start starts the proxy servers.
func (s *ProxyServer) Start() error {
	s.vt = &virtualTun{
		Tnet: s.tnet,
		Dev:  nil,
		Ctx:  s.ctx,
		pool: buf.DefaultAllocator,
	}

	if s.opts.SocksBindAddress != nil {
		log.Debugf("Attempting to listen on SOCKS address: %s", s.opts.SocksBindAddress.String())
		ln, err := net.Listen("tcp", s.opts.SocksBindAddress.String())
		if err != nil {
			log.Errorf("Failed to listen on SOCKS address %s: %v", s.opts.SocksBindAddress.String(), err)
			return err
		}
		s.socksLn = ln
		log.Infof("SOCKS proxy listener started on %s", s.socksLn.Addr().String())
	}

	if s.opts.HttpBindAddress != nil {
		log.Debugf("Attempting to listen on HTTP address: %s", s.opts.HttpBindAddress.String())
		ln, err := net.Listen("tcp", s.opts.HttpBindAddress.String())
		if err != nil {
			log.Errorf("Failed to listen on HTTP address %s: %v", s.opts.HttpBindAddress.String(), err)
			if s.socksLn != nil {
				log.Warnf("Closing SOCKS listener due to HTTP listener failure.")
				_ = s.socksLn.Close()
			}
			return err
		}
		s.httpLn = ln
		log.Infof("HTTP proxy listener started on %s", s.httpLn.Addr().String())
	}

	if s.socksLn == nil && s.httpLn == nil {
		return errors.New("no proxy listeners configured")
	}

	if s.socksLn != nil {
		go s.startSocksProxy()
	}

	if s.httpLn != nil {
		go s.startHttpProxy()
	}

	go func() {
		<-s.ctx.Done()
		log.Infof("ProxyServer context cancelled, stopping virtual tunnel.")
		s.vt.Stop()
	}()

	log.Debugf("Proxy servers started successfully.")
	return nil
}

// Stop stops the proxy servers.
func (s *ProxyServer) Stop() {
	log.Infof("Stopping proxy servers...")
	s.cancel()
	if s.httpLn != nil {
		log.Debugf("Closing HTTP listener.")
		_ = s.httpLn.Close()
	}
	if s.socksLn != nil {
		log.Debugf("Closing SOCKS listener.")
		_ = s.socksLn.Close()
	}
	log.Infof("Proxy servers stopped.")
}

func (s *ProxyServer) startSocksProxy() {
	log.Debugf("Starting SOCKS proxy handler.")
	proxy := socks.NewServer(
		socks.WithListener(s.socksLn),
		socks.WithContext(s.ctx),
		socks.WithConnectHandler(func(request *statute.ProxyRequest) error {
			log.Debugf("SOCKS Connect request for %s://%s", request.Network, request.Destination)
			return s.vt.handler(request)
		}),
		socks.WithAssociateHandler(func(request *statute.ProxyRequest) error {
			log.Debugf("SOCKS Associate request for %s://%s", request.Network, request.Destination)
			return s.vt.handler(request)
		}),
	)

	err := proxy.ListenAndServe()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Errorf("SOCKS proxy server stopped with error: %v", err)
	} else if errors.Is(err, net.ErrClosed) {
		log.Debugf("SOCKS proxy server listener closed.")
	}
}

func (s *ProxyServer) startHttpProxy() {
	log.Debugf("Starting HTTP proxy handler.")
	proxy := http.NewServer(
		http.WithContext(s.ctx),
		http.WithConnectHandle(func(request *statute.ProxyRequest) error {
			log.Debugf("HTTP Connect request for %s://%s", request.Network, request.Destination)
			return s.vt.handler(request)
		}),
	)
	proxy.Listener = s.httpLn

	err := proxy.ListenAndServe()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Errorf("HTTP proxy server stopped with error: %v", err)
	} else if errors.Is(err, net.ErrClosed) {
		log.Debugf("HTTP proxy server listener closed.")
	}
}
