package wiresocks

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/shahradelahi/wiresocks/log"
)

// WireSocks is the main engine for running WARP.
type WireSocks struct {
	conf             *Configuration
	socksBindAddress *netip.AddrPort
	httpBindAddress  *netip.AddrPort
	testURL          string

	ctx    context.Context
	cancel context.CancelFunc
}

func NewWireSocks(options ...option) (*WireSocks, error) {
	dnsServers := []string{"1.1.1.1", "1.0.0.1"}

	log.Debugf("Initializing WireSocks with default DNS servers: %v", dnsServers)

	var dnsAddrs []netip.Addr
	for _, dns := range dnsServers {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			log.Errorf("Failed to parse default DNS server %s: %v", dns, err)
			return nil, fmt.Errorf("failed to parse DNS server: %v", err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	iface := InterfaceConfig{
		DNS:        dnsAddrs,
		PrivateKey: "",
		Addresses:  []netip.Addr{},
		MTU:        1330,
		FwMark:     0x0,
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &WireSocks{
		conf: &Configuration{
			Interface: &iface,
			Peers:     []PeerConfig{},
		},
		ctx:     ctx,
		testURL: "https://1.1.1.1/cdn-cgi/trace/",
		cancel:  cancel,
	}

	for _, option := range options {
		option(s)
	}

	log.Debugf("WireSocks instance created with initial configuration.")
	return s, nil
}

func (s *WireSocks) Run() error {
	log.Infof("Starting WireSocks main run loop.")
	s.conf.Interface.MTU = 1330
	log.Debugf("Setting interface MTU to: %d", s.conf.Interface.MTU)

	resolver := "1.1.1.1" // Default resolver
	s.conf.Interface.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	log.Debugf("Setting DNS resolver to: %s", resolver)

	// Enable keepalive on all peers in conf
	for i, peer := range s.conf.Peers {
		peer.KeepAlive = 5
		log.Debugf("Setting KeepAlive for peer %d to %d seconds.", i, peer.KeepAlive)

		addr, err := ParseResolveAddressPort(peer.Endpoint, true, resolver)
		if err == nil {
			log.Debugf("Resolved peer endpoint %s to %s", peer.Endpoint, addr.String())
			peer.Endpoint = addr.String()
		} else {
			log.Warnf("Failed to resolve peer endpoint: %s, using original. Error: %v", peer.Endpoint, err)
		}

		s.conf.Peers[i] = peer
	}

	// Establish wireguard on userspace stack
	log.Infof("Attempting to create WireGuard device.")
	dev, tnet, err := createWireguardDevice(s.ctx, s.conf, s.testURL)
	if err != nil {
		log.Fatalf("Failed to create WireGuard device: %v", err)
		return err
	}
	if dev != nil {
		defer func() {
			log.Infof("Closing WireGuard device.")
			dev.Close()
		}()
	}

	opts := &ProxyOptions{
		SocksBindAddress: s.socksBindAddress,
		HttpBindAddress:  s.httpBindAddress,
	}

	proxy := NewProxyServer(tnet, opts)
	log.Infof("Starting proxy server.")
	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
		return err
	}

	log.Infof("WireSocks is running. Waiting for shutdown signal.")
	<-s.ctx.Done()

	log.Infof("Shutdown signal received. Stopping proxy server.")
	proxy.Stop()

	log.Infof("WireSocks main run loop finished.")
	return nil
}

func (s *WireSocks) Stop() {
	log.Infof("Initiating WireSocks shutdown.")
	s.cancel()
}

type option func(*WireSocks)

func (s *WireSocks) WithTestURL(testURL string) {
	s.testURL = testURL
	log.Debugf("Set test URL to: %s", testURL)
}

func (s *WireSocks) WithPeer(peer PeerConfig) {
	s.conf.Peers = append(s.conf.Peers, peer)
	log.Debugf("Added peer with public key (first 8 chars): %s", peer.PublicKey[:8])
}

func (s *WireSocks) WithPrivateKey(key string) {
	s.conf.Interface.PrivateKey = key
	log.Debugf("Set private key (first 8 chars): %s", key[:8])
}

func (s *WireSocks) WithConfig(conf *Configuration) {
	s.conf = conf
	log.Debugf("Set configuration from external source.")
}

func (s *WireSocks) WithSocksBindAddr(addr netip.AddrPort) {
	s.socksBindAddress = &addr
	log.Debugf("Set SOCKS bind address to: %s", addr.String())
}

func (s *WireSocks) WithHTTPBindAddr(addr netip.AddrPort) {
	s.httpBindAddress = &addr
	log.Debugf("Set HTTP bind address to: %s", addr.String())
}
