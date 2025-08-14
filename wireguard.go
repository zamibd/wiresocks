package wiresocks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/shahradelahi/wiresocks/log"
)

func connectivityTest(ctx context.Context, tnet *netstack.Net, url string) error {
	log.Debugf("Starting WireGuard connectivity test to %s", url)

	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(10*time.Second))
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			log.Warnf("WireGuard connectivity test timed out or cancelled: %v", ctx.Err())
			return ctx.Err()
		default:
		}

		client := http.Client{Transport: &http.Transport{
			DialContext: tnet.DialContext,
		}}

		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			log.Errorf("Failed to create WireGuard tunnel test request: %v", err)
			// This is likely a programming error, so we'll just fail fast.
			return err
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Debugf("WireGuard tunnel connectivity test attempt failed: %v", err)
			continue
		}
		if err := resp.Body.Close(); err != nil {
			log.Warnf("Failed to close response body: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			log.Debugf("WireGuard tunnel connectivity test returned non-OK HTTP status: %d", resp.StatusCode)
			continue
		}

		log.Debugf("WireGuard tunnel connectivity test successful")
		break
	}

	return nil
}

func waitHandshake(ctx context.Context, dev *device.Device) error {
	log.Debugf("Waiting for WireGuard handshake...")
	lastHandshakeSecs := "0"
	for {
		select {
		case <-ctx.Done():
			log.Warnf("WireGuard handshake wait timed out or cancelled: %v", ctx.Err())
			return ctx.Err()
		default:
		}

		get, err := dev.IpcGet()
		if err != nil {
			log.Debugf("Failed to get IPC info from WireGuard device: %v", err)
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(get))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}

			key, value, ok := strings.Cut(line, "=")
			if !ok {
				log.Debugf("Skipping malformed IPC line: %s", line)
				continue
			}

			if key == "last_handshake_time_sec" {
				lastHandshakeSecs = value
				break
			}
		}
		if lastHandshakeSecs != "0" {
			log.Debugf("WireGuard handshake completed successfully (last handshake: %s seconds ago)", lastHandshakeSecs)
			break
		}

		log.Debugf("Still waiting for WireGuard handshake to complete...")
		time.Sleep(1 * time.Second)
	}

	return nil
}

func establishWireguard(conf *Configuration, tunDev tun.Device, fwmark uint32) (*device.Device, error) {
	log.Debugf("Establishing WireGuard device with private key (first 8 chars): %s", conf.Interface.PrivateKey[:8])
	// create the IPC message to establish the wireguard conn
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.Interface.PrivateKey))

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.Interface.PrivateKey))
	if fwmark != 0 {
		request.WriteString(fmt.Sprintf("fwmark=%d\n", fwmark))
		log.Debugf("Setting FwMark: %d", fwmark)
	}

	// AmneziaWG parameters for obfuscation
	request.WriteString("jc=10\n")
	request.WriteString("jmin=50\n")
	request.WriteString("jmax=1000\n")
	request.WriteString("s1=0\n")
	request.WriteString("s2=0\n")
	request.WriteString("h1=1\n")
	request.WriteString("h2=2\n")
	request.WriteString("h3=3\n")
	request.WriteString("h4=4\n")

	for _, peer := range conf.Peers {
		log.Debugf("Adding peer with public key (first 8 chars): %s, endpoint: %s", peer.PublicKey[:8], peer.Endpoint)
		request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
		request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.KeepAlive))
		request.WriteString(fmt.Sprintf("preshared_key=%s\n", peer.PreSharedKey))
		request.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))

		for _, cidr := range peer.AllowedIPs {
			request.WriteString(fmt.Sprintf("allowed_ip=%s\n", cidr))
		}
	}

	dev := device.NewDevice(
		tunDev,
		conn.NewDefaultBind(),
		device.NewLogger(0, ""), // WireGuard-Go's internal logger
	)

	log.Debugf("Setting IPC configuration for WireGuard device.")
	if err := dev.IpcSet(request.String()); err != nil {
		log.Errorf("Failed to set IPC configuration for WireGuard device: %v", err)
		return nil, err
	}

	log.Debugf("Bringing up WireGuard device.")
	if err := dev.Up(); err != nil {
		log.Errorf("Failed to bring up WireGuard device: %v", err)
		return nil, err
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(15*time.Second))
	defer cancel()

	if err := waitHandshake(ctx, dev); err != nil {
		log.Errorf("WireGuard handshake failed: %v", err)
		if err := dev.BindClose(); err != nil {
			log.Warnf("Failed to close WireGuard device bind: %v", err)
		}
		dev.Close()
		return nil, err
	}

	log.Debugf("WireGuard device established successfully.")
	return dev, nil
}

func createWireguardDevice(ctx context.Context, conf *Configuration, testURL string) (*device.Device, *netstack.Net, error) {
	log.Debugf("Creating netstack TUN device with addresses: %v, DNS: %v, MTU: %d", conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)

	var interfaceAddrs []netip.Addr
	for _, prefix := range conf.Interface.Addresses {
		interfaceAddrs = append(interfaceAddrs, prefix.Addr())
	}

	tunDev, tnet, err := netstack.CreateNetTUN(interfaceAddrs, conf.Interface.DNS, conf.Interface.MTU)
	if err != nil {
		log.Errorf("Failed to create netstack TUN device: %v", err)
		return nil, nil, err
	}

	log.Debugf("Establishing WireGuard connection")
	dev, err := establishWireguard(conf, tunDev, conf.Interface.FwMark)
	if err != nil {
		log.Errorf("Failed to establish WireGuard connection: %v", err)
		return nil, nil, err
	}

	// Test wireguard connectivity
	log.Debugf("Testing WireGuard connection")
	err = connectivityTest(ctx, tnet, testURL)
	if err != nil {
		log.Errorf("WireGuard connectivity test failed: %v", err)
		dev.Close()
		return nil, nil, err
	}

	log.Debugf("WireGuard device and netstack created successfully.")
	return dev, tnet, nil
}
