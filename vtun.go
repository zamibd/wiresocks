package wiresocks

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/shahradelahi/wiresocks/log"
	"github.com/shahradelahi/wiresocks/proxy/statute"
)

// virtualTun stores a reference to netstack network and DNS configuration
type virtualTun struct {
	Tnet *netstack.Net
	Dev  *device.Device
	Ctx  context.Context
	pool buf.Allocator
	//pool bufferpool.BufPool
}

var BuffSize = 65536

func (vt *virtualTun) handler(req *statute.ProxyRequest) error {
	log.Debugf("Handling virtual tunnel connection for protocol: %s, destination: %s", req.Network, req.Destination)

	conn, err := vt.Tnet.Dial(req.Network, req.Destination)
	if err != nil {
		log.Errorf("Failed to dial virtual tunnel for %s://%s: %v", req.Network, req.Destination, err)
		return err
	}
	log.Debugf("Successfully dialed virtual tunnel for %s://%s", req.Network, req.Destination)

	timeout := 0 * time.Second
	switch req.Network {
	case "udp", "udp4", "udp6":
		timeout = 15 * time.Second
		log.Debugf("Setting UDP timeout to %v for %s://%s", timeout, req.Network, req.Destination)
	}

	// Close the connections when this function exits
	defer func() {
		log.Debugf("Closing virtual tunnel connection to %s://%s", req.Network, req.Destination)
		_ = conn.Close()
		log.Debugf("Closing client connection for %s://%s", req.Network, req.Destination)
		_ = req.Conn.Close()
	}()

	// Channel to notify when copy operation is done
	done := make(chan error, 1)

	// Copy data from req.Conn to conn
	go func() {
		buf1 := vt.pool.Get(BuffSize)
		defer func(pool buf.Allocator, buf []byte) {
			_ = pool.Put(buf)
		}(vt.pool, buf1)
		log.Debugf("Starting copy from client to virtual tunnel for %s://%s", req.Network, req.Destination)
		_, err := copyConnTimeout(conn, req.Conn, buf1, timeout)
		if errors.Is(err, syscall.ECONNRESET) {
			log.Debugf("Connection reset by peer during copy from client to virtual tunnel for %s://%s", req.Network, req.Destination)
			done <- nil
			return
		}
		done <- err
	}()

	// Copy data from conn to req.Conn
	go func() {
		buf2 := vt.pool.Get(BuffSize)
		defer func(pool buf.Allocator, buf []byte) {
			_ = pool.Put(buf)
		}(vt.pool, buf2)
		log.Debugf("Starting copy from virtual tunnel to client for %s://%s", req.Network, req.Destination)
		_, err := copyConnTimeout(req.Conn, conn, buf2, timeout)
		done <- err
	}()

	// Wait for one of the copy operations to finish
	err = <-done
	if err != nil {
		log.Warnf("An error occurred during proxy connection handling for %s://%s: %v", req.Network, req.Destination, err)
	}

	// Close connections and wait for the other copy operation to finish
	<-done
	log.Debugf("Finished proxy connection handling for %s://%s", req.Network, req.Destination)
	return nil
}

func (vt *virtualTun) Stop() {
	if vt.Dev != nil {
		log.Infof("Shutting down virtual tunnel device.")
		if err := vt.Dev.Down(); err != nil {
			log.Warnf("Failed to gracefully shut down the virtual tunnel device: %v", err)
		}
	} else {
		log.Debugf("Virtual tunnel device not initialized, nothing to stop.")
	}
}

func copyConnTimeout(dst net.Conn, src net.Conn, buf []byte, timeout time.Duration) (written int64, err error) {
	if buf != nil && len(buf) == 0 {
		log.Errorf("Empty buffer provided to copyConnTimeout.")
		panic("empty buffer in CopyBuffer")
	}

	for {
		deadline := time.Time{}
		if timeout != 0 {
			deadline = time.Now().Add(timeout)
		}
		if err := src.SetReadDeadline(deadline); err != nil {
			log.Errorf("Failed to set read deadline on source connection: %v", err)
			return written, err
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				log.Errorf("Error writing to destination connection: %v", ew)
				err = ew
				break
			}
			if nr != nw {
				log.Warnf("Short write to destination connection: wrote %d, expected %d", nw, nr)
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				log.Errorf("Error reading from source connection: %v", er)
				err = er
			}
			break
		}
	}
	return written, err
}
