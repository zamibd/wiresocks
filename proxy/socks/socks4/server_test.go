package socks4

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestServer_Connect(t *testing.T) {
	// Create a new server
	s := NewServer(WithBind("127.0.0.1:0"))

	// Use a WaitGroup to wait for the server to start
	var wg sync.WaitGroup
	wg.Add(1)

	// Start the server in a new goroutine
	go func() {
		wg.Done()
		if err := s.ListenAndServe(); err != nil && err != net.ErrClosed {
			t.Errorf("failed to start server: %v", err)
		}
	}()

	// Wait for the server to start
	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	// Create a client connection
	conn, err := net.Dial("tcp", s.Bind)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// Send a connect request
	req := &Request{
		Version: Socks4Version,
		Command: ConnectCommand,
		DestAddr: &Address{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 1234,
		},
		User: "test",
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	// Read the reply
	rep, err := readReply(conn)
	if err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}

	// Check the reply
	if rep.Code != GrantedReply {
		t.Errorf("unexpected reply code: got %v, want %v", rep.Code, GrantedReply)
	}

	// Close the server
	if err := s.Listener.Close(); err != nil {
		t.Errorf("failed to close server: %v", err)
	}
}

func TestServer_Bind(t *testing.T) {
	// Create a new server
	s := NewServer(WithBind("127.0.0.1:0"))

	// Use a WaitGroup to wait for the server to start
	var wg sync.WaitGroup
	wg.Add(1)

	// Start the server in a new goroutine
	go func() {
		wg.Done()
		if err := s.ListenAndServe(); err != nil && err != net.ErrClosed {
			t.Errorf("failed to start server: %v", err)
		}
	}()

	// Wait for the server to start
	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	// Create a client connection
	conn, err := net.Dial("tcp", s.Bind)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// Send a bind request
	req := &Request{
		Version: Socks4Version,
		Command: BindCommand,
		DestAddr: &Address{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 1234,
		},
		User: "test",
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	// Read the first reply
	rep1, err := readReply(conn)
	if err != nil {
		t.Fatalf("failed to read first reply: %v", err)
	}

	// Check the first reply
	if rep1.Code != GrantedReply {
		t.Errorf("unexpected reply code: got %v, want %v", rep1.Code, GrantedReply)
	}

	// Create a target connection
	target, err := net.Dial("tcp", rep1.Addr.String())
	if err != nil {
		t.Fatalf("failed to connect to target: %v", err)
	}
	defer func() {
		_ = target.Close()
	}()

	// Read the second reply
	rep2, err := readReply(conn)
	if err != nil {
		t.Fatalf("failed to read second reply: %v", err)
	}

	// Check the second reply
	if rep2.Code != GrantedReply {
		t.Errorf("unexpected reply code: got %v, want %v", rep2.Code, GrantedReply)
	}

	// Close the server
	if err := s.Listener.Close(); err != nil {
		t.Errorf("failed to close server: %v", err)
	}
}

func (r *Request) Bytes() []byte {
	b := make([]byte, 8+len(r.User)+1)
	b[0] = r.Version
	b[1] = byte(r.Command)
	binary.BigEndian.PutUint16(b[2:4], uint16(r.DestAddr.Port))
	copy(b[4:8], r.DestAddr.IP.To4())
	copy(b[8:], r.User)
	b[len(b)-1] = 0
	return b
}

type TestReply struct {
	Code Reply
	Addr *Address
}

func readReply(r io.Reader) (*TestReply, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return &TestReply{
		Code: Reply(buf[1]),
		Addr: &Address{
			Port: int(binary.BigEndian.Uint16(buf[2:4])),
			IP:   net.IP(buf[4:8]),
		},
	}, nil
}