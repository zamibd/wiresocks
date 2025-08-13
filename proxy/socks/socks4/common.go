package socks4

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	// Socks4Version is the required version number for the SOCKS4 protocol.
	Socks4Version = 0x04
	// ReplyVersion is the required version number for a SOCKS4 reply.
	ReplyVersion = 0x00
)

// Command is a SOCKS Command.
type Command byte

const (
	// ConnectCommand is a command for establishing a TCP/IP stream connection.
	ConnectCommand Command = 0x01
	// BindCommand is a command for establishing a TCP/IP port binding.
	BindCommand Command = 0x02
)

func (cmd Command) String() string {
	switch cmd {
	case ConnectCommand:
		return "CONNECT"
	case BindCommand:
		return "BIND"
	default:
		return "Unknown(" + strconv.Itoa(int(cmd)) + ")"
	}
}

// Reply is a SOCKS Command reply code.
type Reply byte

const (
	// GrantedReply is a reply for a granted request.
	GrantedReply Reply = 0x5a
	// RejectedReply is a reply for a rejected or failed request.
	RejectedReply Reply = 0x5b
	// NoIdentdReply is a reply for a rejected request because the SOCKS server cannot connect to identd on the client.
	NoIdentdReply Reply = 0x5c
	// InvalidUserReply is a reply for a rejected request because the client program and identd report different user-ids.
	InvalidUserReply Reply = 0x5d
)

func (c Reply) String() string {
	switch c {
	case GrantedReply:
		return "request granted"
	case RejectedReply:
		return "request rejected or failed"
	case NoIdentdReply:
		return "request rejected because SOCKS server cannot connect to identd on the client"
	case InvalidUserReply:
		return "request rejected because the client program and identd report different user-ids"
	default:
		return "unknown code: " + strconv.Itoa(int(c))
	}
}

// Address is a SOCKS-specific address.
type Address struct {
	// Name is the fully-qualified domain name.
	Name string
	// IP is the IP address.
	IP net.IP
	// Port is the port number.
	Port int
}

// String returns a string suitable for dialing, preferring IP-based addresses.
func (a *Address) String() string {
	if a == nil {
		return "<nil>"
	}
	port := strconv.Itoa(a.Port)
	if len(a.Name) > 0 {
		return net.JoinHostPort(a.Name, port)
	}
	return net.JoinHostPort(a.IP.String(), port)
}

// Request is a SOCKS4 request.
type Request struct {
	// Version is the SOCKS protocol version number.
	Version byte
	// Command is the SOCKS command code.
	Command Command
	// DestAddr is the destination address.
	DestAddr *Address
	// User is the user ID string.
	User string
}

// NewRequest creates a new Request from a reader.
func NewRequest(r io.Reader) (*Request, error) {
	// Read version and command
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	version, command := header[0], header[1]

	if version != Socks4Version {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	// Read port and IP
	addr := make([]byte, 6)
	if _, err := io.ReadFull(r, addr); err != nil {
		return nil, err
	}

	port := binary.BigEndian.Uint16(addr[0:2])
	ip := net.IPv4(addr[2], addr[3], addr[4], addr[5])

	// Read user
	user, err := readUntilNull(r)
	if err != nil {
		return nil, err
	}

	req := &Request{
		Version: version,
		Command: Command(command),
		User:    string(user),
		DestAddr: &Address{
			IP:   ip,
			Port: int(port),
		},
	}

	// Check for SOCKS4a
	if req.isSocks4a() {
		domain, err := readUntilNull(r)
		if err != nil {
			return nil, err
		}
		req.DestAddr.Name = string(domain)
	}

	return req, nil
}

// isSocks4a returns true if the request is a SOCKS4a request.
func (r *Request) isSocks4a() bool {
	return r.DestAddr.IP[0] == 0 && r.DestAddr.IP[1] == 0 && r.DestAddr.IP[2] == 0 && r.DestAddr.IP[3] != 0
}

// readUntilNull reads from a reader until a null byte is encountered.
func readUntilNull(r io.Reader) ([]byte, error) {
	var buf []byte
	var b [1]byte
	for {
		_, err := r.Read(b[:])
		if err != nil {
			return nil, err
		}
		if b[0] == 0 {
			return buf, nil
		}
		buf = append(buf, b[0])
	}
}

// WriteReply writes a reply to a writer.
func WriteReply(w io.Writer, reply Reply, addr *Address) error {
	if addr == nil {
		addr = &Address{}
	}
	if addr.IP == nil {
		addr.IP = net.IPv4zero
	}

	b := make([]byte, 8)
	b[0] = ReplyVersion
	b[1] = byte(reply)
	binary.BigEndian.PutUint16(b[2:4], uint16(addr.Port))
	copy(b[4:8], addr.IP.To4())

	_, err := w.Write(b)
	return err
}
