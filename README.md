# 🔌 wiresocks

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue)](./LICENSE) 
[![Go Report Card](https://goreportcard.com/badge/github.com/shahradelahi/wiresocks)](https://goreportcard.com/report/github.com/shahradelahi/wiresocks)
[![Go Reference](https://pkg.go.dev/badge/github.com/shahradelahi/wiresocks.svg)](https://pkg.go.dev/github.com/shahradelahi/wiresocks)

A user-space WireGuard client that exposes a SOCKS and HTTP proxy.

`wiresocks` allows you to connect to a WireGuard peer and route traffic from any application through the tunnel by
connecting to the local proxy server. It runs entirely in user-space, meaning it does not require elevated privileges to
operate.

## 💡 Motivation

Many WireGuard clients require kernel-level access or route all system traffic through the tunnel by default.
`wiresocks` was created to provide a more flexible, lightweight alternative that:

- **Runs without root:** Operates entirely in user-space, enhancing security and simplifying setup.
- **Offers per-application tunneling:** By exposing a proxy, it allows you to selectively route traffic from specific
  applications (like web browsers or torrent clients) without affecting the rest of your system.
- **Is simple and portable:** As a single, cross-platform binary, it is easy to deploy and run anywhere.

## ✨ Features

- **User-Space WireGuard:** Connects to a WireGuard peer without needing kernel modules or root access.
- **SOCKS and HTTP Proxy:** Exposes both SOCKS and HTTP proxies to tunnel application traffic.
- **Full SOCKS Support:** Implements SOCKS4, SOCKS4a, and SOCKS5 with TCP (`CONNECT`) and UDP (`ASSOCIATE`) support.
- **Standard Configuration:** Uses a standard `wg-quick`-style configuration file.
- **Cross-Platform:** Written in Go, it can be built for Linux, macOS, Windows, and more.

## 🚀 Installation

There are multiple ways to install `wiresocks`.

### From Source (Recommended)

To install the latest version, use `go install`:

```bash
go install github.com/shahradelahi/wiresocks/cmd/wiresocks@latest
```

### From GitHub Releases

You can download pre-compiled binaries for various operating systems and architectures from
the [GitHub Releases](https://github.com/shahradelahi/wiresocks/releases) page.

### Building from Source

Clone the repository and use the `Makefile` to build the binary.

```bash
git clone https://github.com/shahradelahi/wiresocks.git
cd wiresocks
make wiresocks
```

The compiled binary will be located in the `build/` directory.

## ⚙️ Usage

Run `wiresocks` from the command line, providing the path to your WireGuard configuration file.

```bash
./build/wiresocks -c ./config.conf
```

### Command-line Flags

- `-c <path>`: Path to the WireGuard configuration file (default: `./config.conf`).
- `-s <addr:port>`: SOCKS proxy bind address (default: `127.0.0.1:1080`). Use an empty string to disable.
- `-h <addr:port>`: HTTP proxy bind address. Disabled by default.
- `-v`: Enable verbose logging.
- `-version`: Show version information and exit.

**Example:** Run with a SOCKS proxy on port 1080 and an HTTP proxy on port 8118.

```bash
./build/wiresocks -c /etc/wireguard/wg0.conf -s 127.0.0.1:1080 -h 127.0.0.1:8118
```

## 🐳 Docker

You can also run `wiresocks` using Docker.

### Building the Image

Build the Docker image using the provided `Dockerfile`:

```bash
docker build -t wiresocks .
```

### Running the Container

When running the container, you must mount your configuration file and expose the necessary ports.

```bash
docker run -d \
  --name wiresocks \
  -v /path/to/your/config.conf:/etc/wiresocks/config.conf:ro \
  -p 1080:1080 \
  --restart=unless-stopped \
  wiresocks
```

This command runs `wiresocks` in the background, mounts your local `config.conf` as read-only, and exposes the SOCKS
proxy on port 1080.

To use an HTTP proxy, add the `-h` flag and expose its port:

```bash
docker run -d \
  --name wiresocks \
  -v /path/to/your/config.conf:/etc/wiresocks/config.conf:ro \
  -p 1080:1080 \
  -p 8118:8118 \
  --restart=unless-stopped \
  wiresocks -h 0.0.0.0:8118
```

**Note:** Inside the container, the proxy must bind to `0.0.0.0` to be accessible from outside.

## 📁 Configuration

`wiresocks` uses a configuration file format that is compatible with `wg-quick`.

The file must contain one `[Interface]` section and at least one `[Peer]` section.

**Example `config.conf`:**

```ini
[Interface]
# The private key for the client (this machine)
PrivateKey = <your-private-key>

# (Optional) IP addresses to assign to the interface
Address = 10.0.0.2/32

# (Optional) DNS servers to use for resolution
DNS = 1.1.1.1

# (Optional) MTU for the interface
MTU = 1420

[Peer]
# The public key of the WireGuard peer (the server)
PublicKey = <peer-public-key>

# (Optional) A pre-shared key for an extra layer of security
PresharedKey = <your-preshared-key>

# A comma-separated list of IPs to be routed through the tunnel
AllowedIPs = 0.0.0.0/0, ::/0

# The public endpoint of the WireGuard peer
Endpoint = <peer-ip-or-hostname>:<peer-port>

# (Optional) Keepalive interval in seconds
PersistentKeepalive = 25
```

## License

[MIT](/LICENSE) © [Shahrad Elahi](https://github.com/shahradelahi)
