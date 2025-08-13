package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/shahradelahi/wiresocks"
	"github.com/shahradelahi/wiresocks/internal/version"
	"github.com/shahradelahi/wiresocks/log"
)

var (
	configFile = flag.String("c", "./config.conf", "Path to the configuration file.")
	socksAddr  = flag.String("s", "127.0.0.1:1080", "SOCKS5 proxy bind address. Use an empty string to disable.")
	httpAddr   = flag.String("h", "", "HTTP proxy bind address. Use an empty string to disable.")
	verbose    = flag.Bool("v", false, "Enable verbose logging.")
	ver        = flag.Bool("version", false, "Show version information and exit.")
)

func main() {
	flag.Parse()

	if *ver {
		fmt.Println(version.String())
		fmt.Println(version.BuildString())
		return
	}

	logLevel := log.InfoLevel
	if *verbose {
		logLevel = log.DebugLevel
	}

	logger, err := log.NewLeveled(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	log.SetLogger(logger)
	log.Debugf("Logger initialized with level: %s", logLevel.String())

	if *configFile == "" {
		log.Fatalf("Path to a configuration file is required.")
	}
	log.Debugf("Using configuration file: %s", *configFile)

	conf, err := wiresocks.ParseConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}
	log.Debugf("Configuration parsed successfully: %+v", conf)

	ws, err := wiresocks.NewWireSocks()
	if err != nil {
		log.Fatalf("Failed to create a new WireSocks instance: %v", err)
	}
	log.Debugf("WireSocks instance created.")

	ws.WithConfig(conf)
	//ws.WithTestURL("https://google.com/")

	if *socksAddr != "" {
		addr, err := netip.ParseAddrPort(*socksAddr)
		if err != nil {
			log.Fatalf("Failed to parse SOCKS address: %v", err)
		}
		ws.WithSocksBindAddr(addr)
		log.Debugf("SOCKS5 proxy enabled on: %s", addr.String())
	} else {
		log.Debugf("SOCKS5 proxy disabled.")
	}

	if *httpAddr != "" {
		addr, err := netip.ParseAddrPort(*httpAddr)
		if err != nil {
			log.Fatalf("Failed to parse HTTP address: %v", err)
		}
		ws.WithHTTPBindAddr(addr)
		log.Debugf("HTTP proxy enabled on: %s", addr.String())
	} else {
		log.Debugf("HTTP proxy disabled.")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Debugf("Signal received, shutting down...")
		ws.Stop()
	}()

	log.Debugf("wiresocks is starting up (version: %s, build: %s)", version.String(), version.BuildString())

	if err := ws.Run(); err != nil {
		log.Fatalf("wiresocks failed to run: %v", err)
	}

	log.Debugf("wiresocks has been shut down.")
}
