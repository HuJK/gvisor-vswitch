// gvswitch is a pure user-space virtual switch with per-VLAN NAT gateways,
// controlled over a REST API.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/HuJK/gvisor-vswitch/internal/api"
	"github.com/HuJK/gvisor-vswitch/internal/manager"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		listen      string
		configPath  string
		authToken   string
		stpEnable   bool
		stpPriority uint
	)
	flag.StringVar(&listen, "listen", "", "control socket: \"ip:port\" = tcp4, \"[ip]:port\" = tcp6, otherwise a unix socket path")
	flag.StringVar(&configPath, "config", "", "optional JSON config replayed at startup")
	flag.StringVar(&authToken, "auth-token", os.Getenv("GVSWITCH_AUTH_TOKEN"),
		"require `Authorization: Bearer <token>` on the API (default: $GVSWITCH_AUTH_TOKEN; empty = no auth)")
	flag.BoolVar(&stpEnable, "stp", false, "enable spanning tree (802.1D) with default timers; ports join via stp:true")
	flag.UintVar(&stpPriority, "stp-priority", 32768, "bridge priority for STP root election")
	flag.Parse()

	if listen == "" {
		fmt.Fprintln(os.Stderr, "[!] -listen is required")
		flag.Usage()
		return 2
	}

	m := manager.New()
	defer m.Close()

	if stpEnable {
		if err := m.SetSTP(api.STPRequest{Enabled: true, Priority: uint16(stpPriority)}); err != nil {
			fmt.Fprintf(os.Stderr, "[!] stp: %v\n", err)
			return 1
		}
	}

	if configPath != "" {
		if err := m.ReplayConfig(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "[!] config %s: %v\n", configPath, err)
			return 1
		}
	}

	srv, err := api.Listen(listen, authToken, m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		return 1
	}
	defer srv.Close()
	fmt.Fprintf(os.Stderr, "[+] gvswitch control API on %s\n", srv.Addr())

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Fprintf(os.Stderr, "[-] signal %v received, shutting down\n", sig)
	return 0
}
