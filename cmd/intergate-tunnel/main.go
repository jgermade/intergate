// Command intergate-tunnel keeps a machine's intergate tunnels open, as a
// service: subdomains of one or more gates, each with its HTTP tunnel and
// TCP or UDP ports. It is the client half of intergate, without the server.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/jgermade/intergate/internal/agent"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := agent.Main(os.Args[1:], version); err != nil {
		if !errors.Is(err, agent.ErrQuiet) {
			fmt.Fprintln(os.Stderr, "intergate-tunnel:", err)
		}
		os.Exit(1)
	}
}
