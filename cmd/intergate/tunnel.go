package main

import (
	"errors"

	"github.com/jgermade/intergate/internal/agent"
)

const tunnelUsage = `Usage: intergate tunnel [flags] SUBDOMAIN

Forwards a subdomain's HTTP tunnel and ports from this machine, UDP
included, which plain ssh -R can't carry. It reconnects when the
connection drops.

  intergate tunnel --server gate.example.com:2222 myapp \
    --http 3000 --tcp db=5432 --udp mc=19132
  intergate tunnel myapp.gate.example.com --http 3000

To keep tunnels open as a service, see intergate-tunnel.

Flags:
`

func cmdTunnel(args []string) error {
	err := agent.RunAdhoc(args, tunnelUsage)
	if errors.Is(err, agent.ErrQuiet) {
		return errQuiet
	}
	return err
}
