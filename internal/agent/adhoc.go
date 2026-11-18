package agent

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jgermade/intergate/internal/client"
)

// adhoc forwards one subdomain now, as flags say, with the user's keys.
type adhoc struct {
	server, hostKey, dashboard, http *string
	tcp, udp, identities             multi
}

func adhocFlags(fs *flag.FlagSet) *adhoc {
	a := &adhoc{
		server:    fs.String("server", os.Getenv("INTERGATE_SERVER"), "with HOST, the gate's SSH endpoint `HOST[:PORT]` (or $INTERGATE_SERVER); HOST is then just the subdomain"),
		hostKey:   fs.String("host-key", os.Getenv("INTERGATE_HOST_KEY"), "with HOST, the gate's host key `SHA256:...` (or $INTERGATE_HOST_KEY); otherwise its dashboard's or ~/.ssh/known_hosts"),
		dashboard: fs.String("dashboard", "", "with HOST, the gate's dashboard `URL`, when it is not HOST without its first label"),
		http:      fs.String("http", "", "with HOST, forward the HTTP tunnel to this local `PORT` (or HOST:PORT)"),
	}
	fs.Var(&a.tcp, "tcp", "with HOST, forward the TCP port `NAME=PORT` (repeatable)")
	fs.Var(&a.udp, "udp", "with HOST, forward the UDP port `NAME=PORT` (repeatable)")
	fs.Var(&a.identities, "i", "with HOST, a private key `FILE` (repeatable); by default ssh-agent and ~/.ssh/id_*")
	return a
}

func (a *adhoc) run(host string) error {
	var forwards []client.Forward
	if *a.http != "" {
		f, err := client.ParseForward(client.HTTP, *a.http)
		if err != nil {
			return err
		}
		forwards = append(forwards, f)
	}
	for _, kind := range []string{client.TCP, client.UDP} {
		list := a.tcp
		if kind == client.UDP {
			list = a.udp
		}
		for _, v := range list {
			f, err := client.ParseForward(kind, v)
			if err != nil {
				return err
			}
			forwards = append(forwards, f)
		}
	}
	if len(forwards) == 0 {
		return errors.New("nothing to forward: add --http, --tcp or --udp")
	}
	ctx, cancel := signalContext()
	defer cancel()

	addr, sub, hostKey := *a.server, strings.ToLower(host), *a.hostKey
	if addr == "" {
		_, s, g, _, err := gateFor(ctx, &Config{Gates: map[string]*Gate{}}, host, *a.dashboard, hostKey)
		if err != nil {
			return err
		}
		addr, sub, hostKey = g.Server, s, cmp.Or(hostKey, g.HostKey)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}
	auth, err := client.AuthMethods(a.identities)
	if err != nil {
		return err
	}
	check, err := client.HostKeyCheck(hostKey)
	if err != nil {
		return err
	}
	for _, f := range forwards {
		fmt.Printf("intergate: %s: %s\n", sub, f)
	}
	return client.Run(ctx, client.Options{
		Server: addr, Subdomain: sub, Forwards: forwards, Auth: auth, HostKey: check, Out: os.Stdout,
	})
}

// RunAdhoc is `intergate tunnel`: one subdomain, as args say, now.
func RunAdhoc(args []string, usageText string) error {
	fs := flag.NewFlagSet("intergate tunnel", flag.ContinueOnError)
	a := adhocFlags(fs)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
		fs.PrintDefaults()
	}
	pos, err := parse(fs, args)
	if err != nil {
		return quiet(err)
	}
	if len(pos) != 1 {
		fs.Usage()
		return ErrQuiet
	}
	if *a.server == "" && !strings.Contains(pos[0], ".") && *a.dashboard == "" {
		return errors.New("which server? Pass --server HOST[:PORT] (the dashboard shows it), or the full name, like myapp.gate.example.com")
	}
	return a.run(pos[0])
}
