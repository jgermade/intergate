package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mattn/go-isatty"
	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/client"
	"github.com/jgermade/intergate/internal/wire"
)

// ErrQuiet is a failure already reported to the user.
var ErrQuiet = errors.New("failed")

const usage = `intergate-tunnel keeps this machine's tunnels open: subdomains of one or
more intergate gates, each with its HTTP tunnel and TCP or UDP ports.

Usage:
  intergate-tunnel setup                 set it all up in an interactive wizard
  intergate-tunnel add HOST [flags]      forward a subdomain, or more of it, from here
  intergate-tunnel remove HOST [flags]   stop forwarding a subdomain, or part of it
  intergate-tunnel allow HOST PORT ADDR… change who may connect to a port (any for anyone)
  intergate-tunnel ports HOST            list a subdomain's ports on its gate
  intergate-tunnel status                how every tunnel fares
  intergate-tunnel key                   print this machine's public key
  intergate-tunnel install [--user]      run as a service, started at boot
  intergate-tunnel uninstall [--user]    stop and remove the service
  intergate-tunnel run                   forward everything configured, in the foreground
  intergate-tunnel run HOST [flags]      forward one subdomain now, without saving anything
  intergate-tunnel version               print the version

HOST is the tunnel's full name, like web1.gate.example.com: its gate's
dashboard is gate.example.com. For a dashboard elsewhere, give it with
--dashboard and HOST as just the subdomain.

  sudo intergate-tunnel add web1.gate.example.com --http 8080 --tcp db=5432 --allow 203.0.113.7
  sudo intergate-tunnel add web2.gate.example2.com --http 8090 --udp mc=19132@30100 --allow any
  sudo intergate-tunnel install

The machine's configuration is /etc/intergate-tunnel/tunnels.yaml (with
sudo); --user uses ~/.config/intergate-tunnel and a service of your own.
Every command takes --config FILE.
`

// Main runs intergate-tunnel with args (without the program's name).
func Main(args []string, version string) error {
	if len(args) == 0 {
		if isTerminal() {
			return cmdSetup(nil)
		}
		fmt.Print(usage)
		return nil
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "setup":
		return cmdSetup(args)
	case "add":
		return cmdAdd(args)
	case "remove":
		return cmdRemove(args)
	case "allow":
		return cmdAllow(args)
	case "ports":
		return cmdPorts(args)
	case "status":
		return cmdStatus(args)
	case "key":
		return cmdKey(args)
	case "install":
		return cmdInstall(args)
	case "uninstall":
		return cmdUninstall(args)
	case "run":
		return cmdRun(args)
	case "version", "--version", "-version":
		fmt.Println("intergate-tunnel", version)
		return nil
	case "help", "--help", "-help", "-h":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

// cmdSetup is replaced by the wizard when it is built in.
var cmdSetup = func(args []string) error {
	fmt.Print(usage)
	return nil
}

// isTerminal reports whether someone is there to answer: stdin and stdout
// are a terminal.
func isTerminal() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
}

// common are the flags every command takes.
type common struct {
	config string
	user   bool
}

func newFlags(name string, usageText string) (*flag.FlagSet, *common) {
	fs := flag.NewFlagSet("intergate-tunnel "+name, flag.ContinueOnError)
	c := &common{}
	fs.StringVar(&c.config, "config", "", "the configuration `FILE`")
	fs.BoolVar(&c.user, "user", false, "use your own configuration and service, not the machine's")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
		fs.PrintDefaults()
	}
	return fs, c
}

// parse reads args, positional arguments anywhere among the flags.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, flag.ErrHelp
			}
			return nil, ErrQuiet
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// paths picks the configuration: --config, --user, the machine's with
// root or when it exists, else the user's.
func (c *common) paths() (Paths, error) {
	sys := SystemPaths()
	var p Paths
	switch {
	case c.user:
		up, err := UserPaths()
		if err != nil {
			return Paths{}, err
		}
		p = up
	case os.Geteuid() == 0:
		p = sys
	default:
		if _, err := os.Stat(sys.Config); err == nil {
			p = sys
		} else if up, err := UserPaths(); err == nil {
			p = up
		} else {
			p = sys
		}
	}
	if c.config != "" {
		// A configuration of its own keeps its daemon's status beside it.
		p.Config = c.config
		p.Status = filepath.Join(filepath.Dir(c.config), "status.json")
	}
	return p, nil
}

// load reads the configuration; write says it will be changed, which the
// machine's needs root for.
func (c *common) load(write bool) (Paths, *Config, error) {
	p, err := c.paths()
	if err != nil {
		return p, nil, err
	}
	if write && !p.User && os.Geteuid() != 0 && c.config == "" {
		return p, nil, fmt.Errorf("changing %s needs root: run it with sudo, or pass --user for a configuration of your own", p.Config)
	}
	cfg, err := LoadConfig(p.Config)
	return p, cfg, err
}

// save writes cfg and tells a running service.
func save(p Paths, cfg *Config) error {
	if err := cfg.Save(); err != nil {
		return err
	}
	if err := p.ShareWithService(cfg); err != nil {
		return err
	}
	if p.Active() {
		if err := p.Reload(); err != nil {
			return err
		}
		fmt.Println("The service picked up the change.")
	} else if st, err := ReadStatus(p.Status); err == nil && processAlive(st.PID) {
		// intergate-tunnel run, in a terminal of its own.
		if proc, err := os.FindProcess(st.PID); err == nil && proc.Signal(syscall.SIGHUP) == nil {
			fmt.Println("intergate-tunnel run picked up the change.")
		}
	} else if !p.Installed() {
		user := ""
		if p.User {
			user = " --user"
		}
		fmt.Printf("Saved. To keep it running: %sintergate-tunnel install%s (or intergate-tunnel run%s)\n", sudo(p), user, user)
	}
	return nil
}

func sudo(p Paths) string {
	if p.User || os.Geteuid() == 0 {
		return ""
	}
	return "sudo "
}

// portFlag is --tcp or --udp NAME=LOCAL[@PUBLIC].
type portFlag struct {
	name, local string
	public      int
}

func parsePortFlag(kind, v string) (portFlag, error) {
	var pf portFlag
	if i := strings.LastIndexByte(v, '@'); i >= 0 {
		n, err := strconv.Atoi(v[i+1:])
		if err != nil || n < 1 || n > 65535 {
			return pf, fmt.Errorf("--%s %q: the public port after @ must be a number", kind, v)
		}
		pf.public, v = n, v[:i]
	}
	f, err := client.ParseForward(kind, v)
	if err != nil {
		return pf, err
	}
	_, local, _ := strings.Cut(v, "=")
	pf.name, pf.local = f.Name, local
	return pf, nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// gateFor finds or discovers the gate of host, returning its domain and
// the subdomain. A new gate's host key is pinned from its /client.json,
// which only an HTTPS dashboard vouches for.
func gateFor(ctx context.Context, cfg *Config, host, dashboard, hostKey string) (string, string, *Gate, bool, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if dashboard == "" {
		if domain, sub, ok := cfg.Find(host); ok {
			return domain, sub, cfg.Gates[domain], false, nil
		}
		sub, rest, ok := strings.Cut(host, ".")
		if !ok || !strings.Contains(rest, ".") {
			return "", "", nil, false, fmt.Errorf("%q is not a tunnel's full name, like web1.gate.example.com; for just a subdomain, give its dashboard with --dashboard", host)
		}
		info, err := client.Discover(ctx, rest, nil)
		if err != nil {
			return "", "", nil, false, fmt.Errorf("%w; if the dashboard is elsewhere, give it with --dashboard", err)
		}
		if info.Domain != rest {
			return "", "", nil, false, fmt.Errorf("%s says its tunnels are on %s, not %s: give its dashboard with --dashboard", rest, info.Domain, rest)
		}
		g, err := newGate(info, hostKey, strings.HasPrefix(info.Dashboard, "https://"))
		return rest, sub, g, true, err
	}
	info, err := client.Discover(ctx, dashboard, nil)
	if err != nil {
		return "", "", nil, false, err
	}
	sub := strings.TrimSuffix(host, "."+info.Domain)
	if sub == "" || strings.Contains(sub, ".") {
		return "", "", nil, false, fmt.Errorf("%q is not a subdomain of %s", host, info.Domain)
	}
	if g, ok := cfg.Gates[info.Domain]; ok {
		return info.Domain, sub, g, false, nil
	}
	u, _ := client.DashboardURL(dashboard)
	g, err := newGate(info, hostKey, u.Scheme == "https")
	return info.Domain, sub, g, true, err
}

// errNotHTTPS is returned, with the gate, when nothing vouches for its
// host key: its dashboard is on plain HTTP and none was given to check.
var errNotHTTPS = errors.New("the dashboard is not on HTTPS, so its host key can't be trusted")

func newGate(info *client.GateInfo, hostKey string, https bool) (*Gate, error) {
	g := &Gate{Dashboard: info.Dashboard, Server: info.Server, HostKey: info.HostKey, Tunnels: map[string]*Tunnel{}}
	switch {
	case hostKey != "" && hostKey != info.HostKey:
		return nil, fmt.Errorf("the gate's host key is %s, not %s", info.HostKey, hostKey)
	case hostKey == "" && !https:
		return g, fmt.Errorf("%w: check it there and pass --host-key %s", errNotHTTPS, info.HostKey)
	}
	return g, nil
}

func sshAuth(s ssh.Signer) []ssh.AuthMethod { return []ssh.AuthMethod{ssh.PublicKeys(s)} }

// connect signs in to g as sub with the machine's key. With wait, and a
// terminal, it shows the key and waits for someone to add it.
func connect(ctx context.Context, cfg *Config, g *Gate, sub string, wait bool) (*ssh.Client, error) {
	signer, created, err := cfg.LoadKey(true)
	if err != nil {
		return nil, err
	}
	if created {
		fmt.Println("Created this machine's key:", cfg.KeyPath())
	}
	check, err := client.HostKeyCheck(g.HostKey)
	if err != nil {
		return nil, err
	}
	auth := []ssh.AuthMethod{ssh.PublicKeys(signer)}
	told := false
	for {
		c, err := client.Dial(g.Server, sub, auth, check)
		if err == nil {
			if told {
				fmt.Println("✔ The key is authorized.")
			}
			return c, nil
		}
		if !strings.Contains(err.Error(), "unable to authenticate") {
			return nil, err
		}
		if !told {
			fmt.Printf("\nThe gate doesn't know this machine's key yet. Add it to %s at\n  %s/subdomains/%s\n(or to your account's SSH keys, then to the subdomain):\n\n  %s\n\n",
				sub, g.Dashboard, sub, AuthorizedKey(signer))
			told = true
		}
		if !wait || !isTerminal() {
			return nil, errors.New("the key is not authorized yet: add it, then run this again")
		}
		fmt.Print("\rWaiting for it… (Ctrl-C to stop) ")
		select {
		case <-ctx.Done():
			fmt.Println()
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

const addUsage = `Usage: intergate-tunnel add HOST [flags]

Forwards HOST (web1.gate.example.com) from this machine, or more of it, and
saves it. Ports are named as on the gate: one that doesn't exist yet is
created, with --allow saying who may connect, and NAME=LOCAL@PUBLIC asking
for its public number.

  intergate-tunnel add web1.gate.example.com --http 8080
  intergate-tunnel add web1.gate.example.com --tcp db=5432 --allow 203.0.113.0/24
  intergate-tunnel add web1.gate.example.com --udp mc=19132@30100 --allow any

Flags:
`

func cmdAdd(args []string) error {
	fs, c := newFlags("add", addUsage)
	var httpLocal, dashboard, hostKey string
	var tcp, udp, allow multi
	fs.StringVar(&httpLocal, "http", "", "forward the HTTP tunnel to this local `PORT` (or HOST:PORT)")
	fs.Var(&tcp, "tcp", "forward the TCP port `NAME=PORT[@PUBLIC]` (repeatable)")
	fs.Var(&udp, "udp", "forward the UDP port `NAME=PORT[@PUBLIC]` (repeatable)")
	fs.Var(&allow, "allow", "for ports it creates: an `ADDRESS` or CIDR that may connect, or any (repeatable)")
	fs.StringVar(&dashboard, "dashboard", "", "the gate's dashboard `URL`, when it is not HOST without its first label")
	fs.StringVar(&hostKey, "host-key", "", "the gate's host key `SHA256:...`, to check against")
	pos, err := parse(fs, args)
	if err != nil {
		return quiet(err)
	}
	if len(pos) != 1 {
		fs.Usage()
		return ErrQuiet
	}
	req := Request{HTTP: httpLocal, Allow: allow}
	for kind, list := range map[string]multi{client.TCP: tcp, client.UDP: udp} {
		for _, v := range list {
			pf, err := parsePortFlag(kind, v)
			if err != nil {
				return err
			}
			req.Ports = append(req.Ports, PortRequest{Kind: kind, Name: pf.name, Local: pf.local, Public: pf.public})
		}
	}
	if req.HTTP == "" && len(req.Ports) == 0 {
		return errors.New("nothing to forward: add --http, --tcp or --udp (or run intergate-tunnel setup)")
	}
	p, cfg, err := c.load(true)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	domain, sub, g, isNew, err := gateFor(ctx, cfg, pos[0], dashboard, hostKey)
	if err != nil {
		return err
	}
	if isNew {
		fmt.Printf("Gate %s: SSH %s, host key %s\n", domain, g.Server, g.HostKey)
	}
	conn, err := connect(ctx, cfg, g, sub, true)
	if err != nil {
		return err
	}
	defer conn.Close()
	t, made, err := Apply(conn, g, sub, req)
	if err != nil {
		return err
	}
	for _, line := range made {
		fmt.Println(line)
	}
	cfg.Gates[domain] = g
	g.Tunnels[sub] = t
	return save(p, cfg)
}

func quiet(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

// Request is what to add to a tunnel.
type Request struct {
	HTTP  string
	Ports []PortRequest
	// Allow is who may connect to the ports it creates.
	Allow []string
}

// PortRequest is one port to forward; Public is the number asked for,
// should it be created.
type PortRequest struct {
	Kind, Name, Local string
	Public            int
}

// Apply adds req to sub's tunnel on g, creating on the gate the ports it
// lacks, and returns the tunnel and what it did.
func Apply(conn client.Requester, g *Gate, sub string, req Request) (*Tunnel, []string, error) {
	info, err := client.Info(conn, sub)
	if err != nil {
		return nil, nil, err
	}
	var have []wire.Port
	if len(info.Subdomains) == 1 {
		have = info.Subdomains[0].Ports
	}
	t := &Tunnel{}
	if old := g.Tunnels[sub]; old != nil {
		*t = *old
		t.TCP, t.UDP = cloneMap(old.TCP), cloneMap(old.UDP)
	}
	if req.HTTP != "" {
		if _, err := client.ParseForward(client.HTTP, req.HTTP); err != nil {
			return nil, nil, err
		}
		t.HTTP = req.HTTP
	}
	var done []string
	for _, pr := range req.Ports {
		i := slices.IndexFunc(have, func(p wire.Port) bool { return p.Name == pr.Name })
		switch {
		case i >= 0 && have[i].Protocol != pr.Kind:
			return nil, nil, fmt.Errorf("%s.%s is a %s port on the gate, not %s", pr.Name, sub, strings.ToUpper(have[i].Protocol), strings.ToUpper(pr.Kind))
		case i >= 0:
			done = append(done, fmt.Sprintf("  %s %s → %s", pr.Name, have[i].Address, pr.Local))
		case len(req.Allow) == 0:
			return nil, nil, fmt.Errorf("%s has no port %s yet: to create it, say who may connect with --allow ADDRESS (or --allow any)", sub, pr.Name)
		default:
			p, err := client.AddPort(conn, wire.PortAdd{
				PortRef: wire.PortRef{Subdomain: sub, Name: pr.Name}, Protocol: pr.Kind,
				Allow: req.Allow, Port: pr.Public, LocalPort: localPort(pr.Local),
			})
			if err != nil {
				return nil, nil, fmt.Errorf("create %s.%s: %w", pr.Name, sub, err)
			}
			done = append(done, fmt.Sprintf("  %s %s → %s (created, open to %s)", pr.Name, p.Address, pr.Local, describeAllow(p.Allow)))
		}
		if pr.Kind == client.TCP {
			t.TCP = setKey(t.TCP, pr.Name, pr.Local)
		} else {
			t.UDP = setKey(t.UDP, pr.Name, pr.Local)
		}
	}
	return t, done, nil
}

func describeAllow(allow []string) string {
	if len(allow) == 0 {
		return "anyone"
	}
	return strings.Join(allow, ", ")
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func setKey(m map[string]string, k, v string) map[string]string {
	if m == nil {
		m = map[string]string{}
	}
	m[k] = v
	return m
}

const removeUsage = `Usage: intergate-tunnel remove HOST [flags]

Stops forwarding HOST, or only what the flags name. Its ports stay on the
gate, with their numbers, unless --delete.

  intergate-tunnel remove web1.gate.example.com --udp mc
  intergate-tunnel remove web1.gate.example.com --tcp db --delete
  intergate-tunnel remove web1.gate.example.com

Flags:
`

func cmdRemove(args []string) error {
	fs, c := newFlags("remove", removeUsage)
	var httpToo, del bool
	var tcp, udp multi
	fs.BoolVar(&httpToo, "http", false, "stop forwarding the HTTP tunnel")
	fs.Var(&tcp, "tcp", "stop forwarding the TCP port `NAME` (repeatable)")
	fs.Var(&udp, "udp", "stop forwarding the UDP port `NAME` (repeatable)")
	fs.BoolVar(&del, "delete", false, "also delete those ports from the gate, freeing their numbers")
	pos, err := parse(fs, args)
	if err != nil {
		return quiet(err)
	}
	if len(pos) != 1 {
		fs.Usage()
		return ErrQuiet
	}
	p, cfg, err := c.load(true)
	if err != nil {
		return err
	}
	domain, sub, ok := cfg.Find(pos[0])
	if !ok || cfg.Gates[domain].Tunnels[sub] == nil {
		return fmt.Errorf("%s is not forwarded from here (intergate-tunnel status)", pos[0])
	}
	g := cfg.Gates[domain]
	t := g.Tunnels[sub]
	whole := !httpToo && len(tcp) == 0 && len(udp) == 0
	var gone []string // ports to delete on the gate
	if whole {
		for name := range t.TCP {
			gone = append(gone, name)
		}
		for name := range t.UDP {
			gone = append(gone, name)
		}
		delete(g.Tunnels, sub)
	} else {
		if httpToo {
			t.HTTP = ""
		}
		for kind, list := range map[string]multi{client.TCP: tcp, client.UDP: udp} {
			m := t.TCP
			if kind == client.UDP {
				m = t.UDP
			}
			for _, name := range list {
				name = strings.ToLower(name)
				if _, ok := m[name]; !ok {
					return fmt.Errorf("%s doesn't forward the %s port %s", pos[0], strings.ToUpper(kind), name)
				}
				delete(m, name)
				gone = append(gone, name)
			}
		}
		if t.Empty() {
			delete(g.Tunnels, sub)
		}
	}
	if del && len(gone) > 0 {
		ctx, cancel := signalContext()
		defer cancel()
		conn, err := connect(ctx, cfg, g, sub, false)
		if err != nil {
			return err
		}
		defer conn.Close()
		slices.Sort(gone)
		for _, name := range gone {
			if err := client.DeletePort(conn, wire.PortRef{Subdomain: sub, Name: name}); err != nil {
				return fmt.Errorf("delete %s.%s: %w", name, sub, err)
			}
			fmt.Printf("Deleted %s.%s from the gate.\n", name, sub)
		}
	}
	if len(g.Tunnels) == 0 {
		delete(cfg.Gates, domain)
	}
	return save(p, cfg)
}

const allowUsage = `Usage: intergate-tunnel allow HOST PORT ADDRESS...

Sets who may connect to one of HOST's ports: addresses and CIDRs, or any
for anyone. Connections already in keep going.

  intergate-tunnel allow web1.gate.example.com db 203.0.113.7 198.51.100.0/24
  intergate-tunnel allow web1.gate.example.com mc any

Flags:
`

func cmdAllow(args []string) error {
	fs, c := newFlags("allow", allowUsage)
	var dashboard string
	fs.StringVar(&dashboard, "dashboard", "", "the gate's dashboard `URL`")
	pos, err := parse(fs, args)
	if err != nil {
		return quiet(err)
	}
	if len(pos) < 3 {
		fs.Usage()
		return ErrQuiet
	}
	ctx, cancel := signalContext()
	defer cancel()
	_, sub, conn, err := c.dialHost(ctx, pos[0], dashboard)
	if err != nil {
		return err
	}
	defer conn.Close()
	port, err := client.UpdatePort(conn, wire.PortUpdate{PortRef: wire.PortRef{Subdomain: sub, Name: strings.ToLower(pos[1])}, Allow: pos[2:]})
	if err != nil {
		return err
	}
	fmt.Printf("%s.%s (%s) is open to %s.\n", port.Name, sub, port.Address, describeAllow(port.Allow))
	return nil
}

// dialHost connects to the gate of host, known or not, without saving it.
func (c *common) dialHost(ctx context.Context, host, dashboard string) (*Gate, string, *ssh.Client, error) {
	_, cfg, err := c.load(false)
	if err != nil {
		return nil, "", nil, err
	}
	_, sub, g, _, err := gateFor(ctx, cfg, host, dashboard, "")
	if err != nil {
		return nil, "", nil, err
	}
	if _, err := os.Stat(cfg.KeyPath()); err != nil {
		return nil, "", nil, fmt.Errorf("this machine has no key yet (%s): add a tunnel first", cfg.KeyPath())
	}
	conn, err := connect(ctx, cfg, g, sub, false)
	return g, sub, conn, err
}

func cmdPorts(args []string) error {
	fs, c := newFlags("ports", "Usage: intergate-tunnel ports HOST\n\nLists HOST's ports on its gate, and where this machine forwards them.\n\nFlags:\n")
	var dashboard string
	fs.StringVar(&dashboard, "dashboard", "", "the gate's dashboard `URL`")
	pos, err := parse(fs, args)
	if err != nil {
		return quiet(err)
	}
	if len(pos) != 1 {
		fs.Usage()
		return ErrQuiet
	}
	ctx, cancel := signalContext()
	defer cancel()
	g, sub, conn, err := c.dialHost(ctx, pos[0], dashboard)
	if err != nil {
		return err
	}
	defer conn.Close()
	info, err := client.Info(conn, sub)
	if err != nil {
		return err
	}
	s := info.Subdomains[0]
	t := g.Tunnels[sub]
	if t == nil {
		t = &Tunnel{}
	}
	fmt.Printf("%s — %d of %d ports, numbers from %s\n\n", s.URL, s.Quota.Used, s.Quota.Max, s.Quota.Ranges)
	if len(s.Ports) == 0 {
		fmt.Println("No ports yet: intergate-tunnel add", pos[0], "--tcp NAME=PORT --allow ADDRESS")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDRESS\tOPEN TO\tHERE\tCREATED BY")
	for _, p := range s.Ports {
		local := t.TCP[p.Name]
		if p.Protocol == client.UDP {
			local = t.UDP[p.Name]
		}
		if local == "" {
			local = "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Address, describeAllow(p.Allow), local, p.CreatedBy)
	}
	return w.Flush()
}

func cmdStatus(args []string) error {
	fs, c := newFlags("status", "Usage: intergate-tunnel status\n\nShows every tunnel and how it fares.\n\nFlags:\n")
	if _, err := parse(fs, args); err != nil {
		return quiet(err)
	}
	p, cfg, err := c.load(false)
	if err != nil {
		return err
	}
	if len(cfg.Gates) == 0 {
		fmt.Println("Nothing is forwarded from here yet: intergate-tunnel setup, or intergate-tunnel add HOST --http PORT")
		return nil
	}
	st, err := ReadStatus(p.Status)
	running := err == nil && processAlive(st.PID)
	switch {
	case p.Active():
		fmt.Println("The service is running.")
	case running:
		fmt.Println("intergate-tunnel run is running.")
	case p.Installed():
		fmt.Println("The service is installed but not running: systemctl", map[bool]string{true: "--user "}[p.User]+"status intergate-tunnel")
	default:
		fmt.Printf("Not running: %sintergate-tunnel install%s, or intergate-tunnel run\n", sudo(p), map[bool]string{true: " --user"}[p.User])
	}
	if running && st.Error != "" {
		fmt.Println("Configuration error:", st.Error)
	}
	byHost := map[string]TunnelStatus{}
	if running {
		for _, t := range st.Tunnels {
			byHost[t.Host] = t
		}
	}
	fmt.Println()
	cfg.Each(func(domain string, g *Gate, sub string, t *Tunnel) {
		host := Host(sub, domain)
		ts, ok := byHost[host]
		state := "—"
		if ok {
			state = describeState(ts)
		}
		fmt.Printf("%s  %s\n", host, state)
		fws, _ := t.Forwards()
		for _, f := range fws {
			line := "  " + f.String()
			if ok {
				for _, fs := range ts.Forwards {
					if fs.Kind == f.Kind && fs.Name == f.Name {
						switch {
						case fs.State == "forwarded" && fs.Port != 0:
							line += fmt.Sprintf("  ● public port %d", fs.Port)
						case fs.State == "forwarded":
							line += "  ●"
						case fs.State == "refused":
							line += "  ✖ refused"
							if fs.Reason != "" {
								line += ": " + fs.Reason
							}
						}
					}
				}
			}
			fmt.Println(line)
		}
	})
	return nil
}

func describeState(t TunnelStatus) string {
	since := time.Since(t.Since).Round(time.Second)
	switch t.State {
	case StateConnected:
		return "● connected for " + since.String()
	case StateUnauthorized:
		return "✖ " + t.Error
	case StateRefused:
		return "✖ the gate refused every forward; trying again soon"
	case StateRetrying:
		if t.Error != "" {
			return "… reconnecting: " + t.Error
		}
		return "… reconnecting"
	}
	return "… connecting"
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	return err == nil && proc.Signal(syscall.Signal(0)) == nil
}

func cmdKey(args []string) error {
	fs, c := newFlags("key", "Usage: intergate-tunnel key\n\nPrints the public key this machine signs in with, creating it if needed.\n\nFlags:\n")
	if _, err := parse(fs, args); err != nil {
		return quiet(err)
	}
	p, err := c.paths()
	if err != nil {
		return err
	}
	if c.config != "" {
		p.Config = c.config
	}
	cfg, err := LoadConfig(p.Config)
	if err != nil {
		return err
	}
	_, statErr := os.Stat(cfg.KeyPath())
	create := statErr != nil && (p.User || os.Geteuid() == 0 || c.config != "")
	signer, created, err := cfg.LoadKey(create)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("this machine has no key yet: run it with sudo to create it, or pass --user")
	}
	if err != nil {
		return err
	}
	if created {
		if err := p.ShareWithService(cfg); err != nil {
			return err
		}
	}
	fmt.Println(AuthorizedKey(signer))
	return nil
}

func cmdInstall(args []string) error {
	fs, c := newFlags("install", "Usage: intergate-tunnel install [--user]\n\nRuns intergate-tunnel as a service, started at boot (or, with --user,\nwhen you log in, and after you log out if allowed).\n\nFlags:\n")
	if _, err := parse(fs, args); err != nil {
		return quiet(err)
	}
	p, cfg, err := c.load(true)
	if err != nil {
		return err
	}
	if _, _, err := cfg.LoadKey(true); err != nil {
		return err
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	if err := p.Install(cfg, os.Stdout); err != nil {
		return err
	}
	user := map[bool]string{true: " --user"}[p.User]
	fmt.Printf("\nintergate-tunnel runs as a service.\n  status:  intergate-tunnel status%s\n  logs:    journalctl%s -u intergate-tunnel -f\n", user, user)
	if len(cfg.Gates) == 0 {
		fmt.Printf("  next:    %sintergate-tunnel add HOST --http PORT%s\n", sudo(p), user)
	}
	return nil
}

func cmdUninstall(args []string) error {
	fs, c := newFlags("uninstall", "Usage: intergate-tunnel uninstall [--user]\n\nStops and removes the service; the configuration and key stay.\n\nFlags:\n")
	if _, err := parse(fs, args); err != nil {
		return quiet(err)
	}
	p, err := c.paths()
	if err != nil {
		return err
	}
	if err := p.Uninstall(os.Stdout); err != nil {
		return err
	}
	fmt.Printf("\nThe service was removed. %s and the key were kept.\n", p.Config)
	return nil
}

const runUsage = `Usage: intergate-tunnel run [HOST [flags]]

Without HOST, forwards everything configured until stopped, reading the
configuration again on SIGHUP: what the service runs.

With HOST, forwards it now as the flags say, without saving anything, with
your ssh-agent or ~/.ssh keys (or -i):

  intergate-tunnel run web1.gate.example.com --http 3000 --udp mc=19132
  intergate-tunnel run --server gate.example.com:2222 --host-key SHA256:... web1 --http 3000

Flags:
`

func cmdRun(args []string) error {
	fs, c := newFlags("run", runUsage)
	status := fs.String("status", "", "write the daemon's status to this `FILE`")
	ah := adhocFlags(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return quiet(err)
	}
	if len(pos) > 1 {
		fs.Usage()
		return ErrQuiet
	}
	if len(pos) == 1 {
		return ah.run(pos[0])
	}
	p, err := c.paths()
	if err != nil {
		return err
	}
	if *status != "" {
		p.Status = *status
	}
	if _, err := LoadConfig(p.Config); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, cancel := signalContext()
	defer cancel()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	reload := make(chan struct{}, 1)
	go func() {
		for range hup {
			select {
			case reload <- struct{}{}:
			default:
			}
		}
	}()
	log.Info("intergate-tunnel started", "config", p.Config, "status", p.Status)
	d := &Daemon{ConfigPath: p.Config, StatusPath: p.Status, Log: log}
	return d.Run(ctx, reload)
}
