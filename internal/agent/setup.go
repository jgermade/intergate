package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/jgermade/intergate/internal/client"
	"github.com/jgermade/intergate/internal/wire"
)

func init() { cmdSetup = runSetup }

const setupUsage = `Usage: intergate-tunnel setup [--user] [--accessible]

Sets up this machine's tunnels in an interactive wizard: which subdomains
of which gates, what they forward, the ports they need on the gate, and the
service that keeps them open.

Flags:
`

// setup is the wizard's state.
type setup struct {
	ctx        context.Context
	paths      Paths
	cfg        *Config
	accessible bool
	in         io.Reader
}

func runSetup(args []string) error {
	fs, c := newFlags("setup", setupUsage)
	accessible := fs.Bool("accessible", strings.EqualFold(os.Getenv("ACCESSIBLE"), "1"), "plain prompts instead of full-screen forms (for screen readers and scripts)")
	if _, err := parse(fs, args); err != nil {
		return quiet(err)
	}
	if !*accessible && !isTerminal() {
		return errors.New("the wizard needs a terminal: use intergate-tunnel add, or --accessible to answer from a script")
	}
	p, err := c.paths()
	if err != nil {
		return err
	}
	if !p.User && os.Geteuid() != 0 && c.config == "" {
		fmt.Printf("This machine's tunnels (%s) need root.\n", p.Config)
		fmt.Println("Run it with sudo, or pass --user to set up tunnels and a service of your own.")
		return ErrQuiet
	}
	cfg, err := LoadConfig(p.Config)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	s := &setup{ctx: ctx, paths: p, cfg: cfg, accessible: *accessible}
	if *accessible {
		s.in = &lineReader{r: os.Stdin}
	}
	err = s.run()
	if errors.Is(err, huh.ErrUserAborted) || errors.Is(err, errInputEnded) {
		return nil
	}
	return err
}

// errInputEnded means a script's answers ran out.
var errInputEnded = errors.New("input ended")

// lineReader hands out one line per Read, so every accessible prompt gets
// its own answer, and remembers when input ends.
type lineReader struct {
	r     io.Reader
	ended bool
}

func (l *lineReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if _, err := l.r.Read(p[n : n+1]); err != nil {
			if n > 0 {
				return n, nil
			}
			l.ended = true
			return 0, err
		}
		n++
		if p[n-1] == '\n' {
			break
		}
	}
	return n, nil
}

func (s *setup) form(groups ...*huh.Group) error {
	f := huh.NewForm(groups...).WithAccessible(s.accessible)
	if !s.accessible {
		f = f.WithTheme(huh.ThemeCharm())
	}
	if s.in != nil {
		f = f.WithInput(s.in)
	}
	err := f.RunWithContext(s.ctx)
	if lr, ok := s.in.(*lineReader); ok && lr.ended {
		return errInputEnded
	}
	return err
}

func (s *setup) confirm(title string, def bool) (bool, error) {
	v := def
	err := s.form(huh.NewGroup(huh.NewConfirm().Title(title).Value(&v)))
	return v, err
}

func (s *setup) run() error {
	if len(s.cfg.Gates) == 0 {
		fmt.Println("Let's forward a first subdomain from this machine.")
		fmt.Println()
		if err := s.addTunnel(); err != nil {
			return err
		}
		return s.offerService()
	}
	for {
		fmt.Println()
		s.summary()
		const (
			actAdd, actChange, actRemove, actKey, actInstall, actUninstall, actQuit = "add", "change", "remove", "key", "install", "uninstall", "quit"
		)
		opts := []huh.Option[string]{
			huh.NewOption("Add a tunnel", actAdd),
			huh.NewOption("Change a tunnel: what it forwards, its ports", actChange),
			huh.NewOption("Stop forwarding a tunnel", actRemove),
			huh.NewOption("Show this machine's key", actKey),
		}
		if s.paths.Installed() {
			opts = append(opts, huh.NewOption("Remove the service", actUninstall))
		} else {
			opts = append(opts, huh.NewOption("Run as a service, started at boot", actInstall))
		}
		opts = append(opts, huh.NewOption("Quit", actQuit))
		act := actAdd
		if err := s.form(huh.NewGroup(huh.NewSelect[string]().Title("What now?").Options(opts...).Value(&act))); err != nil {
			return err
		}
		var err error
		switch act {
		case actAdd:
			err = s.addTunnel()
		case actChange:
			var host string
			if host, err = s.pickTunnel("Which tunnel?"); err == nil {
				err = s.editTunnel(host)
			}
		case actRemove:
			err = s.removeTunnel()
		case actKey:
			err = s.showKey()
		case actInstall:
			err = s.install()
		case actUninstall:
			err = s.paths.Uninstall(os.Stdout)
		case actQuit:
			return nil
		}
		if errors.Is(err, huh.ErrUserAborted) || errors.Is(err, errInputEnded) {
			return err
		}
		if err != nil {
			fmt.Println("✖", err)
		}
	}
}

// summary prints every tunnel and how it fares.
func (s *setup) summary() {
	byHost := map[string]TunnelStatus{}
	if st, err := ReadStatus(s.paths.Status); err == nil && processAlive(st.PID) {
		for _, t := range st.Tunnels {
			byHost[t.Host] = t
		}
	}
	s.cfg.Each(func(domain string, g *Gate, sub string, t *Tunnel) {
		host := Host(sub, domain)
		state := "not running"
		if ts, ok := byHost[host]; ok {
			state = describeState(ts)
		}
		fws, _ := t.Forwards()
		parts := make([]string, len(fws))
		for i, f := range fws {
			parts[i] = f.String()
		}
		fmt.Printf("  %s  %s\n    %s\n", host, state, strings.Join(parts, " · "))
	})
	fmt.Println()
}

func (s *setup) pickTunnel(title string) (string, error) {
	var opts []huh.Option[string]
	s.cfg.Each(func(domain string, _ *Gate, sub string, _ *Tunnel) {
		opts = append(opts, huh.NewOption(Host(sub, domain), Host(sub, domain)))
	})
	if len(opts) == 0 {
		return "", errors.New("there are no tunnels yet")
	}
	host := opts[0].Value
	err := s.form(huh.NewGroup(huh.NewSelect[string]().Title(title).Options(opts...).Value(&host)))
	return host, err
}

// addTunnel asks for a gate and a subdomain, then what to forward.
func (s *setup) addTunnel() error {
	var where string
	err := s.form(huh.NewGroup(huh.NewInput().
		Title("Which tunnel?").
		Description("Its full name, like web1.gate.example.com, or its gate's dashboard, like https://gate.example.com.").
		Value(&where).
		Validate(func(v string) error {
			if strings.TrimSpace(v) == "" {
				return errors.New("type a name or an address")
			}
			return nil
		})))
	if err != nil {
		return err
	}
	where = strings.TrimSpace(where)
	domain, sub, g, isNew, err := s.locate(where)
	if err != nil {
		return err
	}
	if isNew {
		fmt.Printf("\nGate %s: SSH %s\nHost key %s\n", domain, g.Server, g.HostKey)
		if !strings.HasPrefix(g.Dashboard, "https://") {
			ok, err := s.confirm("Its dashboard is not on HTTPS: is this the host key it shows?", false)
			if err != nil || !ok {
				return errors.Join(err, errors.New("check the host key on the dashboard, then try again"))
			}
		}
	}
	if sub == "" {
		if sub, err = s.askSubdomain(g); err != nil {
			return err
		}
	}
	if s.cfg.Gates[domain] == nil {
		s.cfg.Gates[domain] = g
	}
	if g.Tunnels[sub] == nil {
		g.Tunnels[sub] = &Tunnel{}
	}
	err = s.editTunnel(Host(sub, domain))
	if t := g.Tunnels[sub]; t != nil && t.Empty() {
		delete(g.Tunnels, sub)
		if len(g.Tunnels) == 0 && isNew {
			delete(s.cfg.Gates, domain)
		}
	}
	return err
}

// locate finds the gate of what was typed: a known tunnel, a dashboard, or
// a tunnel's full name. sub is empty for a dashboard.
func (s *setup) locate(where string) (domain, sub string, g *Gate, isNew bool, err error) {
	if d, sb, ok := s.cfg.Find(where); ok {
		return d, sb, s.cfg.Gates[d], false, nil
	}
	if strings.Contains(where, "://") || strings.Count(where, ".") == 1 {
		info, err := client.Discover(s.ctx, where, nil)
		if err != nil {
			return "", "", nil, false, err
		}
		if g, ok := s.cfg.Gates[info.Domain]; ok {
			return info.Domain, "", g, false, nil
		}
		u, _ := client.DashboardURL(where)
		g, err := newGate(info, info.HostKey, u.Scheme == "https")
		return info.Domain, "", g, true, err
	}
	// A dashboard named by its host alone, gate.example.com, is tried
	// first; else it is a tunnel's full name.
	if info, err := client.Discover(s.ctx, where, nil); err == nil && info.Domain == strings.ToLower(where) {
		if g, ok := s.cfg.Gates[info.Domain]; ok {
			return info.Domain, "", g, false, nil
		}
		g, err := newGate(info, info.HostKey, strings.HasPrefix(info.Dashboard, "https://"))
		return info.Domain, "", g, true, err
	}
	d, sb, g, isNew, err := gateFor(s.ctx, s.cfg, where, "", "")
	if errors.Is(err, errNotHTTPS) {
		// The wizard asks about the host key instead.
		return d, sb, g, isNew, nil
	}
	return d, sb, g, isNew, err
}

// askSubdomain offers the subdomains this machine's key opens on g, or
// asks for one.
func (s *setup) askSubdomain(g *Gate) (string, error) {
	var names []string
	if signer, _, err := s.cfg.LoadKey(true); err == nil {
		if check, err := client.HostKeyCheck(g.HostKey); err == nil {
			if conn, err := client.Dial(g.Server, "", sshAuth(signer), check); err == nil {
				if info, err := client.Info(conn, ""); err == nil {
					for _, sd := range info.Subdomains {
						names = append(names, sd.Name)
					}
				}
				conn.Close()
			}
		}
	}
	var sub string
	if len(names) > 0 {
		opts := make([]huh.Option[string], 0, len(names)+1)
		for _, n := range names {
			opts = append(opts, huh.NewOption(n, n))
		}
		opts = append(opts, huh.NewOption("Another one…", ""))
		sub = names[0]
		if err := s.form(huh.NewGroup(huh.NewSelect[string]().Title("Which subdomain?").Options(opts...).Value(&sub))); err != nil {
			return "", err
		}
		if sub != "" {
			return sub, nil
		}
	}
	err := s.form(huh.NewGroup(huh.NewInput().Title("Which subdomain?").Description("Its name in the dashboard, like web1.").
		Value(&sub).Validate(func(v string) error {
		if v = strings.TrimSpace(v); v == "" || strings.Contains(v, ".") {
			return errors.New("just the subdomain's name, like web1")
		}
		return nil
	})))
	return strings.ToLower(strings.TrimSpace(sub)), err
}

// editTunnel connects, shows the subdomain's ports on the gate to choose
// from, offers to add new ones, and saves.
func (s *setup) editTunnel(host string) error {
	domain, sub, _ := s.cfg.Find(host)
	g := s.cfg.Gates[domain]
	if domain == "" {
		// A new gate isn't in the configuration's index yet.
		for d, gg := range s.cfg.Gates {
			if name, ok := strings.CutSuffix(host, "."+d); ok {
				domain, sub, g = d, name, gg
			}
		}
	}
	old := g.Tunnels[sub]
	if old == nil {
		old = &Tunnel{}
	}
	fmt.Printf("\nConnecting to %s…\n", host)
	conn, err := connect(s.ctx, s.cfg, g, sub, true)
	if err != nil {
		return err
	}
	defer conn.Close()
	info, err := client.Info(conn, sub)
	if err != nil {
		return err
	}
	sd := info.Subdomains[0]

	// What to forward: the HTTP tunnel and the ports the gate has.
	const httpChoice = "\x00http"
	var opts []huh.Option[string]
	selected := []string{}
	opts = append(opts, huh.NewOption("HTTP — "+sd.URL, httpChoice))
	if old.HTTP != "" || old.Empty() {
		selected = append(selected, httpChoice)
	}
	for _, p := range sd.Ports {
		label := fmt.Sprintf("%s — %s, open to %s", p.Name, p.Address, describeAllow(p.Allow))
		opts = append(opts, huh.NewOption(label, p.Name))
		if _, ok := old.TCP[p.Name]; ok {
			selected = append(selected, p.Name)
		} else if _, ok := old.UDP[p.Name]; ok {
			selected = append(selected, p.Name)
		}
	}
	err = s.form(huh.NewGroup(huh.NewMultiSelect[string]().
		Title("What does " + host + " forward to this machine?").
		Description(fmt.Sprintf("Ports: %d of %d its owner may have, numbers from %s. You can add more next.", sd.Quota.Used, sd.Quota.Max, sd.Quota.Ranges)).
		Options(opts...).Value(&selected)))
	if err != nil {
		return err
	}

	t := &Tunnel{}
	var fields []huh.Field
	httpLocal := cmpOr(old.HTTP, "3000")
	if slices.Contains(selected, httpChoice) {
		fields = append(fields, huh.NewInput().Title("HTTP → local port").Description("Or HOST:PORT.").Value(&httpLocal).Validate(validLocal(client.HTTP)))
	}
	locals := map[string]*string{}
	for _, p := range sd.Ports {
		if !slices.Contains(selected, p.Name) {
			continue
		}
		v := cmpOr(old.TCP[p.Name], old.UDP[p.Name])
		if v == "" && p.LocalPort > 0 {
			v = strconv.Itoa(p.LocalPort)
		}
		locals[p.Name] = &v
		fields = append(fields, huh.NewInput().Title(fmt.Sprintf("%s (%s) → local port", p.Name, strings.ToUpper(p.Protocol))).Value(&v).Validate(validLocal(p.Protocol)))
	}
	if len(fields) > 0 {
		if err := s.form(huh.NewGroup(fields...)); err != nil {
			return err
		}
	}
	if slices.Contains(selected, httpChoice) {
		t.HTTP = strings.TrimSpace(httpLocal)
	}
	for _, p := range sd.Ports {
		if v, ok := locals[p.Name]; ok {
			if p.Protocol == client.UDP {
				t.UDP = setKey(t.UDP, p.Name, strings.TrimSpace(*v))
			} else {
				t.TCP = setKey(t.TCP, p.Name, strings.TrimSpace(*v))
			}
		}
	}

	// New ports, created on the gate.
	used := sd.Quota.Used
	for used < sd.Quota.Max {
		more, err := s.confirm(fmt.Sprintf("Add a new port to %s? (%d of %d)", sub, used, sd.Quota.Max), false)
		if err != nil {
			return err
		}
		if !more {
			break
		}
		p, local, err := s.newPort(conn, sub, sd)
		if err != nil {
			fmt.Println("✖", err)
			continue
		}
		used++
		fmt.Printf("✔ Created %s: %s, open to %s\n", p.Name, p.Address, describeAllow(p.Allow))
		if p.Protocol == client.UDP {
			t.UDP = setKey(t.UDP, p.Name, local)
		} else {
			t.TCP = setKey(t.TCP, p.Name, local)
		}
		sd.Ports = append(sd.Ports, *p)
	}

	g.Tunnels[sub] = t
	if t.Empty() {
		fmt.Println("Nothing to forward: nothing was saved for", host)
		if old.Empty() {
			return nil
		}
		delete(g.Tunnels, sub)
	}
	return save(s.paths, s.cfg)
}

// newPort asks for a port and creates it on the gate.
func (s *setup) newPort(conn client.Requester, sub string, sd wire.Subdomain) (*wire.Port, string, error) {
	var name, local, public, allow string
	proto := client.TCP
	allow = ""
	err := s.form(huh.NewGroup(
		huh.NewInput().Title("Name").Description("Like db or minecraft: it is <name>."+sub+" for clients.").Value(&name).Validate(func(v string) error {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" {
				return errors.New("give it a name")
			}
			if slices.ContainsFunc(sd.Ports, func(p wire.Port) bool { return p.Name == v }) {
				return fmt.Errorf("%s already has a port named %s", sub, v)
			}
			return nil
		}),
		huh.NewSelect[string]().Title("Protocol").Options(
			huh.NewOption("TCP: databases, SSH, most servers", client.TCP),
			huh.NewOption("UDP: games, DNS, WireGuard", client.UDP),
		).Value(&proto),
		huh.NewInput().Title("Local port").Description("Or HOST:PORT.").Value(&local).Validate(validLocal(client.TCP)),
		huh.NewInput().Title("Public port").Description("Empty for any free one of "+sd.Quota.Ranges+".").Value(&public).Validate(func(v string) error {
			if v = strings.TrimSpace(v); v == "" {
				return nil
			}
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
				return errors.New("a port number, or empty")
			}
			return nil
		}),
		huh.NewInput().Title("Who may connect?").Description("Addresses or ranges like 203.0.113.0/24, separated by spaces; any for anyone.").
			Value(&allow).Validate(func(v string) error {
			if strings.TrimSpace(v) == "" {
				return errors.New("say who may connect, or any")
			}
			return nil
		}),
	))
	if err != nil {
		return nil, "", err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(public))
	local = strings.TrimSpace(local)
	p, err := client.AddPort(conn, wire.PortAdd{
		PortRef:  wire.PortRef{Subdomain: sub, Name: strings.ToLower(strings.TrimSpace(name))},
		Protocol: proto, Allow: strings.Fields(strings.ReplaceAll(allow, ",", " ")), Port: n, LocalPort: localPort(local),
	})
	return p, local, err
}

func validLocal(kind string) func(string) error {
	return func(v string) error {
		v = strings.TrimSpace(v)
		if kind != client.HTTP {
			v = "x=" + v
		}
		_, err := client.ParseForward(kind, v)
		if err != nil {
			return errors.New("a port from 1 to 65535, or HOST:PORT")
		}
		return nil
	}
}

func (s *setup) removeTunnel() error {
	host, err := s.pickTunnel("Stop forwarding which tunnel?")
	if err != nil {
		return err
	}
	domain, sub, _ := s.cfg.Find(host)
	g := s.cfg.Gates[domain]
	t := g.Tunnels[sub]
	del := false
	if len(t.TCP)+len(t.UDP) > 0 {
		if del, err = s.confirm("Also delete its ports from the gate, freeing their numbers?", false); err != nil {
			return err
		}
	}
	if del {
		conn, err := connect(s.ctx, s.cfg, g, sub, false)
		if err != nil {
			return err
		}
		for _, m := range []map[string]string{t.TCP, t.UDP} {
			for name := range m {
				if err := client.DeletePort(conn, wire.PortRef{Subdomain: sub, Name: name}); err != nil {
					fmt.Println("✖", err)
				} else {
					fmt.Printf("Deleted %s.%s from the gate.\n", name, sub)
				}
			}
		}
		conn.Close()
	}
	delete(g.Tunnels, sub)
	if len(g.Tunnels) == 0 {
		delete(s.cfg.Gates, domain)
	}
	return save(s.paths, s.cfg)
}

func (s *setup) showKey() error {
	signer, _, err := s.cfg.LoadKey(true)
	if err != nil {
		return err
	}
	if err := s.paths.ShareWithService(s.cfg); err != nil {
		return err
	}
	fmt.Printf("\nThis machine signs in with:\n\n  %s\n\nAdd it to your account's SSH keys in a dashboard to pick it on each subdomain.\n", AuthorizedKey(signer))
	return nil
}

func (s *setup) offerService() error {
	if s.paths.Installed() || len(s.cfg.Gates) == 0 {
		return nil
	}
	if err := ServiceAvailable(); err != nil {
		fmt.Println("\nTo keep it running, start intergate-tunnel run from your service manager.")
		return nil
	}
	title := "Run it as a service, started at boot?"
	if s.paths.User {
		title = "Run it as your own service, started when you log in?"
	}
	ok, err := s.confirm(title, true)
	if err != nil || !ok {
		return err
	}
	return s.install()
}

func (s *setup) install() error {
	if err := s.paths.Install(s.cfg, os.Stdout); err != nil {
		return err
	}
	fmt.Println("\n✔ intergate-tunnel runs as a service: intergate-tunnel status shows how it fares.")
	return nil
}

func cmpOr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
