package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/client"
)

// Status is what the daemon writes for `intergate-tunnel status`.
type Status struct {
	PID     int            `json:"pid"`
	Started time.Time      `json:"started"`
	Updated time.Time      `json:"updated"`
	Tunnels []TunnelStatus `json:"tunnels"`
	// Error is why the configuration could not be (re)loaded.
	Error string `json:"error,omitempty"`
}

// Tunnel states.
const (
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateRetrying     = "retrying"
	StateUnauthorized = "unauthorized" // the key is not on the subdomain
	StateRefused      = "refused"      // every forward was refused
)

// TunnelStatus is how one subdomain fares.
type TunnelStatus struct {
	Host     string          `json:"host"`
	State    string          `json:"state"`
	Since    time.Time       `json:"since"`
	Error    string          `json:"error,omitempty"`
	Forwards []ForwardStatus `json:"forwards"`
	// Log is the last lines from the gate and the client.
	Log []string `json:"log"`
}

// ForwardStatus is how one forward fares.
type ForwardStatus struct {
	Kind  string `json:"kind"`
	Name  string `json:"name,omitempty"`
	Local string `json:"local"`
	// State is "forwarded", "refused" or "" while connecting.
	State string `json:"state,omitempty"`
	// Port is the public port a TCP or UDP forward got.
	Port   uint32 `json:"port,omitempty"`
	Reason string `json:"reason,omitempty"`
}

const maxLog = 12

// retryAfter is how long a tunnel the gate turned away waits to try again:
// someone may be adding its key or ports on the dashboard.
var retryAfter = 30 * time.Second

// Daemon keeps every tunnel of a configuration open.
type Daemon struct {
	ConfigPath string
	StatusPath string
	Log        *slog.Logger

	mu      sync.Mutex
	status  Status
	running map[string]*runner
	written chan struct{}
}

type runner struct {
	spec   spec
	cancel context.CancelFunc
	done   chan struct{}
	st     *TunnelStatus
}

// spec is what a runner was started with; a change restarts it.
type spec struct {
	Server, HostKey, Subdomain, Key string
	Forwards                        []client.Forward
}

// Run keeps the tunnels open until ctx is done, reloading the
// configuration on every value from reload.
func (d *Daemon) Run(ctx context.Context, reload <-chan struct{}) error {
	d.running = map[string]*runner{}
	d.status = Status{PID: os.Getpid(), Started: time.Now(), Tunnels: []TunnelStatus{}}
	d.written = make(chan struct{}, 1)
	go d.writer(ctx)
	d.reload(ctx)
	for {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			for _, r := range d.running {
				r.cancel()
			}
			list := d.running
			d.mu.Unlock()
			for _, r := range list {
				<-r.done
			}
			if d.StatusPath != "" {
				os.Remove(d.StatusPath)
			}
			return nil
		case <-reload:
			d.Log.Info("reloading", "config", d.ConfigPath)
			d.reload(ctx)
		}
	}
}

// reload starts, restarts and stops runners to match the configuration.
func (d *Daemon) reload(ctx context.Context) {
	want, err := d.specs()
	d.mu.Lock()
	if err != nil {
		// Keep what runs: a typo must not close every tunnel.
		d.status.Error = err.Error()
		d.Log.Error("load configuration", "err", err)
		d.changed()
		d.mu.Unlock()
		return
	}
	d.status.Error = ""
	var stopping []*runner
	for host, r := range d.running {
		if s, ok := want[host]; !ok || !reflect.DeepEqual(s, r.spec) {
			r.cancel()
			stopping = append(stopping, r)
			delete(d.running, host)
		}
	}
	d.mu.Unlock()
	// Runners update the status as they stop, under d.mu.
	for _, r := range stopping {
		<-r.done
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for host, s := range want {
		if _, ok := d.running[host]; !ok {
			d.start(ctx, host, s)
		}
	}
	d.status.Tunnels = d.status.Tunnels[:0]
	for _, host := range slices.Sorted(maps.Keys(d.running)) {
		d.status.Tunnels = append(d.status.Tunnels, *d.running[host].st)
	}
	d.changed()
}

func (d *Daemon) specs() (map[string]spec, error) {
	cfg, err := LoadConfig(d.ConfigPath)
	if err != nil {
		return nil, err
	}
	out := map[string]spec{}
	var ferr error
	cfg.Each(func(domain string, g *Gate, sub string, t *Tunnel) {
		if t.Empty() {
			return
		}
		fw, err := t.Forwards()
		if err != nil && ferr == nil {
			ferr = err
		}
		out[Host(sub, domain)] = spec{Server: g.Server, HostKey: g.HostKey, Subdomain: sub, Key: cfg.KeyPath(), Forwards: fw}
	})
	return out, ferr
}

// start runs a tunnel; d.mu is held.
func (d *Daemon) start(parent context.Context, host string, s spec) {
	ctx, cancel := context.WithCancel(parent)
	r := &runner{spec: s, cancel: cancel, done: make(chan struct{}), st: &TunnelStatus{Host: host, State: StateConnecting, Since: time.Now(), Log: []string{}}}
	for _, f := range s.Forwards {
		r.st.Forwards = append(r.st.Forwards, ForwardStatus{Kind: f.Kind, Name: f.Name, Local: f.Local})
	}
	d.running[host] = r
	go func() {
		defer close(r.done)
		d.supervise(ctx, r)
	}()
}

// supervise runs one tunnel until ctx is done, trying again after the
// gate turns it away.
func (d *Daemon) supervise(ctx context.Context, r *runner) {
	log := d.Log.With("tunnel", r.st.Host)
	out := &lineWriter{line: func(line string) { d.logLine(r, line) }}
	for ctx.Err() == nil {
		err := d.runOnce(ctx, r, out)
		if ctx.Err() != nil {
			return
		}
		state, msg := StateRetrying, ""
		if err != nil {
			msg = err.Error()
		}
		switch {
		case errors.Is(err, client.ErrRejected):
			state = StateRefused
		case err != nil && (strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "not registered")):
			state, msg = StateUnauthorized, "the gate doesn't know this machine's key: add it to the subdomain (intergate-tunnel key)"
		}
		log.Warn("tunnel stopped", "state", state, "err", err)
		d.update(r, func(st *TunnelStatus) { st.State, st.Error, st.Since = state, msg, time.Now() })
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryAfter):
		}
	}
}

func (d *Daemon) runOnce(ctx context.Context, r *runner, out *lineWriter) error {
	key, err := os.ReadFile(r.spec.Key)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("%s: %w", r.spec.Key, err)
	}
	check, err := client.HostKeyCheck(r.spec.HostKey)
	if err != nil {
		return err
	}
	return client.Run(ctx, client.Options{
		Server: r.spec.Server, Subdomain: r.spec.Subdomain, Forwards: r.spec.Forwards,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKey: check, Out: out,
		OnEvent: func(e client.Event) { d.event(r, e) },
	})
}

func (d *Daemon) event(r *runner, e client.Event) {
	d.update(r, func(st *TunnelStatus) {
		set := func(f client.Forward, fn func(*ForwardStatus)) {
			for i := range st.Forwards {
				if st.Forwards[i].Kind == f.Kind && st.Forwards[i].Name == f.Name {
					fn(&st.Forwards[i])
				}
			}
		}
		switch e.Kind {
		case client.Connecting:
			if st.State != StateConnected {
				st.State = StateConnecting
			}
		case client.Connected:
			st.State, st.Error, st.Since = StateConnected, "", time.Now()
			for i := range st.Forwards {
				st.Forwards[i].State, st.Forwards[i].Reason = "", ""
			}
		case client.Forwarded:
			set(e.Forward, func(f *ForwardStatus) { f.State, f.Port, f.Reason = "forwarded", e.Port, "" })
		case client.Refused:
			set(e.Forward, func(f *ForwardStatus) { f.State = "refused" })
		case client.Retrying:
			st.State, st.Since = StateRetrying, time.Now()
			if e.Err != nil {
				st.Error = e.Err.Error()
			}
		}
	})
}

// logLine keeps a line of the gate's console, and the reason a forward
// was refused: "✖ cannot forward db.web1:0: ...".
func (d *Daemon) logLine(r *runner, line string) {
	d.update(r, func(st *TunnelStatus) {
		st.Log = append(st.Log, time.Now().Format("15:04:05")+"  "+line)
		if len(st.Log) > maxLog {
			st.Log = st.Log[len(st.Log)-maxLog:]
		}
		rest, ok := strings.CutPrefix(line, "✖ cannot forward ")
		if !ok {
			return
		}
		for i := range st.Forwards {
			f := &st.Forwards[i]
			bind := r.spec.Subdomain
			if f.Kind != client.HTTP {
				bind = f.Name + "." + r.spec.Subdomain
			}
			if strings.HasPrefix(rest, bind+":") {
				if _, reason, ok := strings.Cut(rest, ": "); ok {
					f.Reason = reason
				}
			}
		}
	})
}

func (d *Daemon) update(r *runner, fn func(*TunnelStatus)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fn(r.st)
	for i := range d.status.Tunnels {
		if d.status.Tunnels[i].Host == r.st.Host {
			d.status.Tunnels[i] = *r.st
		}
	}
	d.changed()
}

// changed asks the writer to write the status; d.mu is held.
func (d *Daemon) changed() {
	select {
	case d.written <- struct{}{}:
	default:
	}
}

// writer writes the status file at most a few times a second.
func (d *Daemon) writer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.written:
		}
		if d.StatusPath != "" {
			d.mu.Lock()
			d.status.Updated = time.Now()
			b, _ := json.MarshalIndent(d.status, "", "  ")
			d.mu.Unlock()
			if err := writeFile(d.StatusPath, b, 0o644); err != nil {
				d.Log.Warn("write status", "err", err)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ReadStatus reads the daemon's status file.
func ReadStatus(path string) (*Status, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Status
	return &s, json.Unmarshal(b, &s)
}

// lineWriter calls line for each line written to it.
type lineWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	line func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf.Next(i+1)), "\r\n")
		if line != "" {
			w.line(line)
		}
	}
	return len(p), nil
}
