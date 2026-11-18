package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/agent"
	"github.com/jgermade/intergate/internal/client"
	"github.com/jgermade/intergate/internal/store"
)

// intergate-tunnel's daemon keeps what tunnels.yaml says open, creates the
// ports it lacks through Apply, and follows changes on reload.
func TestAgentDaemon(t *testing.T) {
	first := freeRange(t, 4)
	h := newHarness(t, fmt.Sprintf("tcp:\n  ports: %d-%d\n  listen_host: 127.0.0.1", first, first+3))
	ctx := context.Background()
	u, err := h.store.EnsureUser(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	d, err := h.store.CreateSubdomain(ctx, u.ID, "app", store.AccessPublic)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfg, err := agent.LoadConfig(filepath.Join(dir, "tunnels.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	signer, _, err := cfg.LoadKey(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AddKey(ctx, d.ID, "machine", signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	hostKey := ssh.FingerprintSHA256(h.srv.HostKey())
	g := &agent.Gate{Server: h.sshAddr, HostKey: hostKey, Tunnels: map[string]*agent.Tunnel{}}
	check, _ := client.HostKeyCheck(hostKey)
	conn, err := client.Dial(h.sshAddr, "app", []ssh.AuthMethod{ssh.PublicKeys(signer)}, check)
	if err != nil {
		t.Fatal(err)
	}
	echo := tcpEcho(t)
	_, echoPort, _ := net.SplitHostPort(echo)
	if _, _, err := agent.Apply(conn, g, "app", agent.Request{Ports: []agent.PortRequest{{Kind: "tcp", Name: "db", Local: echoPort}}}); err == nil {
		t.Error("Apply created a port without an allow list")
	}
	tn, made, err := agent.Apply(conn, g, "app", agent.Request{
		HTTP: backend(t).Listener.Addr().String(), Allow: []string{"127.0.0.1"},
		Ports: []agent.PortRequest{{Kind: "tcp", Name: "db", Local: echo}},
	})
	conn.Close()
	if err != nil || len(made) != 1 {
		t.Fatal(made, err)
	}
	g.Tunnels["app"] = tn
	cfg.Gates[domain] = g
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	status := filepath.Join(dir, "status.json")
	dmn := &agent.Daemon{ConfigPath: cfg.Path(), StatusPath: status, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	runCtx, cancel := context.WithCancel(ctx)
	reload := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- dmn.Run(runCtx, reload) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	forwarded := func(name string) (uint32, bool) {
		st, err := agent.ReadStatus(status)
		if err != nil || len(st.Tunnels) != 1 || st.Tunnels[0].State != agent.StateConnected {
			return 0, false
		}
		for _, f := range st.Tunnels[0].Forwards {
			if f.Name == name && f.State == "forwarded" {
				return f.Port, true
			}
		}
		return 0, false
	}
	waitFor(t, func() bool { _, ok := forwarded("db"); return ok })
	port, _ := forwarded("db")
	if port != uint32(first) {
		t.Errorf("db's public port = %d", port)
	}
	if got := ask(t, fmt.Sprintf("127.0.0.1:%d", port), "ping"); got != "ping" {
		t.Errorf("TCP through the daemon: %q", got)
	}

	// A port the gate doesn't have shows why it was refused; the rest
	// keeps working after the reload.
	tn.TCP["nope"] = "1"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	reload <- struct{}{}
	waitFor(t, func() bool {
		st, err := agent.ReadStatus(status)
		if err != nil || len(st.Tunnels) != 1 {
			return false
		}
		for _, f := range st.Tunnels[0].Forwards {
			if f.Name == "nope" && f.State == "refused" && f.Reason != "" {
				return true
			}
		}
		return false
	})
	waitFor(t, func() bool { _, ok := forwarded("db"); return ok })
	if got := ask(t, fmt.Sprintf("127.0.0.1:%d", port), "pong"); got != "pong" {
		t.Errorf("TCP after the reload: %q", got)
	}
}

func ask(t *testing.T, addr, msg string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, msg)
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err.Error()
	}
	return string(buf)
}
