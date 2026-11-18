package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/client"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/wire"
)

// The intergate client sees and changes a subdomain's ports with the key
// it signs in with, within its owner's limits, and forwards what it made.
func TestClientManagesPorts(t *testing.T) {
	first := freeRange(t, 4)
	h := newHarness(t, fmt.Sprintf("tcp:\n  ports: %d-%d\n  listen_host: 127.0.0.1\n  max_ports: 2", first, first+3))
	_, _, key := h.setup("alice@example.com", "app", store.AccessPublic)
	// Another subdomain, another owner: alice's key can't touch it.
	h.setup("bob@example.com", "other", store.AccessPublic)

	auth := []ssh.AuthMethod{ssh.PublicKeys(key)}
	c, err := client.Dial(h.sshAddr, "", auth, ssh.InsecureIgnoreHostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	info, err := client.Info(c, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Subdomains) != 1 || info.Subdomains[0].Name != "app" || info.Subdomains[0].Quota.Max != 2 || len(info.Subdomains[0].Ports) != 0 {
		t.Fatalf("info = %+v", info)
	}
	if _, err := client.Info(c, "other"); err == nil {
		t.Error("info about another's subdomain")
	}

	add := func(in wire.PortAdd) (*wire.Port, error) {
		in.Subdomain = "app"
		return client.AddPort(c, in)
	}
	if _, err := add(wire.PortAdd{PortRef: wire.PortRef{Name: "db"}, LocalPort: 5432}); err == nil || !strings.Contains(err.Error(), "who may connect") {
		t.Errorf("a port without an allow list: %v", err)
	}
	db, err := add(wire.PortAdd{PortRef: wire.PortRef{Name: "db"}, Protocol: "tcp", LocalPort: 5432, Allow: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if db.Port != first || db.CreatedBy != "key test key" || len(db.Allow) != 1 {
		t.Errorf("db = %+v", db)
	}
	mc, err := add(wire.PortAdd{PortRef: wire.PortRef{Name: "mc"}, Protocol: "udp", LocalPort: 19132, Allow: []string{wire.Anyone}, Port: first + 3})
	if err != nil {
		t.Fatal(err)
	}
	if mc.Port != first+3 || len(mc.Allow) != 0 {
		t.Errorf("mc = %+v", mc)
	}
	if _, err := add(wire.PortAdd{PortRef: wire.PortRef{Name: "ssh"}, LocalPort: 22, Allow: []string{wire.Anyone}}); err == nil || !strings.Contains(err.Error(), "2 of the 2") {
		t.Errorf("over the quota: %v", err)
	}
	if _, err := client.AddPort(c, wire.PortAdd{PortRef: wire.PortRef{Subdomain: "other", Name: "x"}, LocalPort: 1, Allow: []string{wire.Anyone}}); err == nil {
		t.Error("a port on another's subdomain")
	}

	// Who may connect changes, and so does the live forward.
	if p, err := client.UpdatePort(c, wire.PortUpdate{PortRef: wire.PortRef{Subdomain: "app", Name: "db"}, Allow: []string{"192.0.2.0/24"}}); err != nil || p.Allow[0] != "192.0.2.0/24" {
		t.Errorf("update: %+v %v", p, err)
	}
	if _, err := client.UpdatePort(c, wire.PortUpdate{PortRef: wire.PortRef{Subdomain: "app", Name: "db"}, Allow: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}

	// What the client made, it forwards.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx, client.Options{
			Server: h.sshAddr, Subdomain: "app",
			Forwards: []client.Forward{{Kind: client.TCP, Name: "db", Local: tcpEcho(t)}},
			Auth:     auth, HostKey: ssh.InsecureIgnoreHostKey(), Out: io.Discard,
		})
	}()
	waitFor(t, func() bool { return h.srv.Ports().Get(db.Port) != nil })
	tc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", db.Port))
	if err != nil {
		t.Fatal(err)
	}
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(tc, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "ping" {
		t.Errorf("TCP: %q %v", buf, err)
	}
	tc.Close()

	// Deleting it closes the forward and frees its number and quota.
	if err := client.DeletePort(c, wire.PortRef{Subdomain: "app", Name: "db"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return h.srv.Ports().Get(db.Port) == nil })
	info, _ = client.Info(c, "app")
	if len(info.Subdomains[0].Ports) != 1 || info.Subdomains[0].Quota.Used != 1 {
		t.Errorf("after delete: %+v", info.Subdomains[0])
	}
	if err := client.DeletePort(c, wire.PortRef{Subdomain: "app", Name: "db"}); err == nil {
		t.Error("deleted a port twice")
	}
	cancel()
	<-done
}
