package manage

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/names"
	"github.com/jgermade/intergate/internal/ports"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/tunnel"
)

func newService(t *testing.T, yaml string) (*Service, *store.Store) {
	t.Helper()
	cfg, err := config.Parse([]byte("public_url: https://gate.test\n" + yaml))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, st, tunnel.NewRegistry(), ports.NewRegistry("127.0.0.1"), names.NewChecker(nil), log), st
}

func intp(n int) *int { return &n }

func TestUserLimits(t *testing.T) {
	ctx := context.Background()
	s, st := newService(t, "limits: {subdomains_per_user: 2}\ntcp: {ports: 30000-30299, max_ports: 3}\n")
	ana, err := s.CreateUser(ctx, "ana@example.com", "test")
	if err != nil {
		t.Fatal(err)
	}

	l := s.Limits(ana)
	if l.Subdomains != 2 || l.Ports != 3 || len(l.Ranges) != 1 || l.Ranges[0] != (config.PortRange{First: 30000, Last: 30299}) || l.CustomPorts {
		t.Fatalf("default limits = %+v", l)
	}

	for _, bad := range []LimitsInput{
		{Ports: intp(-1)},
		{Ranges: "30100-30109,29000-29010"}, // outside tcp.ports
		{Ranges: "30100-"},
	} {
		if err := s.SetUserLimits(ctx, ana.ID, bad, "test"); err == nil {
			t.Errorf("SetUserLimits(%+v) accepted", bad)
		}
	}
	if err := s.SetUserLimits(ctx, ana.ID, LimitsInput{Subdomains: intp(1), Ports: intp(2), Ranges: "30100-30100, 30200-30299"}, "test"); err != nil {
		t.Fatal(err)
	}
	ana, _ = st.UserByID(ctx, ana.ID)
	l = s.Limits(ana)
	if l.Subdomains != 1 || l.Ports != 2 || config.FormatPortRanges(l.Ranges) != "30100,30200-30299" || !l.CustomRanges {
		t.Fatalf("limits = %+v", l)
	}

	d, _, err := s.CreateSubdomain(ctx, ana, "web1", store.AccessPublic, "", false, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateSubdomain(ctx, ana, "web2", store.AccessPublic, "", false, "test"); err == nil || !strings.Contains(err.Error(), "at most 1") {
		t.Errorf("second subdomain: %v", err)
	}

	port := func(name string, number int) (*store.Port, error) {
		return s.CreatePort(ctx, d, PortInput{Name: name, LocalPort: 5432, Port: number}, "test")
	}
	// Numbers come from her ranges, in order.
	p1, err := port("db", 0)
	if err != nil || p1.Port != 30100 {
		t.Fatalf("first port = %v, %v", p1, err)
	}
	if _, err := port("mc", 30050); err == nil || !strings.Contains(err.Error(), "not one") {
		t.Errorf("a number outside her ranges: %v", err)
	}
	if _, err := port("mc", 30100); err == nil || !strings.Contains(err.Error(), "taken") {
		t.Errorf("a number in use: %v", err)
	}
	p2, err := port("mc", 30250)
	if err != nil || p2.Port != 30250 {
		t.Fatalf("asked number = %v, %v", p2, err)
	}
	if _, err := port("ssh", 0); err == nil || !strings.Contains(err.Error(), "2 of the 2") {
		t.Errorf("over the quota: %v", err)
	}

	// Lowering the quota keeps what she has.
	if err := s.SetUserLimits(ctx, ana.ID, LimitsInput{Ports: intp(1)}, "test"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.Ports(ctx, d); len(list) != 2 {
		t.Errorf("ports after lowering the quota: %d", len(list))
	}
	// Back to the configuration's.
	if err := s.SetUserLimits(ctx, ana.ID, LimitsInput{}, "test"); err != nil {
		t.Fatal(err)
	}
	ana, _ = st.UserByID(ctx, ana.ID)
	if l := s.Limits(ana); l.CustomSubdomains || l.CustomPorts || l.CustomRanges || l.Ports != 3 {
		t.Errorf("reset limits = %+v", l)
	}
}

func TestRangesFullAndShrunk(t *testing.T) {
	ctx := context.Background()
	s, st := newService(t, "tcp: {ports: 30000-30009, max_ports: 5}\n")
	bob, _ := s.CreateUser(ctx, "bob@example.com", "test")
	if err := s.SetUserLimits(ctx, bob.ID, LimitsInput{Ranges: "30008-30009"}, "test"); err != nil {
		t.Fatal(err)
	}
	bob, _ = st.UserByID(ctx, bob.ID)
	d, _, err := s.CreateSubdomain(ctx, bob, "bob", store.AccessPublic, "", false, "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if _, err := s.CreatePort(ctx, d, PortInput{Name: name, LocalPort: 1}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreatePort(ctx, d, PortInput{Name: "c", LocalPort: 1}, "test"); err == nil || !strings.Contains(err.Error(), "30008-30009") {
		t.Errorf("full ranges: %v", err)
	}

	// A range partly outside a narrower tcp.ports counts only inside it.
	s2, st2 := newService(t, "tcp: {ports: 30000-30005, max_ports: 5}\n")
	u, _ := s2.CreateUser(ctx, "u@example.com", "test")
	st2.SetUserLimits(ctx, u.ID, store.UserLimits{PortRanges: "30004-30009"})
	u, _ = st2.UserByID(ctx, u.ID)
	if got := config.FormatPortRanges(s2.Limits(u).Ranges); got != "30004-30005" {
		t.Errorf("clipped ranges = %q", got)
	}
}
