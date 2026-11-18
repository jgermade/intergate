package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnels.yaml")
	cfg, err := LoadConfig(path)
	if err != nil || len(cfg.Gates) != 0 {
		t.Fatalf("missing file: %v %v", cfg, err)
	}
	cfg.Gates["gate.example1.com"] = &Gate{Server: "gate.example1.com:2222", HostKey: "SHA256:a", Tunnels: map[string]*Tunnel{
		"web1": {HTTP: "8080", TCP: map[string]string{"db": "5432"}, UDP: map[string]string{"mc": "192.168.1.5:19132"}},
	}}
	cfg.Gates["gate.example2.com"] = &Gate{Server: "gate.example2.com:22", HostKey: "SHA256:b", Tunnels: map[string]*Tunnel{
		"web2": {HTTP: "8090"},
	}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v", fi.Mode())
	}
	back, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	back.Each(func(domain string, g *Gate, sub string, tn *Tunnel) { hosts = append(hosts, Host(sub, domain)) })
	if strings.Join(hosts, " ") != "web1.gate.example1.com web2.gate.example2.com" {
		t.Errorf("hosts = %v", hosts)
	}
	fw, err := back.Gates["gate.example1.com"].Tunnels["web1"].Forwards()
	if err != nil || len(fw) != 3 || fw[0].Local != "localhost:8080" || fw[1].Name != "db" || fw[2].Local != "192.168.1.5:19132" {
		t.Errorf("forwards = %+v %v", fw, err)
	}
	if d, s, ok := back.Find("WEB1.gate.example1.com."); !ok || d != "gate.example1.com" || s != "web1" {
		t.Errorf("Find = %q %q %v", d, s, ok)
	}
	if _, _, ok := back.Find("a.b.gate.example1.com"); ok {
		t.Error("Find took a name two levels down")
	}
	if back.KeyPath() != filepath.Join(filepath.Dir(path), "key") {
		t.Errorf("key path = %s", back.KeyPath())
	}

	os.WriteFile(path, []byte("gates:\n  g.test:\n    tunnels:\n      x: {tcp: {db: notaport}}\n"), 0o600)
	if _, err := LoadConfig(path); err == nil {
		t.Error("a bad local port was accepted")
	}
}

func TestKey(t *testing.T) {
	cfg := &Config{path: filepath.Join(t.TempDir(), "tunnels.yaml")}
	if _, _, err := cfg.LoadKey(false); err == nil {
		t.Fatal("a missing key without create")
	}
	s1, created, err := cfg.LoadKey(true)
	if err != nil || !created {
		t.Fatal(created, err)
	}
	s2, created, err := cfg.LoadKey(true)
	if err != nil || created || string(s1.PublicKey().Marshal()) != string(s2.PublicKey().Marshal()) {
		t.Fatal("the key changed", created, err)
	}
	if fi, _ := os.Stat(cfg.KeyPath()); fi.Mode().Perm() != 0o640 {
		t.Errorf("key mode = %v", fi.Mode())
	}
	if !strings.HasPrefix(AuthorizedKey(s1), "ssh-ed25519 ") {
		t.Errorf("authorized key = %q", AuthorizedKey(s1))
	}
}

func TestPortFlag(t *testing.T) {
	for in, want := range map[string]portFlag{
		"db=5432":              {"db", "5432", 0},
		"MC=19132@30100":       {"mc", "19132", 30100},
		"web=10.0.0.2:80@3001": {"web", "10.0.0.2:80", 3001},
	} {
		got, err := parsePortFlag("tcp", in)
		if err != nil || got != want {
			t.Errorf("%q = %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"db", "db=x", "db=5432@", "db=5432@99999"} {
		if _, err := parsePortFlag("tcp", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUnit(t *testing.T) {
	sys, err := SystemPaths().unit("/usr/local/bin/intergate-tunnel")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=intergate-tunnel", "ExecStart=/usr/local/bin/intergate-tunnel run --config /etc/intergate-tunnel/tunnels.yaml --status /run/intergate-tunnel/status.json", "ExecReload=/bin/kill -HUP $MAINPID", "ProtectSystem=strict", "WantedBy=multi-user.target"} {
		if !strings.Contains(sys, want) {
			t.Errorf("system unit lacks %q:\n%s", want, sys)
		}
	}
	up := Paths{User: true, Config: "/home/a/.config/intergate-tunnel/tunnels.yaml"}
	usr, _ := up.unit("/home/a/bin/intergate-tunnel")
	if strings.Contains(usr, "User=") || !strings.Contains(usr, "--status %t/intergate-tunnel/status.json") || !strings.Contains(usr, "WantedBy=default.target") {
		t.Errorf("user unit:\n%s", usr)
	}
}
