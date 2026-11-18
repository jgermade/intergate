package e2e

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeRelease writes a release directory whose intergate and
// intergate-tunnel only print their arguments, and returns it.
func fakeRelease(t *testing.T, corrupt bool) string {
	t.Helper()
	dir := t.TempDir()
	target := runtime.GOOS + "-" + runtime.GOARCH
	var sums []byte
	for name, says := range map[string]string{"intergate": "client", "intergate-tunnel": "tunnel"} {
		bin := filepath.Join(dir, name+"-"+target)
		os.MkdirAll(bin, 0o755)
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho \""+says+" $*\"\n"), 0o755)
		asset := name + "-" + target + ".tar.gz"
		if out, err := exec.Command("tar", "-czf", filepath.Join(dir, asset), "-C", dir, name+"-"+target).CombinedOutput(); err != nil {
			t.Fatalf("tar: %v %s", err, out)
		}
		os.RemoveAll(bin)
		data, _ := os.ReadFile(filepath.Join(dir, asset))
		sum := sha256.Sum256(data)
		if corrupt {
			sum[0]++
		}
		sums = fmt.Appendf(sums, "%x  %s\n", sum, asset)
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums, 0o644)
	return dir
}

func TestTunnelScript(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is needed")
	}
	h := newHarness(t)
	resp, script := get(t, h.browser(false), "http://"+domain+"/tunnel.sh")
	fp := ssh.FingerprintSHA256(h.srv.HostKey())
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(script, "#!/bin/sh") ||
		!strings.Contains(script, "HOST_KEY='"+fp+"'") || !strings.Contains(script, "SERVER='"+domain+":2222'") ||
		!strings.Contains(script, "VERSION=''") {
		t.Fatalf("tunnel.sh: %d\n%s", resp.StatusCode, script)
	}
	resp, ps := get(t, h.browser(false), "http://"+domain+"/tunnel.ps1")
	if resp.StatusCode != http.StatusOK || !strings.Contains(ps, "$HostKey = '"+fp+"'") || !strings.Contains(ps, "$Server = '"+domain+":2222'") ||
		!strings.Contains(ps, "irm http://"+domain+"/tunnel.ps1") || !strings.Contains(ps, "intergate-$target.zip") {
		t.Errorf("tunnel.ps1: %d\n%s", resp.StatusCode, ps)
	}

	path := filepath.Join(t.TempDir(), "tunnel.sh")
	os.WriteFile(path, []byte(script), 0o644)

	run := func(release, home string, args ...string) (string, error) {
		cmd := exec.Command("sh", append([]string{path}, args...)...)
		tmp := t.TempDir()
		cmd.Env = append(os.Environ(), "INTERGATE_DOWNLOAD_URL=file://"+release, "HOME="+home, "TMPDIR="+tmp,
			"XDG_CACHE_HOME=", "INTERGATE_VERSION=1.2.3")
		out, err := cmd.CombinedOutput()
		if left, _ := os.ReadDir(tmp); len(left) != 0 {
			t.Errorf("left %d files in TMPDIR", len(left))
		}
		return string(out), err
	}
	good, home := fakeRelease(t, false), t.TempDir()
	want := fmt.Sprintf("client tunnel --server %s:2222 --host-key %s myapp --udp mc=19132", domain, fp)
	if out, err := run(good, home, "myapp", "--udp", "mc=19132"); err != nil || strings.TrimSpace(out) != want {
		t.Errorf("run: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".cache")); err == nil {
		t.Error("cached without --cache")
	}
	// --cache keeps it, and the next run needs no download.
	if out, err := run(good, home, "--cache", "myapp", "--http", "3000"); err != nil || !strings.HasPrefix(out, "client tunnel") {
		t.Errorf("run --cache: %v\n%s", err, out)
	}
	if out, err := run(t.TempDir(), home, "--cache", "myapp", "--http", "3000"); err != nil || !strings.HasPrefix(out, "client tunnel") {
		t.Errorf("run from the cache: %v\n%s", err, out)
	}
	if out, err := run(fakeRelease(t, true), t.TempDir(), "myapp", "--http", "3000"); err == nil || !strings.Contains(out, "does not match its checksum") {
		t.Errorf("corrupt download: %v\n%s", err, out)
	}

	// --install puts intergate-tunnel in place and has it add the subdomain
	// and install its service; with --user, all of it is the user's.
	home = t.TempDir()
	out, err := run(good, home, "myapp", "--http", "3000", "--install", "--user")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	wantAdd := fmt.Sprintf("tunnel add myapp --dashboard http://%s/ --host-key %s --http 3000 --user", domain, fp)
	if err != nil || len(lines) != 3 || !strings.Contains(lines[0], home+"/.local/bin/intergate-tunnel") ||
		lines[1] != wantAdd || lines[2] != "tunnel install --user" {
		t.Errorf("--install --user: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "bin", "intergate-tunnel")); err != nil {
		t.Errorf("intergate-tunnel not installed: %v", err)
	}
}
