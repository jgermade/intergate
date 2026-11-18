package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

// On macOS the service is a launchd job: a LaunchDaemon of the machine,
// run as root (macOS has no simple way to make a service user), or the
// user's LaunchAgent.

const launchdLabel = "io.github.jgermade.intergate-tunnel"

func launchdSystemPaths() Paths {
	return Paths{
		Config: "/etc/intergate-tunnel/tunnels.yaml",
		Status: "/var/run/intergate-tunnel/status.json",
		Unit:   "/Library/LaunchDaemons/" + launchdLabel + ".plist",
	}
}

func launchdUserUnit() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist"), nil
}

// launchdDomain is the launchctl domain p's job lives in.
func (p Paths) launchdDomain() string {
	if p.User {
		return "gui/" + strconv.Itoa(os.Getuid())
	}
	return "system"
}

func (p Paths) launchdTarget() string { return p.launchdDomain() + "/" + launchdLabel }

func (p Paths) launchdLog() string {
	if p.User {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Logs", "intergate-tunnel.log")
	}
	return "/var/log/intergate-tunnel.log"
}

var plistTemplate = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Binary}}</string>
		<string>run</string>
		<string>--config</string>
		<string>{{.Config}}</string>
		<string>--status</string>
		<string>{{.Status}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>{{.Log}}</string>
	<key>StandardErrorPath</key>
	<string>{{.Log}}</string>
</dict>
</plist>
`))

func (p Paths) plist(binary string) (string, error) {
	var b strings.Builder
	// Paths go in XML: escape them.
	esc := func(s string) string {
		var x strings.Builder
		_ = xmlEscape(&x, s)
		return x.String()
	}
	err := plistTemplate.Execute(&b, map[string]string{
		"Label": launchdLabel, "Binary": esc(binary), "Config": esc(p.Config), "Status": esc(p.Status), "Log": esc(p.launchdLog()),
	})
	return b.String(), err
}

func xmlEscape(w io.Writer, s string) error {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	_, err := io.WriteString(w, r.Replace(s))
	return err
}

func launchctl(args ...string) func() error { return command("launchctl", args...) }

func (p Paths) launchdActive() bool {
	out, err := exec.Command("launchctl", "print", p.launchdTarget()).Output()
	return err == nil && strings.Contains(string(out), "state = running")
}

func (p Paths) launchdReload() error {
	if err := launchctl("kill", "HUP", p.launchdTarget())(); err != nil {
		return fmt.Errorf("reload the service: %w", err)
	}
	return nil
}

func (p Paths) launchdInstall(cfg *Config, out io.Writer) error {
	if !p.User && os.Geteuid() != 0 {
		return errors.New("the machine's service needs root: run it with sudo, or pass --user for your own")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	binary := exe
	if !p.User {
		binary = binaryPath
		if exe != binaryPath {
			if err := run(out, "copy "+exe+" to "+binaryPath, func() error { return copyBinary(exe, binaryPath) }); err != nil {
				return err
			}
		}
	}
	plist, err := p.plist(binary)
	if err != nil {
		return err
	}
	if err := run(out, "write "+p.Unit, func() error { return writeFile(p.Unit, []byte(plist), 0o644) }); err != nil {
		return err
	}
	// A job loaded before keeps its old definition until booted out.
	_ = launchctl("bootout", p.launchdTarget())()
	if err := run(out, "load "+launchdLabel, launchctl("bootstrap", p.launchdDomain(), p.Unit)); err != nil {
		return err
	}
	return run(out, "start "+launchdLabel, launchctl("kickstart", "-k", p.launchdTarget()))
}

func (p Paths) launchdUninstall(out io.Writer) error {
	if !p.User && os.Geteuid() != 0 {
		return errors.New("removing the machine's service needs root: run it with sudo")
	}
	if err := run(out, "stop "+launchdLabel, func() error {
		if err := launchctl("bootout", p.launchdTarget())(); err != nil && p.launchdActive() {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return run(out, "remove "+p.Unit, func() error { return os.Remove(p.Unit) })
}
