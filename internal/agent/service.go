package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
)

const (
	serviceName = "intergate-tunnel"
	// ServiceUser runs the system service.
	ServiceUser = "intergate-tunnel"
	binaryPath  = "/usr/local/bin/intergate-tunnel"
)

// Paths are where a configuration, its daemon's status and its service
// live: the system's, or the user's.
type Paths struct {
	// User is set for the user's own service (systemctl --user).
	User   bool
	Config string
	Status string
	Unit   string
}

// SystemPaths are the machine's: /etc/intergate-tunnel, run as its own user
// (as root on macOS).
func SystemPaths() Paths {
	if runtime.GOOS == "darwin" {
		return launchdSystemPaths()
	}
	return Paths{
		Config: "/etc/intergate-tunnel/tunnels.yaml",
		Status: "/run/intergate-tunnel/status.json",
		Unit:   "/etc/systemd/system/intergate-tunnel.service",
	}
}

// UserPaths are the user's: ~/.config/intergate-tunnel.
func UserPaths() (Paths, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return Paths{}, err
	}
	run := os.Getenv("XDG_RUNTIME_DIR")
	if run == "" {
		run = filepath.Join(os.TempDir(), "intergate-tunnel-"+strconv.Itoa(os.Getuid()))
	}
	p := Paths{
		User:   true,
		Config: filepath.Join(dir, "intergate-tunnel", "tunnels.yaml"),
		Status: filepath.Join(run, "intergate-tunnel", "status.json"),
		Unit:   filepath.Join(dir, "systemd", "user", "intergate-tunnel.service"),
	}
	if runtime.GOOS == "darwin" {
		if p.Unit, err = launchdUserUnit(); err != nil {
			return Paths{}, err
		}
	}
	return p, nil
}

func launchd() bool { return runtime.GOOS == "darwin" }

// LogsCommand is how to follow the service's log.
func (p Paths) LogsCommand() string {
	if launchd() {
		return "tail -f " + p.launchdLog()
	}
	if p.User {
		return "journalctl --user -u intergate-tunnel -f"
	}
	return "journalctl -u intergate-tunnel -f"
}

// StatusCommand is how to ask the service manager about the service.
func (p Paths) StatusCommand() string {
	if launchd() {
		return "launchctl print " + p.launchdTarget()
	}
	if p.User {
		return "systemctl --user status intergate-tunnel"
	}
	return "systemctl status intergate-tunnel"
}

// systemctl runs systemctl for p's service manager.
func (p Paths) systemctl(args ...string) *exec.Cmd {
	if p.User {
		args = append([]string{"--user"}, args...)
	}
	return exec.Command("systemctl", args...)
}

// Installed reports whether p's service unit exists.
func (p Paths) Installed() bool {
	_, err := os.Stat(p.Unit)
	return err == nil
}

// Active reports whether p's service runs.
func (p Paths) Active() bool {
	if !p.Installed() {
		return false
	}
	if launchd() {
		return p.launchdActive()
	}
	return p.systemctl("is-active", "--quiet", serviceName).Run() == nil
}

// Reload tells a running service to read its configuration again.
func (p Paths) Reload() error {
	if !p.Active() {
		return nil
	}
	if launchd() {
		return p.launchdReload()
	}
	if out, err := p.systemctl("reload", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("reload the service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ShareWithService makes the system configuration's directory, file and
// key readable by root and the service user only. No-op for the user's.
func (p Paths) ShareWithService(cfg *Config) error {
	if p.User || runtime.GOOS != "linux" {
		return nil
	}
	u, err := user.Lookup(ServiceUser)
	if err != nil {
		return nil // not installed yet: install does it
	}
	gid, _ := strconv.Atoi(u.Gid)
	dir := filepath.Dir(p.Config)
	for path, mode := range map[string]os.FileMode{dir: 0o750, p.Config: 0o640, cfg.KeyPath(): 0o640} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := os.Chown(path, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	return nil
}

var unitTemplate = template.Must(template.New("unit").Parse(`[Unit]
Description=intergate tunnels of this machine
Documentation=https://github.com/jgermade/intergate
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{{- if not .User}}
User={{.ServiceUser}}
Group={{.ServiceUser}}
{{- end}}
ExecStart={{.Binary}} run --config {{.Config}} --status {{.Status}}
ExecReload=/bin/kill -HUP $MAINPID
RuntimeDirectory=intergate-tunnel
Restart=always
RestartSec=5s
{{- if not .User}}

NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=0077
{{- end}}

[Install]
WantedBy={{if .User}}default.target{{else}}multi-user.target{{end}}
`))

// Unit is p's service unit, running binary.
func (p Paths) unit(binary string) (string, error) {
	status := p.Status
	if p.User {
		status = "%t/intergate-tunnel/status.json"
	}
	var b strings.Builder
	err := unitTemplate.Execute(&b, map[string]any{
		"User": p.User, "ServiceUser": ServiceUser, "Binary": binary, "Config": p.Config, "Status": status,
	})
	return b.String(), err
}

// ServiceAvailable reports why this machine can't run the service, if it
// can't: systemd on Linux, launchd on macOS.
func ServiceAvailable() error {
	if launchd() {
		return nil
	}
	return systemdAvailable()
}

func systemdAvailable() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("installing the service supports systemd on Linux; on %s run `intergate-tunnel run` from your own service manager", runtime.GOOS)
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is not running here: run `intergate-tunnel run` from your own service manager")
	}
	return nil
}

func run(out io.Writer, desc string, fn func() error) error {
	fmt.Fprintln(out, "→", desc)
	if err := fn(); err != nil {
		return fmt.Errorf("%s: %w", desc, err)
	}
	return nil
}

func command(name string, args ...string) func() error {
	return func() error {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

func (p Paths) command(args ...string) func() error {
	return func() error {
		out, err := p.systemctl(args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// Install sets up and starts p's service. The system one copies this
// binary to /usr/local/bin and runs as its own user; the user's runs this
// binary where it is, and keeps running after logout if linger is allowed.
func (p Paths) Install(cfg *Config, out io.Writer) error {
	if launchd() {
		return p.launchdInstall(cfg, out)
	}
	if err := systemdAvailable(); err != nil {
		return err
	}
	if !p.User && os.Geteuid() != 0 {
		return errors.New("the system service needs root: run it with sudo, or pass --user for your own")
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
		if _, err := user.Lookup(ServiceUser); err != nil {
			if err := run(out, "create system user "+ServiceUser, createUser); err != nil {
				return err
			}
		}
		if err := run(out, "let "+ServiceUser+" read "+filepath.Dir(p.Config), func() error { return p.ShareWithService(cfg) }); err != nil {
			return err
		}
	}
	unit, err := p.unit(binary)
	if err != nil {
		return err
	}
	steps := []struct {
		desc string
		fn   func() error
	}{
		{"write " + p.Unit, func() error { return writeFile(p.Unit, []byte(unit), 0o644) }},
		{"reload systemd", p.command("daemon-reload")},
		{"enable and start " + serviceName, p.command("enable", serviceName)},
		{"restart " + serviceName, p.command("restart", serviceName)},
	}
	for _, s := range steps {
		if err := run(out, s.desc, s.fn); err != nil {
			return err
		}
	}
	if p.User {
		// Without linger, the user's services stop at logout.
		if u, err := user.Current(); err == nil {
			if err := command("loginctl", "enable-linger", u.Username)(); err != nil {
				fmt.Fprintf(out, "Note: it stops when you log out. To keep it running: sudo loginctl enable-linger %s\n", u.Username)
			}
		}
	}
	return nil
}

// Uninstall stops and removes p's service, keeping the configuration and
// the key.
func (p Paths) Uninstall(out io.Writer) error {
	if !p.Installed() {
		return errors.New("the intergate-tunnel service is not installed")
	}
	if launchd() {
		return p.launchdUninstall(out)
	}
	if err := systemdAvailable(); err != nil {
		return err
	}
	if !p.User && os.Geteuid() != 0 {
		return errors.New("removing the system service needs root: run it with sudo")
	}
	if err := run(out, "stop and disable "+serviceName, p.command("disable", "--now", serviceName)); err != nil {
		return err
	}
	if err := run(out, "remove "+p.Unit, func() error { return os.Remove(p.Unit) }); err != nil {
		return err
	}
	return run(out, "reload systemd", p.command("daemon-reload"))
}

func copyBinary(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFile(dst, b, 0o755)
}

func createUser() error {
	if path, err := exec.LookPath("useradd"); err == nil {
		return command(path, "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin", "--comment", "intergate tunnels", ServiceUser)()
	}
	if path, err := exec.LookPath("adduser"); err == nil { // BusyBox (Alpine)
		if err := command("addgroup", "-S", ServiceUser)(); err != nil {
			return err
		}
		return command(path, "-S", "-D", "-H", "-s", "/sbin/nologin", "-G", ServiceUser, ServiceUser)()
	}
	return errors.New("neither useradd nor adduser is available to create the user")
}
