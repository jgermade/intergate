package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GateInfo is what a dashboard's /client.json says about its server.
type GateInfo struct {
	// Server is host:port of the SSH endpoint.
	Server string `json:"server"`
	// HostKey is the SSH host key's fingerprint, SHA256:...
	HostKey string `json:"host_key"`
	// Domain is the dashboard's host; tunnels are its subdomains.
	Domain    string `json:"domain"`
	Dashboard string `json:"dashboard"`
	Version   string `json:"version"`
}

// DashboardURL is dashboard as a URL: https:// unless it says otherwise.
func DashboardURL(dashboard string) (*url.URL, error) {
	dashboard = strings.TrimSpace(dashboard)
	if !strings.Contains(dashboard, "://") {
		dashboard = "https://" + dashboard
	}
	u, err := url.Parse(dashboard)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not an address like gate.example.com", dashboard)
	}
	return u, nil
}

// Discover asks an intergate dashboard where its SSH endpoint is and which
// host key it has. Without a transport of its own, hc (or, when nil, a
// client of this package) knows *.localhost.
func Discover(ctx context.Context, dashboard string, hc *http.Client) (*GateInfo, error) {
	if hc == nil {
		hc = defaultHTTP
	} else if hc.Transport == nil {
		c := *hc
		c.Transport = defaultHTTP.Transport
		hc = &c
	}
	u, err := DashboardURL(dashboard)
	if err != nil {
		return nil, err
	}
	u.Path, u.RawQuery, u.Fragment = "/client.json", "", ""
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	var info GateInfo
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info) != nil ||
		info.Server == "" || !strings.HasPrefix(info.HostKey, "SHA256:") {
		return nil, fmt.Errorf("%s doesn't look like an intergate (no /client.json)", u.Host)
	}
	info.Dashboard = strings.TrimSuffix(info.Dashboard, "/")
	return &info, nil
}

// loopback maps an address under .localhost to 127.0.0.1, as browsers do
// (RFC 6761): the README suggests *.localhost for local development, and
// Go's resolver doesn't know it.
func loopback(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if h := strings.ToLower(strings.TrimSuffix(host, ".")); h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}

// dialContext is net.Dialer's, with loopback.
func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = 15 * time.Second
	return d.DialContext(ctx, network, loopback(addr))
}

var defaultHTTP = &http.Client{
	Timeout:   20 * time.Second,
	Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dialContext, TLSHandshakeTimeout: 10 * time.Second},
}
