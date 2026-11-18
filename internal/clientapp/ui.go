package clientapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	dashui "github.com/jgermade/intergate/internal/web/ui"
	"github.com/jgermade/intergate/internal/wire"
)

//go:embed ui
var uiFiles embed.FS

var page = template.Must(template.ParseFS(uiFiles, "ui/index.html"))

// UI serves the app's window as a local web page. Only requests to its
// own address carrying its token get in: other local programs and web
// pages can't drive it.
type UI struct {
	app   *App
	token string
	addr  string
	hc    *http.Client
	// Show is called when another instance of the app asks for the
	// window.
	Show func()
}

// NewUI listens on a random port of 127.0.0.1.
func NewUI(app *App) (*UI, net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	b := make([]byte, 16)
	rand.Read(b)
	return &UI{
		app:   app,
		token: hex.EncodeToString(b),
		addr:  ln.Addr().String(),
		hc:    &http.Client{Timeout: 15 * time.Second},
	}, ln, nil
}

// URL opens the window's page.
func (u *UI) URL() string { return "http://" + u.addr + "/?t=" + u.token }

// Token authorizes requests, for another instance asking to show the
// window.
func (u *UI) Token() string { return u.token }

func (u *UI) authorized(r *http.Request) bool {
	if r.Host != u.addr {
		return false // DNS rebinding
	}
	t := r.Header.Get("X-Token")
	if t == "" {
		t = r.URL.Query().Get("t")
	}
	if t == "" {
		if c, err := r.Cookie("t"); err == nil {
			t = c.Value
		}
	}
	return subtle.ConstantTimeCompare([]byte(t), []byte(u.token)) == 1
}

// ServeHTTP implements http.Handler.
func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	if !u.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/" && r.Method != http.MethodGet && r.Header.Get("X-Token") == "" {
		// Changes come from the page's fetch(), which sends the header: a
		// form posted from elsewhere can't.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /":
		http.SetCookie(w, &http.Cookie{Name: "t", Value: u.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		// As the dashboard's: jq79 builds each component's code as scripts
		// carrying this nonce, so the page never needs eval or inline code.
		n := make([]byte, 18)
		rand.Read(n)
		nonce := base64.RawURLEncoding.EncodeToString(n)
		var buf bytes.Buffer
		page.Execute(&buf, struct{ Token, Nonce string }{u.token, nonce})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self'; "+
			"img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		w.Write(buf.Bytes())
	case "GET /api/state":
		// With ?wait=REV, answer at the first change after REV (at once if
		// there was one already), or after 25s. A bare ?wait waits for the
		// next one.
		if r.URL.Query().Has("wait") {
			changed := u.app.Changed()
			if rev, err := strconv.ParseUint(r.URL.Query().Get("wait"), 10, 64); err == nil {
				changed = u.app.ChangedSince(rev)
			}
			select {
			case <-changed:
			case <-time.After(25 * time.Second):
			case <-r.Context().Done():
				return
			}
		}
		writeJSON(w, u.app.State())
	case "PUT /api/settings":
		var s Settings
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&s) != nil {
			fail(w, "invalid settings")
			return
		}
		if err := u.app.SetSettings(s); err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, u.app.State())
	case "POST /api/discover":
		var req struct {
			Dashboard string `json:"dashboard"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := u.app.Discover(ctx, req.Dashboard, u.hc); err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, u.app.State())
	case "POST /api/connect":
		if err := u.app.Connect(); err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, u.app.State())
	case "POST /api/disconnect":
		u.app.Disconnect()
		writeJSON(w, u.app.State())
	case "PUT /api/autostart":
		var req struct {
			On bool `json:"on"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req)
		if err := SetAutostart(req.On); err != nil {
			fail(w, err.Error())
			return
		}
		u.app.mu.Lock()
		u.app.notify()
		u.app.mu.Unlock()
		writeJSON(w, u.app.State())
	case "GET /api/ports":
		sd, err := u.app.Ports()
		if err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, sd)
	case "POST /api/ports":
		var in wire.PortAdd
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in) != nil {
			fail(w, "invalid port")
			return
		}
		p, err := u.app.AddPort(in)
		if err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, p)
	case "PUT /api/ports/allow":
		var req struct {
			Name  string   `json:"name"`
			Allow []string `json:"allow"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req) != nil {
			fail(w, "invalid request")
			return
		}
		p, err := u.app.SetPortAllow(req.Name, req.Allow)
		if err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, p)
	case "POST /api/ports/delete":
		var req struct {
			Name string `json:"name"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
		if err := u.app.DeletePort(req.Name); err != nil {
			fail(w, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "POST /api/show":
		if u.Show != nil {
			u.Show()
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		if r.Method == http.MethodGet && serveFile(w, r) {
			return
		}
		http.NotFound(w, r)
	}
}

// serveFile serves the dashboard's design system under /ui/ and the
// window's own files under /app/.
func serveFile(w http.ResponseWriter, r *http.Request) bool {
	var fsys fs.FS
	var name string
	switch {
	case strings.HasPrefix(r.URL.Path, "/ui/"):
		fsys, name = dashui.FS, strings.TrimPrefix(r.URL.Path, "/ui/")
	case strings.HasPrefix(r.URL.Path, "/app/"):
		fsys, name = uiFiles, "ui/"+strings.TrimPrefix(r.URL.Path, "/app/")
	default:
		return false
	}
	b, err := fs.ReadFile(fsys, name)
	if err != nil || name == "ui/index.html" {
		return false
	}
	http.ServeContent(w, r, path.Base(name), time.Time{}, bytes.NewReader(b))
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
