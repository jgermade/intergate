package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jgermade/intergate/internal/store"
)

// Whoever a protected tunnel sends to sign in lands, once signed in, on the
// page they asked for: no passkey suggestion on the way, however they sign
// in.
func TestTunnelLoginReturnsToPage(t *testing.T) {
	h := newHarness(t)
	_, _, key := h.setup("alice@example.com", "foo", store.AccessPrivate)
	c, err := h.dial(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	c.forward(t, "foo", 80, backend(t))
	const page = "http://foo." + domain + "/some/page?x=1"

	// The visitor's way to the sign-in form, and where it says to go after.
	toLogin := func(b *http.Client) string {
		t.Helper()
		resp, _ := get(t, b, page)
		if resp.Request.URL.Path != "/login" {
			t.Fatalf("not sent to sign in: %s", resp.Request.URL)
		}
		return resp.Request.URL.Query().Get("rd")
	}
	// Follows the app's redirect and checks the page is the tunnel's.
	lands := func(b *http.Client, how, next string) {
		t.Helper()
		if strings.Contains(next, "welcome") {
			t.Errorf("%s: goes to the passkey suggestion: %s", how, next)
		}
		resp, body := get(t, b, "http://"+domain+next)
		if resp.Request.URL.String() != page || !strings.HasPrefix(body, "backend GET /some/page?x=1 ") {
			t.Errorf("%s: landed on %s (%d)\n%s", how, resp.Request.URL, resp.StatusCode, body)
		}
	}

	// With an email code: the first sign-in, which elsewhere suggests a
	// passkey.
	b := h.browser(true)
	rd := toLogin(b)
	lands(b, "email code", h.emailLogin(b, "alice@example.com", rd))

	// With an OpenID Connect provider.
	b = h.browser(true)
	rd = toLogin(b)
	h.idp.SetUser("alice@example.com")
	resp, body := get(t, b, "http://"+domain+"/auth/test/login?rd="+url.QueryEscape(rd))
	if resp.Request.URL.String() != page || !strings.HasPrefix(body, "backend GET /some/page?x=1 ") {
		t.Errorf("oidc: landed on %s (%d)\n%s", resp.Request.URL, resp.StatusCode, body)
	}

	// The dashboard itself still suggests a passkey.
	if next := h.emailLogin(h.browser(true), "alice@example.com", "/"); !strings.HasPrefix(next, "/account?welcome=1") {
		t.Errorf("dashboard sign-in goes to %q", next)
	}
}
