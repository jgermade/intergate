package e2e

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jgermade/intergate/internal/api"
	"github.com/jgermade/intergate/internal/store"
)

// A private subdomain opens to its owner and to the people they choose,
// checked on every request.
func TestPrivateGuests(t *testing.T) {
	h := newHarness(t)
	_, _, key := h.setup("alice@example.com", "secret", store.AccessPrivate)
	c, err := h.dial(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	c.forward(t, "secret", 80, backend(t))

	alice := h.browser(true)
	h.login(alice, "alice@example.com")
	bob := h.browser(true)
	h.login(bob, "bob@example.com")
	carol := h.browser(true)
	h.login(carol, "carol@example.com")
	const tunnelURL = "http://secret." + domain + "/"

	// Before alice shares it, bob sees it as offline.
	if resp, _ := get(t, bob, tunnelURL); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("bob before being added: %d", resp.StatusCode)
	}

	resp, body := call(t, alice, "POST", "/api/subdomains/secret/guests", map[string]string{"email": " Bob@Example.com "})
	guest := decode[api.Guest](t, body)
	if resp.StatusCode != http.StatusCreated || guest.Email != "bob@example.com" || guest.ID == 0 {
		t.Fatalf("add bob: %d %s", resp.StatusCode, body)
	}
	for _, bad := range []struct{ email, want string }{
		{"bob@example.com", "It is already open to bob@example.com."},
		{"ALICE@example.com", "The owner, alice@example.com, can always open secret."},
		{"not an email", "is not an email address"},
		{"", "is not an email address"},
	} {
		if resp, body := call(t, alice, "POST", "/api/subdomains/secret/guests", map[string]string{"email": bad.email}); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, bad.want) {
			t.Errorf("add %q: %d %s", bad.email, resp.StatusCode, body)
		}
	}
	// Only who manages the subdomain manages its guests.
	if resp, _ := call(t, carol, "POST", "/api/subdomains/secret/guests", map[string]string{"email": "carol@example.com"}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("carol adds herself: %d", resp.StatusCode)
	}
	if resp, _ := call(t, carol, "DELETE", fmt.Sprintf("/api/subdomains/secret/guests/%d", guest.ID), nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("carol removes bob: %d", resp.StatusCode)
	}

	_, body = call(t, alice, "GET", "/api/subdomains/secret", nil)
	detail := decode[struct {
		api.SubdomainDetail
		GuestsLimit int `json:"guests_limit"`
	}](t, body)
	if len(detail.GuestList) != 1 || detail.GuestList[0].Email != "bob@example.com" || detail.Guests != 1 || detail.GuestsLimit == 0 {
		t.Fatalf("detail: %s", body)
	}

	// Bob gets in at once, with the session he already had; carol doesn't.
	if resp, body := get(t, bob, tunnelURL+"page"); resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "backend GET /page ") {
		t.Errorf("bob as a guest: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, carol, tunnelURL); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("carol, not a guest: %d", resp.StatusCode)
	}
	if resp, _ := get(t, alice, tunnelURL); resp.StatusCode != http.StatusOK {
		t.Errorf("alice, the owner: %d", resp.StatusCode)
	}

	// Removing bob closes it to him on his next request.
	if resp, _ := call(t, alice, "DELETE", fmt.Sprintf("/api/subdomains/secret/guests/%d", guest.ID), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove bob: %d", resp.StatusCode)
	}
	if resp, _ := get(t, bob, tunnelURL); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("bob after being removed: %d", resp.StatusCode)
	}
	if resp, body := call(t, alice, "DELETE", fmt.Sprintf("/api/subdomains/secret/guests/%d", guest.ID), nil); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "already removed") {
		t.Errorf("remove bob again: %d %s", resp.StatusCode, body)
	}

	// An administrator manages them too, from the dashboard and the socket.
	admin := h.browser(true)
	h.login(admin, "admin@example.com")
	if resp, body := call(t, admin, "POST", "/api/subdomains/secret/guests", map[string]string{"email": "carol@example.com"}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin adds carol: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, carol, tunnelURL); resp.StatusCode != http.StatusOK {
		t.Errorf("carol as a guest: %d", resp.StatusCode)
	}
	sock := h.serveAdmin()
	g, err := sock.AddGuest(t.Context(), "secret", "dave@example.com")
	if err != nil || g.Email != "dave@example.com" {
		t.Fatalf("socket add = %+v, %v", g, err)
	}
	sd, err := sock.Subdomain(t.Context(), "secret")
	if err != nil || len(sd.GuestList) != 2 || sd.GuestList[0].Email != "carol@example.com" || sd.GuestList[1].Email != "dave@example.com" {
		t.Fatalf("socket detail = %+v, %v", sd, err)
	}
	if err := sock.RemoveGuest(t.Context(), "secret", sd.GuestList[0].ID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get(t, carol, tunnelURL); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("carol after the socket removed her: %d", resp.StatusCode)
	}
	if _, err := sock.AddGuest(t.Context(), "secret", "alice@example.com"); err == nil || !strings.Contains(err.Error(), "can always open secret") {
		t.Errorf("socket adds the owner: %v", err)
	}
}

// The add form suggests accounts that could open the subdomain.
func TestGuestSuggestions(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	h.setup("alice@example.com", "secret", store.AccessPrivate)
	for _, u := range []struct{ email, name string }{
		{"bob@example.com", "Bob Builder"},
		{"barbara@example.com", ""},
		{"robert_b@example.com", "Rob"},
		{"dan@example.com", "Dan Bobson"},
		{"outsider@other.test", "Bob Outside"},
	} {
		if _, err := h.store.CreateUser(ctx, u.email, u.name); err != nil {
			t.Fatal(err)
		}
	}
	dan, _ := h.store.UserByEmail(ctx, "dan@example.com")
	if err := h.store.SetUserDisabled(ctx, dan.ID, true); err != nil {
		t.Fatal(err)
	}
	alice := h.browser(true)
	h.login(alice, "alice@example.com")
	suggest := func(q string) []string {
		t.Helper()
		resp, body := call(t, alice, "GET", "/api/subdomains/secret/guests/suggestions?q="+url.QueryEscape(q), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("suggest %q: %d %s", q, resp.StatusCode, body)
		}
		var emails []string
		for _, p := range decode[[]api.Person](t, body) {
			emails = append(emails, p.Email)
		}
		return emails
	}

	// By email or name, emails starting with it first; never the owner, a
	// disabled account or one that may not sign in.
	if got := fmt.Sprint(suggest("B")); got != "[barbara@example.com bob@example.com robert_b@example.com]" {
		t.Errorf("suggest B = %s", got)
	}
	if got := fmt.Sprint(suggest("builder")); got != "[bob@example.com]" {
		t.Errorf("suggest builder = %s", got)
	}
	if got := suggest("alice"); len(got) != 0 {
		t.Errorf("the owner suggested: %v", got)
	}
	// LIKE's wildcards are only themselves.
	if got := fmt.Sprint(suggest("_")); got != "[robert_b@example.com]" {
		t.Errorf("suggest _ = %s", got)
	}
	if got := suggest("%"); len(got) != 0 {
		t.Errorf("suggest %% = %v", got)
	}
	if got := suggest("  "); len(got) != 0 {
		t.Errorf("suggest blank = %v", got)
	}
	// Once added, someone is no longer suggested.
	call(t, alice, "POST", "/api/subdomains/secret/guests", map[string]string{"email": "bob@example.com"})
	if got := fmt.Sprint(suggest("b")); got != "[barbara@example.com robert_b@example.com]" {
		t.Errorf("suggest b after adding bob = %s", got)
	}
	// Only who manages the subdomain gets suggestions for it.
	if resp, _ := call(t, h.loggedIn("barbara@example.com"), "GET", "/api/subdomains/secret/guests/suggestions?q=b", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("barbara asks: %d", resp.StatusCode)
	}
}
