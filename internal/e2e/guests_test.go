package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jgermade/intergate/internal/api"
	"github.com/jgermade/intergate/internal/store"
)

// A private subdomain opens to its owner and to the existing users they
// invited, while an administrator lets them invite; checked on every
// request.
func TestPrivateGuests(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	aliceUser, _, key := h.setup("alice@example.com", "secret", store.AccessPrivate)
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
	admin := h.browser(true)
	h.login(admin, "admin@example.com")
	bobUser, _ := h.store.UserByEmail(ctx, "bob@example.com")
	carolUser, _ := h.store.UserByEmail(ctx, "carol@example.com")
	const tunnelURL = "http://secret." + domain + "/"
	guests := "/api/subdomains/secret/guests"
	type detailView struct {
		api.SubdomainDetail
		GuestsLimit int `json:"guests_limit"`
	}
	detail := func() detailView {
		t.Helper()
		_, body := call(t, alice, "GET", "/api/subdomains/secret", nil)
		return decode[detailView](t, body)
	}
	setInvite := func(can bool) {
		t.Helper()
		if resp, body := call(t, admin, "PATCH", fmt.Sprintf("/api/admin/users/%d", aliceUser.ID), map[string]bool{"can_invite": can}); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("set can_invite %v: %d %s", can, resp.StatusCode, body)
		}
	}

	// Users may not invite until an administrator lets them.
	if d := detail(); d.CanInvite {
		t.Fatal("alice may invite before being allowed")
	}
	if resp, body := call(t, alice, "POST", guests, map[string]string{"email": "bob@example.com"}); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "may not invite other users") {
		t.Fatalf("invite without the right: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, alice, "PATCH", fmt.Sprintf("/api/admin/users/%d", aliceUser.ID), map[string]bool{"can_invite": true}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("alice allows herself: %d", resp.StatusCode)
	}
	setInvite(true)
	if d := detail(); !d.CanInvite || d.GuestsLimit == 0 {
		t.Fatalf("after allowing: %+v", d)
	}

	if resp, _ := get(t, bob, tunnelURL); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("bob before being invited: %d", resp.StatusCode)
	}
	resp, body := call(t, alice, "POST", guests, map[string]string{"email": " Bob@Example.com "})
	guest := decode[api.Guest](t, body)
	if resp.StatusCode != http.StatusCreated || guest.Email != "bob@example.com" || guest.UserID != bobUser.ID || guest.ID == 0 {
		t.Fatalf("invite bob: %d %s", resp.StatusCode, body)
	}

	// Only existing accounts that may sign in, once each.
	if _, err := h.store.CreateUser(ctx, "outsider@other.test", ""); err != nil {
		t.Fatal(err)
	}
	dan, _ := h.store.CreateUser(ctx, "dan@example.com", "")
	h.store.SetUserDisabled(ctx, dan.ID, true)
	for _, bad := range []struct {
		req  any
		want string
	}{
		{map[string]any{"user_id": bobUser.ID}, "It is already open to bob@example.com."},
		{map[string]string{"email": "ALICE@example.com"}, "The owner, alice@example.com, can always open secret."},
		{map[string]string{"email": "nobody@example.com"}, "There is no account for nobody@example.com: only existing users can be invited."},
		{map[string]any{"user_id": 99999}, "That user no longer exists."},
		{map[string]string{"email": "dan@example.com"}, "The account dan@example.com is disabled."},
		{map[string]string{"email": "outsider@other.test"}, "The account outsider@other.test may not sign in"},
		{map[string]string{"email": "not an email"}, "is not an email address"},
	} {
		if resp, body := call(t, alice, "POST", guests, bad.req); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, bad.want) {
			t.Errorf("invite %v: %d %s", bad.req, resp.StatusCode, body)
		}
	}
	// Only who manages the subdomain manages its guests.
	if resp, _ := call(t, carol, "POST", guests, map[string]any{"user_id": carolUser.ID}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("carol invites herself: %d", resp.StatusCode)
	}
	if resp, _ := call(t, carol, "DELETE", fmt.Sprintf("%s/%d", guests, guest.ID), nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("carol removes bob: %d", resp.StatusCode)
	}
	if resp, _ := call(t, carol, "GET", guests+"/candidates", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("carol lists candidates: %d", resp.StatusCode)
	}

	// The select offers the others: enabled, allowed to sign in, not there.
	_, body = call(t, alice, "GET", guests+"/candidates", nil)
	var offered []string
	for _, p := range decode[[]api.Person](t, body) {
		offered = append(offered, p.Email)
	}
	if got := fmt.Sprint(offered); got != "[admin@example.com carol@example.com]" {
		t.Errorf("candidates = %s", got)
	}

	if d := detail(); len(d.GuestList) != 1 || d.GuestList[0].Email != "bob@example.com" || d.Guests != 1 {
		t.Fatalf("detail: %+v", d)
	}
	// Bob gets in at once, with the session he already had; carol doesn't.
	if resp, body := get(t, bob, tunnelURL+"page"); resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "backend GET /page ") {
		t.Errorf("bob as a guest: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, carol, tunnelURL); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("carol, not a guest: %d", resp.StatusCode)
	}

	// Taking away the right to invite keeps the list but closes the door;
	// giving it back opens it again.
	setInvite(false)
	if resp, _ := get(t, bob, tunnelURL); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("bob once alice may not invite: %d", resp.StatusCode)
	}
	if d := detail(); d.CanInvite || len(d.GuestList) != 1 {
		t.Errorf("detail once alice may not invite: %+v", d)
	}
	if resp, _ := get(t, alice, tunnelURL); resp.StatusCode != http.StatusOK {
		t.Errorf("alice, the owner: %d", resp.StatusCode)
	}
	setInvite(true)
	if resp, _ := get(t, bob, tunnelURL); resp.StatusCode != http.StatusOK {
		t.Errorf("bob once alice may invite again: %d", resp.StatusCode)
	}

	// Removing bob closes it to him on his next request.
	if resp, _ := call(t, alice, "DELETE", fmt.Sprintf("%s/%d", guests, guest.ID), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove bob: %d", resp.StatusCode)
	}
	if resp, _ := get(t, bob, tunnelURL); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("bob after being removed: %d", resp.StatusCode)
	}
	if resp, body := call(t, alice, "DELETE", fmt.Sprintf("%s/%d", guests, guest.ID), nil); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "already removed") {
		t.Errorf("remove bob again: %d %s", resp.StatusCode, body)
	}

	// An administrator manages them too, from the dashboard and the socket.
	if resp, body := call(t, admin, "POST", guests, map[string]any{"user_id": carolUser.ID}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin invites carol: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, carol, tunnelURL); resp.StatusCode != http.StatusOK {
		t.Errorf("carol as a guest: %d", resp.StatusCode)
	}
	sock := h.serveAdmin()
	g, err := sock.AddGuest(ctx, "secret", bobUser.ID)
	if err != nil || g.Email != "bob@example.com" {
		t.Fatalf("socket invite = %+v, %v", g, err)
	}
	sd, err := sock.Subdomain(ctx, "secret")
	if err != nil || !sd.CanInvite || len(sd.GuestList) != 2 || sd.GuestList[0].Email != "carol@example.com" || sd.GuestList[1].Email != "bob@example.com" {
		t.Fatalf("socket detail = %+v, %v", sd, err)
	}
	if err := sock.SetUserCanInvite(ctx, aliceUser.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := sock.AddGuest(ctx, "secret", bobUser.ID); err == nil || !strings.Contains(err.Error(), "may not invite") {
		t.Errorf("socket invites for alice, who may not: %v", err)
	}
	if err := sock.SetUserCanInvite(ctx, aliceUser.ID, true); err != nil {
		t.Fatal(err)
	}
	// Deleting an account removes it from the subdomains it was invited to.
	if resp, _ := call(t, admin, "DELETE", fmt.Sprintf("/api/admin/users/%d", carolUser.ID), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete carol: %d", resp.StatusCode)
	}
	if d := detail(); len(d.GuestList) != 1 || d.GuestList[0].Email != "bob@example.com" {
		t.Errorf("after deleting carol: %+v", d.GuestList)
	}

	// Admins and owners may always invite, whatever their flag.
	adminUser, _ := h.store.UserByEmail(ctx, "admin@example.com")
	if _, err := h.store.CreateSubdomain(ctx, adminUser.ID, "ops", store.AccessPrivate); err != nil {
		t.Fatal(err)
	}
	if resp, body := call(t, admin, "POST", "/api/subdomains/ops/guests", map[string]any{"user_id": bobUser.ID}); resp.StatusCode != http.StatusCreated {
		t.Errorf("admin invites to their own: %d %s", resp.StatusCode, body)
	}
}
