package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jgermade/intergate/internal/api"
	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/manage"
	"github.com/jgermade/intergate/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// apiError is the body of every error the API answers with.
type apiError struct {
	Error string `json:"error"`
	// Expired tells the sign-in form to start over and ask for a new code.
	Expired bool `json:"expired,omitempty"`
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

// decode reads a JSON request body into v, answering a 400 if it can't.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request.")
		return false
	}
	return true
}

func (s *Server) internalError(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "err", err)
	jsonError(w, http.StatusInternalServerError, msgInternal)
}

// fail answers err as a 400 the user can act on when it is one, and as an
// internal error otherwise.
func (s *Server) fail(w http.ResponseWriter, what string, err error) {
	var me *manage.Error
	if errors.As(err, &me) {
		jsonError(w, http.StatusBadRequest, capitalize(me.Error())+".")
		return
	}
	s.internalError(w, what, err)
}

func capitalize(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

func (s *Server) view(d *store.Subdomain) api.Subdomain {
	v := api.NewSubdomain(s.cfg, d, s.manage.Tunnel(d.Name))
	v.PortsOnline = s.manage.OnlinePorts(d)
	return v
}

func (s *Server) views(subs []*store.Subdomain) []api.Subdomain {
	out := make([]api.Subdomain, len(subs))
	for i, d := range subs {
		out[i] = s.view(d)
	}
	return out
}

func (s *Server) handleListSubdomains(w http.ResponseWriter, r *http.Request) {
	subs, err := s.store.SubdomainsByUser(r.Context(), currentAuth(r).User.ID)
	if err != nil {
		s.internalError(w, "list subdomains", err)
		return
	}
	writeJSON(w, http.StatusOK, s.views(subs))
}

// handleShared lists the subdomains others invited the user to, and that
// let them in now.
func (s *Server) handleShared(w http.ResponseWriter, r *http.Request) {
	list, err := s.manage.SharedWith(r.Context(), currentAuth(r).User)
	if err != nil {
		s.internalError(w, "list shared subdomains", err)
		return
	}
	out := make([]api.Shared, len(list))
	for i, in := range list {
		out[i] = api.NewShared(s.cfg, in, s.manage.Tunnel(in.Subdomain) != nil)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateSubdomain(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	var req struct {
		Name   string       `json:"name"`
		Access store.Access `json:"access"`
		Keys   string       `json:"keys"`
		// AccountKeys are keys of the account to add.
		AccountKeys []int64 `json:"account_keys"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Access == "" {
		req.Access = store.AccessPublic
	}
	d, res, err := s.manage.CreateSubdomain(r.Context(), a.User, req.Name, req.Access, req.Keys, a.Admin, a.User.Email)
	if d == nil {
		s.fail(w, "create subdomain", err)
		return
	}
	if err != nil {
		s.log.Error("add keys", "err", err)
		res.Problems = append(res.Problems, "an internal error occurred")
	}
	result := api.KeysResult{Added: res.Added, Problems: res.Problems}
	if err := s.attachAccountKeys(r, d, req.AccountKeys, &result); err != nil {
		s.log.Error("add account keys", "err", err)
		result.Problems = append(result.Problems, "an internal error occurred")
	}
	// Read back for the key count.
	if d, err = s.store.SubdomainByName(r.Context(), d.Name); err != nil {
		s.internalError(w, "load subdomain", err)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		Subdomain api.Subdomain  `json:"subdomain"`
		Keys      api.KeysResult `json:"keys"`
	}{s.view(d), result})
}

// loadSubdomain returns the subdomain in the URL if the user may manage
// it. Others get a 404, so names of private subdomains don't leak.
func (s *Server) loadSubdomain(w http.ResponseWriter, r *http.Request) *store.Subdomain {
	a := currentAuth(r)
	d, err := s.store.SubdomainByName(r.Context(), r.PathValue("name"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "load subdomain", err)
		return nil
	}
	if d == nil || (d.UserID != a.User.ID && !a.Admin) {
		jsonError(w, http.StatusNotFound, "Subdomain not found.")
		return nil
	}
	return d
}

func (s *Server) handleSubdomain(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	keys, err := s.store.KeysBySubdomain(r.Context(), d.ID)
	if err != nil {
		s.internalError(w, "list keys", err)
		return
	}
	list, err := s.manage.Ports(r.Context(), d)
	if err != nil {
		s.internalError(w, "list ports", err)
		return
	}
	quota, err := s.portQuota(r.Context(), d)
	if err != nil {
		s.internalError(w, "port quota", err)
		return
	}
	guests, err := s.store.GuestsBySubdomain(r.Context(), d.ID)
	if err != nil {
		s.internalError(w, "list guests", err)
		return
	}
	canInvite, err := s.manage.OwnerMayInvite(r.Context(), d)
	if err != nil {
		s.internalError(w, "load owner", err)
		return
	}
	portList := make([]api.Port, len(list))
	for i, p := range list {
		portList[i] = api.NewPort(s.cfg, p, s.manage.PortStats(p.Port))
	}
	writeJSON(w, http.StatusOK, struct {
		api.SubdomainDetail
		SSHCommand string `json:"ssh_command"`
		// PortsCommand forwards every TCP port to its local port with ssh;
		// TunnelCommand forwards every port, UDP included, with the client.
		PortsCommand         string `json:"ports_command"`
		TunnelCommand        string `json:"tunnel_command"`
		TunnelCommandWindows string `json:"tunnel_command_windows"`
		// ClientIP is the address the dashboard sees, to fill in allow lists.
		ClientIP string `json:"client_ip"`
		Mine     bool   `json:"mine"`
		// GuestsLimit is how many people a private subdomain can be shared
		// with.
		GuestsLimit int `json:"guests_limit"`
		// PortQuota is how many ports the subdomain's owner has, across
		// their subdomains, and may have.
		PortQuota portQuota `json:"port_quota"`
	}{
		SubdomainDetail:      api.SubdomainDetail{Subdomain: s.view(d), KeyList: api.NewKeys(keys), PortList: portList, GuestList: api.NewGuests(guests), CanInvite: canInvite},
		SSHCommand:           s.sshCommand(d.Name),
		PortsCommand:         s.portsCommand(d.Name, list),
		TunnelCommand:        s.tunnelCommand(d.Name, list, false),
		TunnelCommandWindows: s.tunnelCommand(d.Name, list, true),
		ClientIP:             s.clientIP(r),
		Mine:                 d.UserID == currentAuth(r).User.ID,
		GuestsLimit:          manage.GuestsPerSubdomain,
		PortQuota:            quota,
	})
}

type portQuota struct {
	Used   int    `json:"used"`
	Max    int    `json:"max"`
	Ranges string `json:"ranges"`
}

// portQuota is how many ports d's owner has and may have.
func (s *Server) portQuota(ctx context.Context, d *store.Subdomain) (portQuota, error) {
	used, l, err := s.manage.PortQuota(ctx, d)
	return portQuota{Used: used, Max: l.Ports, Ranges: config.FormatPortRanges(l.Ranges)}, err
}

func (s *Server) handleUpdateSubdomain(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	// Either or both: a new name, who can open it.
	var req struct {
		Name   string       `json:"name"`
		Access store.Access `json:"access"`
	}
	if !decode(w, r, &req) {
		return
	}
	actor := currentAuth(r).User.Email
	if req.Name == "" && req.Access == "" {
		jsonError(w, http.StatusBadRequest, "Nothing to change.")
		return
	}
	if req.Name != "" {
		if err := s.manage.RenameSubdomain(r.Context(), d, req.Name, actor); err != nil {
			s.fail(w, "rename subdomain", err)
			return
		}
	}
	if req.Access != "" {
		if err := s.manage.SetAccess(r.Context(), d, req.Access, actor); err != nil {
			s.fail(w, "set access", err)
			return
		}
		d.Access = req.Access
	}
	writeJSON(w, http.StatusOK, s.view(d))
}

func (s *Server) handleAddKeys(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	var req struct {
		Keys string `json:"keys"`
		Name string `json:"name"`
		// AccountKey is a key of the account to add instead.
		AccountKey int64 `json:"account_key"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.AccountKey != 0 {
		var result api.KeysResult
		if err := s.attachAccountKeys(r, d, []int64{req.AccountKey}, &result); err != nil {
			s.internalError(w, "add account key", err)
			return
		}
		if result.Added == 0 {
			jsonError(w, http.StatusBadRequest, capitalize(result.Problems[0])+".")
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	res, err := s.manage.AddKeys(r.Context(), d, req.Keys, req.Name, currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, "add keys", err)
		return
	}
	writeJSON(w, http.StatusOK, api.KeysResult{Added: res.Added, Problems: res.Problems})
}

func (s *Server) handleRenameKey(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	name, err := s.manage.RenameKey(r.Context(), d, id, req.Name, currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, "rename key", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := s.manage.RemoveKey(r.Context(), d, id, currentAuth(r).User.Email); err != nil {
		s.fail(w, "delete key", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddGuest(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	// An account, by id or else by email.
	var req struct {
		UserID int64  `json:"user_id"`
		Email  string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	g, err := s.manage.AddGuest(r.Context(), d, req.UserID, req.Email, currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, "add guest", err)
		return
	}
	writeJSON(w, http.StatusCreated, api.NewGuest(g))
}

// handleGuestCandidates lists the accounts the add form offers.
func (s *Server) handleGuestCandidates(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	users, err := s.manage.GuestCandidates(r.Context(), d)
	if err != nil {
		s.internalError(w, "list guest candidates", err)
		return
	}
	writeJSON(w, http.StatusOK, api.NewPeople(users))
}

func (s *Server) handleDeleteGuest(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := s.manage.RemoveGuest(r.Context(), d, id, currentAuth(r).User.Email); err != nil {
		s.fail(w, "remove guest", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// portRequest is the body that adds a port or changes one.
type portRequest struct {
	Name      string         `json:"name"`
	Protocol  store.Protocol `json:"protocol"`
	Preset    string         `json:"preset"`
	LocalPort int            `json:"local_port"`
	Allow     []string       `json:"allow"`
	// Port is the public number asked for, when adding; 0 for any.
	Port int `json:"port"`
}

func (p portRequest) input() manage.PortInput {
	return manage.PortInput{Name: p.Name, Protocol: p.Protocol, Preset: p.Preset, LocalPort: p.LocalPort, Allow: p.Allow, Port: p.Port}
}

func (s *Server) handleAddPort(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	var req portRequest
	if !decode(w, r, &req) {
		return
	}
	p, err := s.manage.CreatePort(r.Context(), d, req.input(), currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, "add port", err)
		return
	}
	writeJSON(w, http.StatusCreated, api.NewPort(s.cfg, p, nil))
}

func (s *Server) handleUpdatePort(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req portRequest
	if !decode(w, r, &req) {
		return
	}
	p, err := s.manage.UpdatePort(r.Context(), d, id, req.input(), currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, "update port", err)
		return
	}
	writeJSON(w, http.StatusOK, api.NewPort(s.cfg, p, s.manage.PortStats(p.Port)))
}

func (s *Server) handleDeletePort(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.manage.DeletePort(r.Context(), d, id, currentAuth(r).User.Email); err != nil {
		s.fail(w, "delete port", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"disconnected": s.manage.Disconnect(d, currentAuth(r).User.Email)})
}

func (s *Server) handleDeleteSubdomain(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	if err := s.manage.DeleteSubdomain(r.Context(), d, currentAuth(r).User.Email); err != nil {
		s.internalError(w, "delete subdomain", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// passkey describes a passkey to its owner.
type passkey struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

func passkeyView(p *store.Passkey) passkey {
	return passkey{p.ID, p.Name, p.CreatedAt, p.LastUsedAt}
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	keys := []passkey{}
	if s.webauthn != nil {
		list, err := s.store.PasskeysByUser(r.Context(), currentAuth(r).User.ID)
		if err != nil {
			s.internalError(w, "list passkeys", err)
			return
		}
		for _, p := range list {
			keys = append(keys, passkeyView(p))
		}
	}
	accountKeys, err := s.accountKeys(r)
	if err != nil {
		s.internalError(w, "list account keys", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": keys, "keys": accountKeys, "keys_limit": manage.KeysPerAccount})
}

func (s *Server) handleAdminSubdomains(w http.ResponseWriter, r *http.Request) {
	subs, err := s.store.AllSubdomains(r.Context())
	if err != nil {
		s.internalError(w, "list subdomains", err)
		return
	}
	writeJSON(w, http.StatusOK, s.views(subs))
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.internalError(w, "list users", err)
		return
	}
	out := make([]api.User, len(users))
	for i, u := range users {
		out[i] = api.NewUser(s.cfg, u, s.manage.Limits(&u.User))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string     `json:"email"`
		Role  store.Role `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	a := currentAuth(r)
	u, err := s.manage.AddUser(r.Context(), req.Email, req.Role, a.User, a.Role)
	if err != nil {
		s.fail(w, "create user", err)
		return
	}
	writeJSON(w, http.StatusCreated, api.NewUser(s.cfg, store.UserSummary{User: *u}, s.manage.Limits(u)))
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id == a.User.ID {
		jsonError(w, http.StatusBadRequest, "You can't delete your own account.")
		return
	}
	if u, err := s.store.UserByID(r.Context(), id); err == nil && s.cfg.IsAdmin(u.Email) {
		jsonError(w, http.StatusBadRequest, u.Email+" is an owner in the configuration (auth.admins): remove them there first.")
		return
	}
	if !s.mayManageOwner(w, r, id, "delete") {
		return
	}
	if err := s.manage.DeleteUser(r.Context(), id, a.User.Email); err != nil {
		s.fail(w, "delete user", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// mayManageOwner answers with an error, and false, when the user with this
// id is an owner and the signed-in administrator is not: only owners manage
// owners.
func (s *Server) mayManageOwner(w http.ResponseWriter, r *http.Request, id int64, action string) bool {
	if currentAuth(r).Role == store.RoleOwner {
		return true
	}
	if u, err := s.store.UserByID(r.Context(), id); err == nil && s.cfg.UserRole(u.Email, string(u.Role)) == string(store.RoleOwner) {
		jsonError(w, http.StatusForbidden, "Only owners can "+action+" an owner.")
		return false
	}
	return true
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Disabled  *bool       `json:"disabled"`
		Role      *store.Role `json:"role"`
		CanInvite *bool       `json:"can_invite"`
		// Limits replaces all of the user's limits; a null count is the
		// configuration's.
		Limits *struct {
			Subdomains *int   `json:"subdomains"`
			Ports      *int   `json:"ports"`
			Ranges     string `json:"ranges"`
		} `json:"limits"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Disabled == nil && req.Role == nil && req.Limits == nil && req.CanInvite == nil {
		jsonError(w, http.StatusBadRequest, "Nothing to change.")
		return
	}
	if id == a.User.ID && req.Disabled != nil && *req.Disabled {
		jsonError(w, http.StatusBadRequest, "You can't disable your own account.")
		return
	}
	if req.Disabled != nil && !s.mayManageOwner(w, r, id, "enable or disable") {
		return
	}
	if req.Disabled != nil {
		if err := s.manage.SetUserDisabled(r.Context(), id, *req.Disabled, a.User.Email); err != nil {
			s.fail(w, "set user disabled", err)
			return
		}
	}
	if req.Role != nil {
		if err := s.manage.SetUserRole(r.Context(), id, *req.Role, a.User, a.Role); err != nil {
			s.fail(w, "set user role", err)
			return
		}
	}
	if req.CanInvite != nil {
		if !s.mayManageOwner(w, r, id, "change the options of") {
			return
		}
		if err := s.manage.SetUserCanInvite(r.Context(), id, *req.CanInvite, a.User.Email); err != nil {
			s.fail(w, "set user can invite", err)
			return
		}
	}
	if req.Limits != nil {
		if !s.mayManageOwner(w, r, id, "change the limits of") {
			return
		}
		in := manage.LimitsInput{Subdomains: req.Limits.Subdomains, Ports: req.Limits.Ports, Ranges: req.Limits.Ranges}
		if err := s.manage.SetUserLimits(r.Context(), id, in, a.User.Email); err != nil {
			s.fail(w, "set user limits", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
