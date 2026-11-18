// Package wire holds the SSH global requests the intergate client sends,
// besides forwarding, to see and change a subdomain's ports with the key
// it signed in with. Payloads and replies are JSON. A request the server
// understands is always answered with success and a reply whose Error says
// what went wrong, since an SSH failure carries no message; a server too
// old to know a request answers it with failure.
package wire

import "encoding/json"

const (
	// InfoRequest asks for the subdomains the key may open, with their
	// ports. Payload: InfoQuery. Reply: Info.
	InfoRequest = "info@intergate"
	// PortAddRequest creates a port. Payload: PortAdd. Reply: PortReply.
	PortAddRequest = "port-add@intergate"
	// PortUpdateRequest changes who may reach a port. Payload: PortUpdate.
	// Reply: PortReply.
	PortUpdateRequest = "port-update@intergate"
	// PortDeleteRequest deletes a port; its number goes back to the range.
	// Payload: PortRef. Reply: Reply.
	PortDeleteRequest = "port-delete@intergate"
)

// Reply is the part every reply has.
type Reply struct {
	Error string `json:"error,omitempty"`
}

// InfoQuery narrows Info to one subdomain; empty asks for all.
type InfoQuery struct {
	Subdomain string `json:"subdomain,omitempty"`
}

// Info describes what the key may open.
type Info struct {
	Reply
	Domain     string      `json:"domain"`
	Subdomains []Subdomain `json:"subdomains"`
}

// Subdomain is one the key may open.
type Subdomain struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Ports []Port `json:"ports"`
	// Quota is its owner's, across their subdomains.
	Quota Quota `json:"quota"`
}

// Quota is how many ports a subdomain's owner has and may have, and the
// ranges their numbers come from (like "30100-30109,30200-30299").
type Quota struct {
	Used   int    `json:"used"`
	Max    int    `json:"max"`
	Ranges string `json:"ranges"`
}

// Port is a port of a subdomain.
type Port struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Address  string `json:"address"`
	// Allow lists the addresses and CIDRs that may connect; empty is
	// anyone.
	Allow     []string `json:"allow"`
	LocalPort int      `json:"local_port"`
	CreatedBy string   `json:"created_by,omitempty"`
}

// PortRef names a port.
type PortRef struct {
	Subdomain string `json:"subdomain"`
	Name      string `json:"name"`
}

// PortAdd creates a port. Allow must be given, ["any"] for anyone, so a
// port is never open by mistake. Port 0 takes any free number of the
// owner's ranges.
type PortAdd struct {
	PortRef
	Protocol  string   `json:"protocol"`
	Allow     []string `json:"allow"`
	Port      int      `json:"port,omitempty"`
	LocalPort int      `json:"local_port"`
}

// PortUpdate sets who may reach a port, as in PortAdd.
type PortUpdate struct {
	PortRef
	Allow []string `json:"allow"`
}

// PortReply answers a request that leaves a port behind.
type PortReply struct {
	Reply
	Port *Port `json:"port,omitempty"`
}

// Marshal encodes v; it never fails for this package's types.
func Marshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Anyone is how a client asks for a port open to every address.
const Anyone = "any"

// ParseAllow turns a client's allow list into the server's: ["any"] is
// anyone (empty), and an empty list is an error the caller reports.
func ParseAllow(allow []string) (list []string, ok bool) {
	if len(allow) == 1 && allow[0] == Anyone {
		return []string{}, true
	}
	return allow, len(allow) > 0
}
