package web

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// passkeyInfo is what a passkey's credential record says about where it
// lives, to tell it apart from the others.
type passkeyInfo struct {
	// Provider names what keeps it, from its AAGUID: "Google Password
	// Manager", "1Password". Empty when unknown: Apple's, among others,
	// send none.
	Provider string `json:"provider"`
	// Kind is "synced" when it can be copied to the provider's other
	// devices, "security-key" for a key plugged in or tapped, and "device"
	// when it stays on the one that made it.
	Kind string `json:"kind"`
}

func describePasskey(record []byte) passkeyInfo {
	var c webauthn.Credential
	if json.Unmarshal(record, &c) != nil {
		return passkeyInfo{Kind: "device"}
	}
	info := passkeyInfo{Provider: passkeyProviders[aaguidString(c.Authenticator.AAGUID)]}
	external := c.Authenticator.Attachment == protocol.CrossPlatform ||
		slices.ContainsFunc(c.Transport, func(t protocol.AuthenticatorTransport) bool {
			return t == protocol.USB || t == protocol.NFC || t == protocol.BLE
		})
	switch {
	case c.Flags.BackupEligible:
		info.Kind = "synced"
	case external && !slices.Contains(c.Transport, protocol.Hybrid):
		info.Kind = "security-key"
	default:
		info.Kind = "device"
	}
	return info
}

// aaguidString writes an AAGUID as the list of providers keys it,
// or "" for none or all zeros.
func aaguidString(b []byte) string {
	if len(b) != 16 || !slices.ContainsFunc(b, func(x byte) bool { return x != 0 }) {
		return ""
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// deviceOf names the browser and system of a User-Agent, as people say
// them: "Chrome on macOS", "Safari on iOS". Either half may be missing, and
// all of it when the User-Agent says nothing known.
func deviceOf(ua string) string {
	browser := ""
	for _, b := range []struct{ token, name string }{
		{"Edg/", "Edge"}, {"EdgiOS/", "Edge"}, {"EdgA/", "Edge"},
		{"OPR/", "Opera"}, {"SamsungBrowser/", "Samsung Internet"},
		{"Vivaldi/", "Vivaldi"}, {"Brave", "Brave"},
		{"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"},
		{"Safari/", "Safari"},
	} {
		if strings.Contains(ua, b.token) {
			browser = b.name
			break
		}
	}
	system := ""
	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPod"):
		system = "iOS"
	case strings.Contains(ua, "iPad"):
		system = "iPadOS"
	case strings.Contains(ua, "Android"):
		system = "Android"
	case strings.Contains(ua, "CrOS"):
		system = "ChromeOS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		system = "macOS"
	case strings.Contains(ua, "Windows"):
		system = "Windows"
	case strings.Contains(ua, "Linux"):
		system = "Linux"
	}
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	default:
		return system
	}
}
