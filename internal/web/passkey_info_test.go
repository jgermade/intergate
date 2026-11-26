package web

import (
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestDeviceOf(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36":                   "Chrome on macOS",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15":                   "Safari on macOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1": "Safari on iOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0 Mobile/15E148 Safari/604.1":  "Chrome on iOS",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0":           "Edge on Windows",
		"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0":                                                                  "Firefox on Linux",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36":                   "Chrome on Android",
		"curl/8.5.0": "",
		"":           "",
	} {
		if got := deviceOf(ua); got != want {
			t.Errorf("deviceOf(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestDescribePasskey(t *testing.T) {
	gpm := []byte{0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4}
	record := func(c webauthn.Credential) []byte {
		b, _ := json.Marshal(c)
		return b
	}
	for name, tc := range map[string]struct {
		cred webauthn.Credential
		want passkeyInfo
	}{
		"google, synced": {webauthn.Credential{
			Authenticator: webauthn.Authenticator{AAGUID: gpm},
			Flags:         webauthn.CredentialFlags{BackupEligible: true, BackupState: true},
		}, passkeyInfo{"Google Password Manager", "synced"}},
		"apple, no aaguid": {webauthn.Credential{
			Authenticator: webauthn.Authenticator{AAGUID: make([]byte, 16), Attachment: protocol.Platform},
			Flags:         webauthn.CredentialFlags{BackupEligible: true},
		}, passkeyInfo{"", "synced"}},
		"security key": {webauthn.Credential{
			Authenticator: webauthn.Authenticator{Attachment: protocol.CrossPlatform},
			Transport:     []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC},
		}, passkeyInfo{"", "security-key"}},
		"phone, nearby": {webauthn.Credential{
			Authenticator: webauthn.Authenticator{Attachment: protocol.CrossPlatform},
			Transport:     []protocol.AuthenticatorTransport{protocol.Hybrid, protocol.Internal},
		}, passkeyInfo{"", "device"}},
	} {
		if got := describePasskey(record(tc.cred)); got != tc.want {
			t.Errorf("%s: describePasskey = %+v, want %+v", name, got, tc.want)
		}
	}
	if got := describePasskey([]byte("not json")); got.Kind != "device" {
		t.Errorf("describePasskey(bad record) = %+v", got)
	}
}
