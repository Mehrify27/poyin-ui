package database

import (
	"testing"
)

func TestResolveInitialAdminCredentials(t *testing.T) {
	t.Run("generates random strong password by default", func(t *testing.T) {
		t.Setenv("VPNUI_INIT_ADMIN_USER", "")
		t.Setenv("VPNUI_INIT_ADMIN_PASS", "")

		user, pass, generated, err := resolveInitialAdminCredentials()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if user != defaultUsername {
			t.Fatalf("user = %q, want %q", user, defaultUsername)
		}
		if !generated {
			t.Fatalf("expected generated=true when no env password is supplied")
		}
		if pass == "" || pass == "admin" || len(pass) < 16 {
			t.Fatalf("generated password is not strong enough: %q (len=%d)", pass, len(pass))
		}

		// Two calls must produce distinct passwords.
		_, pass2, _, err := resolveInitialAdminCredentials()
		if err != nil {
			t.Fatalf("second call error: %v", err)
		}
		if pass2 == pass {
			t.Fatalf("expected distinct generated passwords across calls")
		}
	})

	t.Run("honors valid custom user and password", func(t *testing.T) {
		t.Setenv("VPNUI_INIT_ADMIN_USER", "  rootop  ")
		t.Setenv("VPNUI_INIT_ADMIN_PASS", "Str0ngPass!2026")

		user, pass, generated, err := resolveInitialAdminCredentials()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if user != "rootop" {
			t.Fatalf("user = %q, want %q", user, "rootop")
		}
		if pass != "Str0ngPass!2026" {
			t.Fatalf("pass mismatch: %q", pass)
		}
		if generated {
			t.Fatalf("expected generated=false when VPNUI_INIT_ADMIN_PASS is set")
		}
	})

	t.Run("rejects weak or default env passwords", func(t *testing.T) {
		for _, bad := range []string{"admin", "1234567", "short"} {
			t.Setenv("VPNUI_INIT_ADMIN_USER", "op")
			t.Setenv("VPNUI_INIT_ADMIN_PASS", bad)
			if _, _, _, err := resolveInitialAdminCredentials(); err == nil {
				t.Fatalf("expected error for weak VPNUI_INIT_ADMIN_PASS %q", bad)
			}
		}
	})
}

func TestSQLiteConnURI(t *testing.T) {
	if got := sqliteConnURI("/etc/vpn-ui/vpn-ui.db", "_busy_timeout=10000"); got != "/etc/vpn-ui/vpn-ui.db?_busy_timeout=10000" {
		t.Fatalf("got %q", got)
	}
	if got := sqliteConnURI("/etc/vpn-ui/vpn-ui.db?cache=shared", "?mode=ro&_busy_timeout=10000"); got != "/etc/vpn-ui/vpn-ui.db?cache=shared&mode=ro&_busy_timeout=10000" {
		t.Fatalf("got %q", got)
	}
}
