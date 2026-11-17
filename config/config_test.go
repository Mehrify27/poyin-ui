package config

import "testing"

func TestGetVersionStrictlyAbove194(t *testing.T) {
	v := GetVersion()
	if !IsNewerSemVer(v, "1.9.4") {
		t.Fatalf("GetVersion() = %q; want strictly newer than 1.9.4", v)
	}
	if v != "2.0.3" {
		t.Fatalf("GetVersion() = %q; want 2.0.3", v)
	}

	origLD := ldVersion
	t.Cleanup(func() { ldVersion = origLD })
	ldVersion = "1.9.3"
	if got := GetVersion(); got != DefaultVersion {
		t.Errorf("GetVersion() with ldVersion=1.9.3 = %q; want fallback %q", got, DefaultVersion)
	}
	ldVersion = "v2.3.1"
	if got := GetVersion(); got != "2.3.1" {
		t.Errorf("GetVersion() with ldVersion=v2.3.1 = %q; want 2.3.1", got)
	}
}

func TestCompareSemVerAndIsNewer(t *testing.T) {
	cases := []struct {
		a, b string
		cmp  int
	}{
		{"2.0.0", "1.9.4", 1},
		{"v2.0.0", "v1.9.99", 1},
		{"2.0.1", "2.0.0", 1},
		{"2.1.0", "2.0.9", 1},
		{"2.0.0", "2.0.0", 0},
		{"v2.0.0", "2.0", 0},
		{"1.9.4", "2.0.0", -1},
		{"2.0.0", "2.0.0-rc.1", 1},
		{"2.0.0-rc.2", "2.0.0-rc.1", 1},
		{"2.0.0-rc.1", "2.0.0-beta.9", 1},
		{"2.0.0-beta.2", "2.0.0-beta.1", 1},
		{"2.0.0-rc.1", "1.9.4", 1},
		{"2.0.0+build5", "2.0.0+build1", 0},
	}
	for _, tc := range cases {
		if got := CompareSemVer(tc.a, tc.b); got != tc.cmp {
			t.Errorf("CompareSemVer(%q, %q) = %d; want %d", tc.a, tc.b, got, tc.cmp)
		}
		if got := IsNewerSemVer(tc.a, tc.b); got != (tc.cmp > 0) {
			t.Errorf("IsNewerSemVer(%q, %q) = %v; want %v", tc.a, tc.b, got, tc.cmp > 0)
		}
	}

	for _, invalid := range []string{"", "nightly", "1.a.0", "2.0.0-", "1"} {
		if _, ok := ParseSemVer(invalid); ok {
			t.Errorf("ParseSemVer(%q) unexpectedly succeeded", invalid)
		}
		if IsNewerSemVer(invalid, "1.9.4") {
			t.Errorf("IsNewerSemVer(%q, 1.9.4) unexpectedly returned true", invalid)
		}
	}
}

func TestRepoAndGHProxyConfig(t *testing.T) {
	t.Cleanup(func() {
		SetRepoOverride("")
		SetGHProxyOverride("")
	})

	t.Setenv("VPNUI_REPO", "")
	t.Setenv("REPO", "")
	if got := GetRepo(); got != DefaultRepo {
		t.Errorf("default GetRepo() = %q; want %q", got, DefaultRepo)
	}

	t.Setenv("VPNUI_REPO", "custom-org/custom-vpn-ui")
	if got := GetRepo(); got != "custom-org/custom-vpn-ui" {
		t.Errorf("env GetRepo() = %q; want custom-org/custom-vpn-ui", got)
	}

	SetRepoOverride("flag-org/flag-ui")
	if got := GetRepo(); got != "flag-org/flag-ui" {
		t.Errorf("override GetRepo() = %q; want flag-org/flag-ui", got)
	}

	SetRepoOverride("../evil")
	if got := GetRepo(); got != "custom-org/custom-vpn-ui" {
		t.Errorf("invalid override should be ignored, got %q", got)
	}

	SetGHProxyOverride("https://mirror.example.com")
	raw := "https://github.com/Mehrify27/poyin-ui/releases/latest/download/vpn-ui-amd64"
	want := "https://mirror.example.com/" + raw
	if got := ApplyGHProxy(raw); got != want {
		t.Errorf("ApplyGHProxy() = %q; want %q", got, want)
	}
	if got := ApplyGHProxy(want); got != want {
		t.Errorf("ApplyGHProxy() should be idempotent, got %q", got)
	}
	if got := ApplyGHProxy("https://example.com/file"); got != "https://example.com/file" {
		t.Errorf("ApplyGHProxy() should not modify non-GitHub URLs, got %q", got)
	}
}
