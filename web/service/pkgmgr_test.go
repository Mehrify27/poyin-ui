package service

import "testing"

func TestParseOSReleaseFieldModernDistros(t *testing.T) {
	samples := []struct {
		name    string
		data    string
		wantID  string
		wantVer string
	}{
		{
			name:    "Ubuntu 24.04",
			data:    "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
			wantID:  "ubuntu",
			wantVer: "24.04",
		},
		{
			name:    "Debian 13",
			data:    "ID=debian\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n",
			wantID:  "debian",
			wantVer: "13",
		},
		{
			name:    "Fedora 43",
			data:    "ID=fedora\nVERSION_ID=43\nPRETTY_NAME=\"Fedora Linux 43 (Cloud Edition)\"\n",
			wantID:  "fedora",
			wantVer: "43",
		},
		{
			name:    "AlmaLinux 10",
			data:    "ID=\"almalinux\"\nVERSION_ID=\"10.0\"\nID_LIKE=\"rhel centos fedora\"\n",
			wantID:  "almalinux",
			wantVer: "10.0",
		},
		{
			name:    "Arch Linux",
			data:    "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n",
			wantID:  "arch",
			wantVer: "",
		},
	}

	for _, tc := range samples {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseOSReleaseField(tc.data, "ID"); got != tc.wantID {
				t.Errorf("ID = %q; want %q", got, tc.wantID)
			}
			if got := parseOSReleaseField(tc.data, "VERSION_ID"); got != tc.wantVer {
				t.Errorf("VERSION_ID = %q; want %q", got, tc.wantVer)
			}
		})
	}
}

func TestParseKernelVersionMatrix(t *testing.T) {
	cases := []struct {
		raw     string
		wantMaj int
		wantMin int
		wantOK  bool
	}{
		{"6.8.0-136-generic", 6, 8, true},
		{"7.1.3-arch2-2", 7, 1, true},
		{"5.14.0-687.26.1.el9_8.x86_64", 5, 14, true},
		{"6.12.95+deb13-cloud-amd64", 6, 12, true},
		{"", 0, 0, false},
		{"bad", 0, 0, false},
	}
	for _, tc := range cases {
		maj, min, ok := parseKernelVersion(tc.raw)
		if ok != tc.wantOK || maj != tc.wantMaj || min != tc.wantMin {
			t.Errorf("parseKernelVersion(%q) = (%d, %d, %v); want (%d, %d, %v)",
				tc.raw, maj, min, ok, tc.wantMaj, tc.wantMin, tc.wantOK)
		}
	}
}

func TestDetectHostEnvironmentNoPanic(t *testing.T) {
	env := DetectHostEnvironment()
	if env.SELinux == "" {
		t.Error("expected non-empty SELinux state")
	}
	if env.Firewall == "" {
		t.Error("expected non-empty Firewall state")
	}
}
