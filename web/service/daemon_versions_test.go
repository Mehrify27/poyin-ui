package service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDaemonVersionExtractionHandlesSubcommandsAndNonZeroExits(t *testing.T) {
	deps := engineProbeDeps{
		runVersionCmd: func(binPath string, args []string) (string, error) {
			base := filepath.Base(binPath)
			switch base {
			case "sing-box":
				if len(args) > 0 && args[0] == "version" {
					return "sing-box version 1.14.4\nEnvironment: go1.25.0 linux/amd64", nil
				}
				return "unknown flag: --version", errors.New("exit status 1")
			case "xl2tpd":
				if len(args) > 0 && args[0] == "-v" {
					return "xl2tpd version:  xl2tpd-1.3.20\n", errors.New("exit status 1")
				}
				return "", errors.New("exit status 1")
			case "openvpn":
				return "OpenVPN 2.6.23 x86_64-alpine-linux-musl [SSL (OpenSSL)] [LZO] [LZ4]", errors.New("exit status 1")
			case "pptpd":
				return "pptpd v1.4.0", errors.New("exit status 1")
			case "charon":
				return "strongSwan 5.9.14", nil
			default:
				return base + " 1.0.0", nil
			}
		},
	}

	cases := []struct {
		name string
		want string
	}{
		{"sing-box", "1.14.4"},
		{"xl2tpd", "1.3.20"},
		{"openvpn", "2.6.23"},
		{"pptpd", "1.4.0"},
		{"charon", "5.9.14"},
	}
	for _, tc := range cases {
		ver, banner := probeDaemonBinaryVersionWith(tc.name, "/usr/bin/"+tc.name, deps)
		if ver != tc.want {
			t.Errorf("probeDaemonBinaryVersionWith(%s) = (%q, %q), want version %q", tc.name, ver, banner, tc.want)
		}
	}
}

func TestGetDaemonVersionsCoversAllProtocolCategoriesSafely(t *testing.T) {
	deps := engineProbeDeps{
		goos: "linux",
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/proc/sys/kernel/osrelease":
				return []byte("6.8.0-35-generic\n"), nil
			case "/sys/module/wireguard/version":
				return []byte("1.0.0\n"), nil
			case "/sys/module/amneziawg/version":
				return []byte("1.0.0\n"), nil
			default:
				return nil, os.ErrNotExist
			}
		},
		statPath: func(path string) (os.FileInfo, error) {
			if path == "/dev/net/tun" {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
		moduleAvail: func(name string) bool {
			return name == "wireguard" || name == "amneziawg" || name == "ip_gre" || name == "l2tp_ppp"
		},
		moduleLoaded: func(name string) bool {
			return name == "wireguard" || name == "ip_gre"
		},
		lookPath: func(name string) (string, error) {
			switch name {
			case "wg", "ip", "openvpn", "xl2tpd", "pptpd", "ocserv", "accel-pppd", "charon", "sing-box", "telemt", "amneziawg-go":
				return "/usr/sbin/" + name, nil
			default:
				return "", os.ErrNotExist
			}
		},
		runVersionCmd: func(binPath string, args []string) (string, error) {
			base := filepath.Base(binPath)
			switch base {
			case "sing-box":
				return "sing-box version 1.14.4", nil
			case "telemt":
				return "telemt 3.4.23", nil
			case "amneziawg-go":
				return "amneziawg-go 3.1.20261116", nil
			case "openvpn":
				return "OpenVPN 2.6.23 x86_64", errors.New("exit status 1")
			case "ocserv":
				return "ocserv 1.3.0", nil
			case "xl2tpd":
				if len(args) > 0 && args[0] == "-v" {
					return "xl2tpd version:  xl2tpd-1.3.20", errors.New("exit status 1")
				}
				return "", errors.New("exit status 1")
			case "pptpd":
				return "pptpd v1.4.0", errors.New("exit status 1")
			case "accel-pppd":
				return "accel-ppp 1.12.0", nil
			case "charon":
				return "strongSwan 5.9.14", nil
			case "wg":
				return "wireguard-tools v1.0.20210914", nil
			case "ip":
				return "ip utility, iproute2-6.1.0", nil
			default:
				return "", os.ErrNotExist
			}
		},
	}

	var svc CoreService
	engines := svc.collectDaemonVersions(deps)
	byID := map[string]ProtocolEngineInfo{}
	for _, e := range engines {
		byID[e.ID] = e
	}

	expectedIDs := []string{
		"xray", "hysteria2", "mtproto", "awg",
		"ssh", "wgc", "gre",
		"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2",
	}
	for _, id := range expectedIDs {
		e, ok := byID[id]
		if !ok {
			t.Fatalf("GetDaemonVersions missing engine %q", id)
		}
		if e.Category == "" || e.EngineName == "" || e.Protocols == "" {
			t.Errorf("engine %s missing required metadata: %+v", id, e)
		}
	}

	if byID["xray"].Category != EngineCategoryUserspace || !byID["xray"].CustomPatched {
		t.Errorf("xray engine metadata incorrect: %+v", byID["xray"])
	}
	if byID["ssh"].Category != EngineCategoryInProcessKernel || !byID["ssh"].Available {
		t.Errorf("ssh engine should be available in-process: %+v", byID["ssh"])
	}
	if byID["openvpn"].Category != EngineCategoryDaemon || byID["openvpn"].Version != "2.6.23" {
		t.Errorf("openvpn engine version mismatch: %+v", byID["openvpn"])
	}
	if byID["l2tp"].Version != "1.3.20" {
		t.Errorf("l2tp engine version mismatch: %+v", byID["l2tp"])
	}

	// Ensure missing binaries never panic and degrade cleanly.
	missingDeps := deps
	missingDeps.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	missingDeps.moduleAvail = func(string) bool { return false }
	missingDeps.statPath = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	missingEngines := svc.collectDaemonVersions(missingDeps)
	if len(missingEngines) != len(expectedIDs) {
		t.Fatalf("expected all %d entries even when binaries missing, got %d", len(expectedIDs), len(missingEngines))
	}
}
