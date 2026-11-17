package service

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeFileInfo struct {
	name string
	dir  bool
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0o755 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.dir }
func (f fakeFileInfo) Sys() any           { return nil }

func newMockNetTuneState(availCC, curCC, curQdisc string) (*netTuneDeps, map[string][]byte, *[]string) {
	files := map[string][]byte{
		"/proc/sys/kernel/osrelease":                       []byte("6.8.0-35-generic\n"),
		"/proc/sys/net/ipv4/tcp_available_congestion_control": []byte(availCC + "\n"),
		"/proc/sys/net/ipv4/tcp_congestion_control":        []byte(curCC + "\n"),
		"/proc/sys/net/core/default_qdisc":                 []byte(curQdisc + "\n"),
		"/proc/sys/net/core/rmem_max":                      []byte("212992\n"),
		"/proc/sys/net/core/wmem_max":                      []byte("212992\n"),
		"/proc/sys/net/core/rmem_default":                  []byte("212992\n"),
		"/proc/sys/net/core/wmem_default":                  []byte("212992\n"),
		"/proc/sys/net/ipv4/tcp_rmem":                      []byte("4096\t131072\t6291456\n"),
		"/proc/sys/net/ipv4/tcp_wmem":                      []byte("4096\t16384\t4194304\n"),
		"/proc/sys/net/ipv4/udp_rmem_min":                  []byte("4096\n"),
		"/proc/sys/net/ipv4/udp_wmem_min":                  []byte("4096\n"),
		"/proc/sys/net/core/netdev_max_backlog":            []byte("1000\n"),
		"/proc/sys/net/core/somaxconn":                     []byte("4096\n"),
		"/proc/sys/net/ipv4/tcp_mtu_probing":               []byte("0\n"),
		"/proc/sys/net/ipv4/tcp_slow_start_after_idle":     []byte("1\n"),
		"/proc/sys/net/ipv4/tcp_notsent_lowat":             []byte("4294967295\n"),
		"/proc/sys/net/ipv4/tcp_fastopen":                  []byte("1\n"),
		"/proc/net/route":                                  []byte("Iface\tDestination\tGateway\tFlags\nens3\t00000000\t0101010A\t0003\n"),
		networkTuningLegacyBBR:                             []byte("net.ipv4.tcp_congestion_control = bbr\n"),
	}
	dirs := map[string]bool{
		"/etc/sysctl.d":       true,
		"/etc/modules-load.d": true,
	}
	qdiscByIface := map[string]string{
		"ens3": "fq_codel",
		"wg0":  "noqueue",
	}
	var cmds []string

	deps := &netTuneDeps{
		goos: "linux",
		readFile: func(path string) ([]byte, error) {
			b, ok := files[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return append([]byte(nil), b...), nil
		},
		writeFile: func(path string, data []byte, perm os.FileMode) error {
			files[path] = append([]byte(nil), data...)
			return nil
		},
		removeFile: func(path string) error {
			delete(files, path)
			return nil
		},
		statPath: func(path string) (os.FileInfo, error) {
			if dirs[path] {
				return fakeFileInfo{name: path, dir: true}, nil
			}
			if _, ok := files[path]; ok {
				return fakeFileInfo{name: path, dir: false}, nil
			}
			return nil, os.ErrNotExist
		},
		mkdirAll:   func(string, os.FileMode) error { return nil },
		isWritable: func(string) bool { return true },
		lookPath: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		detectVirt: func() VirtInfo { return VirtInfo{} },
		listNetDevs: func() []string {
			return []string{"ens3", "wg0"}
		},
		runCmd: func(name string, args ...string) (string, error) {
			line := name + " " + strings.Join(args, " ")
			cmds = append(cmds, line)
			switch name {
			case "sysctl":
				if len(args) == 2 && args[0] == "-w" {
					k, v, ok := strings.Cut(args[1], "=")
					if ok {
						files[sysctlKeyToProcPath(k)] = []byte(v + "\n")
					}
					return args[1], nil
				}
			case "tc":
				if len(args) >= 6 && args[0] == "qdisc" && args[1] == "replace" && args[2] == "dev" && args[4] == "root" {
					qdiscByIface[args[3]] = args[5]
					return "", nil
				}
				if len(args) == 4 && args[0] == "qdisc" && args[1] == "show" && args[2] == "dev" {
					qd := qdiscByIface[args[3]]
					if qd != "" {
						return "qdisc " + qd + " 8001: root refcnt 2\n", nil
					}
				}
			case "ip":
				return "default via 10.1.1.1 dev ens3 proto dhcp\n", nil
			case "modprobe":
				return "", nil
			}
			return "", nil
		},
	}
	return deps, files, &cmds
}

func TestSelectBestBBRVariantAndProfileNormalization(t *testing.T) {
	if got := selectBestBBRVariant([]string{"reno", "cubic", "bbr", "bbr3", "bbr2"}); got != "bbr3" {
		t.Fatalf("expected bbr3 priority, got %q", got)
	}
	if got := selectBestBBRVariant([]string{"cubic", "bbr2", "bbr"}); got != "bbr2" {
		t.Fatalf("expected bbr2 priority, got %q", got)
	}
	if got := selectBestBBRVariant([]string{"cubic", "bbr"}); got != "bbr" {
		t.Fatalf("expected bbr priority, got %q", got)
	}
	if p, err := NormalizeNetworkTuningProfile("perf"); err != nil || p != NetProfileVPNPerformance {
		t.Fatalf("NormalizeNetworkTuningProfile(perf) = (%q, %v)", p, err)
	}
	if _, err := NormalizeNetworkTuningProfile("bogus"); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestNetworkTuningApplyProfilesAndRevert(t *testing.T) {
	deps, files, cmds := newMockNetTuneState("reno cubic bbr bbr3", "cubic", "fq_codel")

	// 1. Apply vpn-performance: selects best BBR (bbr3), writes backup, sets buffers & tc qdiscs.
	res, err := applyNetworkTuningWith(NetProfileVPNPerformance, *deps)
	if err != nil {
		t.Fatalf("apply vpn-performance failed: %v", err)
	}
	if !res.Status.BBRActive || res.Status.BBRVariant != "bbr3" || res.Status.ActiveProfile != NetProfileVPNPerformance {
		t.Fatalf("unexpected status after vpn-performance: %+v", res.Status)
	}
	if res.Status.PrimaryInterface != "ens3" || res.Status.PrimaryQdisc != "fq" {
		t.Fatalf("expected tc qdisc fq on ens3, got iface=%q qdisc=%q", res.Status.PrimaryInterface, res.Status.PrimaryQdisc)
	}
	if _, legacyExists := files[networkTuningLegacyBBR]; legacyExists {
		t.Fatal("expected legacy 99-vpn-ui-bbr.conf to be cleaned up")
	}
	if !res.Status.HasBackup || !res.Status.PersistPresent {
		t.Fatalf("expected backup and persist files present, got HasBackup=%v PersistPresent=%v", res.Status.HasBackup, res.Status.PersistPresent)
	}
	cmdLog := strings.Join(*cmds, "\n")
	if !strings.Contains(cmdLog, "tc qdisc replace dev ens3 root fq") ||
		!strings.Contains(cmdLog, "tc qdisc replace dev wg0 root fq_codel") {
		t.Fatalf("expected tc qdisc application for ens3 and wg0, cmds:\n%s", cmdLog)
	}

	// 2. Downgrade to standard bbr restores non-BBR socket buffers cleanly.
	resBBR, err := applyNetworkTuningWith(NetProfileBBR, *deps)
	if err != nil {
		t.Fatalf("apply standard bbr failed: %v", err)
	}
	if resBBR.Status.ActiveProfile != NetProfileBBR || resBBR.Status.RmemMax != "212992" {
		t.Fatalf("expected standard bbr profile with restored rmem_max=212992, got %+v", resBBR.Status)
	}

	// 3. Revert restores original cubic + fq_codel and removes persist & backup files.
	rev, err := revertNetworkTuningWith(*deps)
	if err != nil {
		t.Fatalf("revert failed: %v", err)
	}
	if rev.Status.BBRActive || rev.Status.CongestionControl != "cubic" || rev.Status.DefaultQdisc != "fq_codel" {
		t.Fatalf("revert did not restore cubic/fq_codel: %+v", rev.Status)
	}
	if rev.Status.HasBackup || rev.Status.PersistPresent {
		t.Fatalf("revert left backup or persist file behind: %+v", rev.Status)
	}
}

func TestNetworkTuningGuardsReadOnlyContainerAndMissingBBR(t *testing.T) {
	deps, _, _ := newMockNetTuneState("reno cubic bbr", "cubic", "pfifo_fast")
	deps.isWritable = func(string) bool { return false }
	deps.detectVirt = func() VirtInfo { return VirtInfo{Virtualized: true, Kind: "container", System: "LXC"} }

	st := getNetworkTuningStatusWith(*deps)
	if !st.ReadOnlySysctl || !st.Container || !strings.Contains(st.Message, "LXC") {
		t.Fatalf("expected read-only container status warning, got %+v", st)
	}
	if _, err := applyNetworkTuningWith(NetProfileBBR, *deps); err == nil {
		t.Fatal("expected error applying BBR in read-only container")
	}

	deps2, _, _ := newMockNetTuneState("reno cubic", "cubic", "fq_codel")
	deps2.runCmd = func(name string, args ...string) (string, error) {
		if name == "modprobe" {
			return "modprobe: FATAL: Module tcp_bbr not found", errors.New("exit status 1")
		}
		return "", nil
	}
	if _, err := applyNetworkTuningWith(NetProfileBBR, *deps2); err == nil {
		t.Fatal("expected error when tcp_bbr unavailable in kernel")
	}
}
