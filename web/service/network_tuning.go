package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

const (
	// Network tuning profile identifiers.
	NetProfileDefault        = "default"
	NetProfileBBR            = "bbr"
	NetProfileVPNPerformance = "vpn-performance"

	networkTuningSysctlFile  = "/etc/sysctl.d/99-vpn-ui-tuning.conf"
	networkTuningLegacyBBR   = "/etc/sysctl.d/99-vpn-ui-bbr.conf"
	networkTuningModulesFile = "/etc/modules-load.d/vpn-ui-tuning.conf"
	networkTuningLegacyMods  = "/etc/modules-load.d/vpn-ui-bbr.conf"
	networkTuningBackupFile  = "/etc/vpn-ui-network-tuning.backup.json"
)

type tunedSysctlKV struct {
	Key   string
	Value string
}

// vpnPerformanceExtraKeys are the high-BDP and low-latency keys applied in
// "vpn-performance" mode on top of BBR + fq.
var vpnPerformanceExtraKeys = []string{
	"net.core.rmem_max",
	"net.core.wmem_max",
	"net.core.rmem_default",
	"net.core.wmem_default",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
	"net.ipv4.udp_rmem_min",
	"net.ipv4.udp_wmem_min",
	"net.core.netdev_max_backlog",
	"net.core.somaxconn",
	"net.ipv4.tcp_mtu_probing",
	"net.ipv4.tcp_slow_start_after_idle",
	"net.ipv4.tcp_notsent_lowat",
	"net.ipv4.tcp_fastopen",
}

// allManagedTuningKeys lists every sysctl key this service may modify or snapshot.
var allManagedTuningKeys = append([]string{
	"net.core.default_qdisc",
	"net.ipv4.tcp_congestion_control",
}, vpnPerformanceExtraKeys...)

// NetworkTuningStatus reports the live Linux TCP congestion control / qdisc /
// buffer sysctl state, BBR capability (v1/v2/v3), active profile, and container safety.
type NetworkTuningStatus struct {
	Supported            bool     `json:"supported"`
	KernelRelease        string   `json:"kernelRelease"`
	Container            bool     `json:"container"`
	ContainerSystem      string   `json:"containerSystem,omitempty"`
	ReadOnlySysctl       bool     `json:"readOnlySysctl"`
	BBRAvailable         bool     `json:"bbrAvailable"`
	BBRActive            bool     `json:"bbrActive"`
	BBRVariant           string   `json:"bbrVariant,omitempty"` // bbr3 | bbr2 | bbr
	BestBBRVariant       string   `json:"bestBBRVariant,omitempty"`
	CongestionControl    string   `json:"congestionControl"`
	AvailableCongestions []string `json:"availableCongestions"`
	DefaultQdisc         string   `json:"defaultQdisc"`
	ActiveProfile        string   `json:"activeProfile"` // default | bbr | vpn-performance | custom
	PrimaryInterface     string   `json:"primaryInterface,omitempty"`
	PrimaryQdisc         string   `json:"primaryQdisc,omitempty"`
	TunnelInterfaces     []string `json:"tunnelInterfaces,omitempty"`
	RmemMax              string   `json:"rmemMax,omitempty"`
	WmemMax              string   `json:"wmemMax,omitempty"`
	TcpRmem              string   `json:"tcpRmem,omitempty"`
	TcpWmem              string   `json:"tcpWmem,omitempty"`
	NetdevMaxBacklog     string   `json:"netdevMaxBacklog,omitempty"`
	Somaxconn            string   `json:"somaxconn,omitempty"`
	TcpMtuProbing        string   `json:"tcpMtuProbing,omitempty"`
	TcpSlowStartIdle     string   `json:"tcpSlowStartAfterIdle,omitempty"`
	TcpNotsentLowat      string   `json:"tcpNotsentLowat,omitempty"`
	TcpFastopen          string   `json:"tcpFastopen,omitempty"`
	PersistFile          string   `json:"persistFile"`
	PersistPresent       bool     `json:"persistPresent"`
	HasBackup            bool     `json:"hasBackup"`
	Message              string   `json:"message,omitempty"`
}

// NetworkTuningResult summarizes the outcome of Apply or Revert.
type NetworkTuningResult struct {
	Profile  string              `json:"profile"`
	Applied  []string            `json:"applied,omitempty"`
	Warnings []string            `json:"warnings,omitempty"`
	Message  string              `json:"message"`
	Status   NetworkTuningStatus `json:"status"`
}

type networkTuningBackup struct {
	Values map[string]string `json:"values"`
}

// netTuneDeps abstracts OS interactions so every Linux sysctl, modprobe, tc qdisc,
// container guard, and snapshot/revert path can be unit-tested deterministically.
type netTuneDeps struct {
	goos        string
	readFile    func(path string) ([]byte, error)
	writeFile   func(path string, data []byte, perm os.FileMode) error
	removeFile  func(path string) error
	statPath    func(path string) (os.FileInfo, error)
	mkdirAll    func(path string, perm os.FileMode) error
	isWritable  func(path string) bool
	runCmd      func(name string, args ...string) (string, error)
	lookPath    func(name string) (string, error)
	detectVirt  func() VirtInfo
	listNetDevs func() []string
}

var netTuneMu sync.Mutex

func defaultNetTuneDeps() netTuneDeps {
	return netTuneDeps{
		goos:       runtime.GOOS,
		readFile:   os.ReadFile,
		writeFile:  os.WriteFile,
		removeFile: os.Remove,
		statPath:   os.Stat,
		mkdirAll:   os.MkdirAll,
		isWritable: isProcSysctlWritable,
		runCmd: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).CombinedOutput()
			return string(out), err
		},
		lookPath:    exec.LookPath,
		detectVirt:  DetectVirtualization,
		listNetDevs: listLinuxNetDevices,
	}
}

func isProcSysctlWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		// On modern Linux containers /proc/sys entries may appear read-only even for root.
		return !errors.Is(err, os.ErrPermission) && !isEROFS(err)
	}
	_ = f.Close()
	return true
}

func isEROFS(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "read-only file system") || strings.Contains(low, "erofs")
}

func listLinuxNetDevices() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := strings.TrimSpace(e.Name())
		if name != "" && name != "lo" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// NetworkTuningService inspects and manages Linux BBR + VPN network stack tuning.
type NetworkTuningService struct{}

// GetStatus returns the current Linux TCP congestion control, BBR variant, qdisc,
// buffer sysctls, active tuning profile, and container writability status.
func (s *NetworkTuningService) GetStatus() NetworkTuningStatus {
	return getNetworkTuningStatusWith(defaultNetTuneDeps())
}

// ApplyProfile applies one of "default", "bbr", or "vpn-performance" to the host
// network stack, persisting configuration via /etc/sysctl.d/99-vpn-ui-tuning.conf
// and applying immediate tc fq / fq_codel qdiscs where available.
func (s *NetworkTuningService) ApplyProfile(profile string) (NetworkTuningResult, error) {
	return applyNetworkTuningWith(profile, defaultNetTuneDeps())
}

// Revert restores sysctls saved before the first vpn-ui network tuning change and
// removes managed sysctl/module persistence drop-ins.
func (s *NetworkTuningService) Revert() (NetworkTuningResult, error) {
	return revertNetworkTuningWith(defaultNetTuneDeps())
}

// NormalizeNetworkTuningProfile maps aliases such as "enable"/"on"/"high"/"off"
// onto canonical profile names ("default", "bbr", "vpn-performance").
func NormalizeNetworkTuningProfile(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "status":
		return "", nil
	case "default", "disabled", "disable", "off", "none", "cubic":
		return NetProfileDefault, nil
	case "bbr", "standard", "bbr-standard", "enable", "enabled", "on":
		return NetProfileBBR, nil
	case "vpn-performance", "vpn", "performance", "high", "turbo", "low-latency":
		return NetProfileVPNPerformance, nil
	default:
		return "", fmt.Errorf("unknown network tuning profile %q (valid: default, bbr, vpn-performance)", raw)
	}
}

func sysctlKeyToProcPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(strings.TrimSpace(key), ".", "/")
}

func readSysctlValue(deps netTuneDeps, key string) string {
	if raw, err := deps.readFile(sysctlKeyToProcPath(key)); err == nil {
		// Normalize whitespace (e.g. tab-separated tcp_rmem) to single spaces.
		return strings.Join(strings.Fields(string(raw)), " ")
	}
	if _, err := deps.lookPath("sysctl"); err == nil {
		if out, cerr := deps.runCmd("sysctl", "-n", key); cerr == nil {
			return strings.Join(strings.Fields(out), " ")
		}
	}
	return ""
}

func selectBestBBRVariant(avail []string) (best string) {
	has := map[string]bool{}
	for _, a := range avail {
		has[strings.ToLower(strings.TrimSpace(a))] = true
	}
	for _, candidate := range []string{"bbr3", "bbr2", "bbr"} {
		if has[candidate] {
			return candidate
		}
	}
	return ""
}

func isBBRAlgorithm(cc string) bool {
	low := strings.ToLower(strings.TrimSpace(cc))
	return low == "bbr" || low == "bbr2" || low == "bbr3"
}

func getNetworkTuningStatusWith(deps netTuneDeps) NetworkTuningStatus {
	virt := VirtInfo{}
	if deps.detectVirt != nil {
		virt = deps.detectVirt()
	}

	st := NetworkTuningStatus{
		Supported:       deps.goos == "linux",
		KernelRelease:   readTuningKernelRelease(deps),
		Container:       virt.Kind == "container",
		ContainerSystem: virt.System,
		PersistFile:     networkTuningSysctlFile,
	}
	if !st.Supported {
		st.ActiveProfile = NetProfileDefault
		st.Message = "Linux BBR network stack tuning is only available on Linux hosts"
		return st
	}

	availRaw := readSysctlValue(deps, "net.ipv4.tcp_available_congestion_control")
	if availRaw != "" {
		st.AvailableCongestions = strings.Fields(availRaw)
	}
	st.CongestionControl = readSysctlValue(deps, "net.ipv4.tcp_congestion_control")
	st.DefaultQdisc = readSysctlValue(deps, "net.core.default_qdisc")
	st.BestBBRVariant = selectBestBBRVariant(st.AvailableCongestions)
	st.BBRAvailable = st.BestBBRVariant != ""

	// Fallback check: tcp_bbr module may be loadable even before modprobe runs.
	if !st.BBRAvailable && deps.runCmd != nil {
		if _, err := deps.runCmd("modprobe", "-nq", "tcp_bbr"); err == nil {
			st.BBRAvailable = true
			st.BestBBRVariant = "bbr"
		}
	}

	if isBBRAlgorithm(st.CongestionControl) {
		st.BBRActive = true
		st.BBRVariant = strings.ToLower(strings.TrimSpace(st.CongestionControl))
	}

	if deps.statPath != nil {
		if _, err := deps.statPath(sysctlKeyToProcPath("net.ipv4.tcp_congestion_control")); err == nil && deps.isWritable != nil {
			st.ReadOnlySysctl = !deps.isWritable(sysctlKeyToProcPath("net.ipv4.tcp_congestion_control"))
		}
		if _, err := deps.statPath(networkTuningSysctlFile); err == nil {
			st.PersistPresent = true
		}
		if _, err := deps.statPath(networkTuningBackupFile); err == nil {
			st.HasBackup = true
		}
	}

	st.RmemMax = readSysctlValue(deps, "net.core.rmem_max")
	st.WmemMax = readSysctlValue(deps, "net.core.wmem_max")
	st.TcpRmem = readSysctlValue(deps, "net.ipv4.tcp_rmem")
	st.TcpWmem = readSysctlValue(deps, "net.ipv4.tcp_wmem")
	st.NetdevMaxBacklog = readSysctlValue(deps, "net.core.netdev_max_backlog")
	st.Somaxconn = readSysctlValue(deps, "net.core.somaxconn")
	st.TcpMtuProbing = readSysctlValue(deps, "net.ipv4.tcp_mtu_probing")
	st.TcpSlowStartIdle = readSysctlValue(deps, "net.ipv4.tcp_slow_start_after_idle")
	st.TcpNotsentLowat = readSysctlValue(deps, "net.ipv4.tcp_notsent_lowat")
	st.TcpFastopen = readSysctlValue(deps, "net.ipv4.tcp_fastopen")

	st.PrimaryInterface = detectPrimaryEgressIfaceWith(deps)
	if st.PrimaryInterface != "" {
		st.PrimaryQdisc = readInterfaceQdiscWith(deps, st.PrimaryInterface)
	}
	if deps.listNetDevs != nil {
		for _, dev := range deps.listNetDevs() {
			if isVPNTunnelInterface(dev) {
				st.TunnelInterfaces = append(st.TunnelInterfaces, dev)
			}
		}
	}

	st.ActiveProfile = detectActiveTuningProfile(st)
	if st.ReadOnlySysctl {
		label := "host/container"
		if st.ContainerSystem != "" {
			label = st.ContainerSystem + " container"
		}
		st.Message = fmt.Sprintf("/proc/sys/net/ipv4/tcp_congestion_control is read-only on this %s", label)
	}
	return st
}

func readTuningKernelRelease(deps netTuneDeps) string {
	if raw, err := deps.readFile("/proc/sys/kernel/osrelease"); err == nil {
		if s := strings.TrimSpace(string(raw)); s != "" {
			return s
		}
	}
	return deps.goos
}

func detectActiveTuningProfile(st NetworkTuningStatus) string {
	if !st.BBRActive {
		return NetProfileDefault
	}
	if st.DefaultQdisc == "fq" && st.RmemMax == "33554432" && st.WmemMax == "33554432" && st.TcpSlowStartIdle == "0" {
		return NetProfileVPNPerformance
	}
	return NetProfileBBR
}

func applyNetworkTuningWith(rawProfile string, deps netTuneDeps) (NetworkTuningResult, error) {
	netTuneMu.Lock()
	defer netTuneMu.Unlock()

	profile, err := NormalizeNetworkTuningProfile(rawProfile)
	if err != nil {
		return NetworkTuningResult{}, err
	}
	if profile == "" {
		profile = NetProfileBBR
	}

	res := NetworkTuningResult{Profile: profile}
	if deps.goos != "linux" {
		res.Status = getNetworkTuningStatusWith(deps)
		return res, errors.New("network stack tuning is supported on Linux hosts only")
	}
	if _, err := deps.lookPath("sysctl"); err != nil {
		res.Status = getNetworkTuningStatusWith(deps)
		return res, errors.New("'sysctl' command not found in PATH")
	}
	ccPath := sysctlKeyToProcPath("net.ipv4.tcp_congestion_control")
	if deps.statPath != nil && deps.isWritable != nil {
		if _, err := deps.statPath(ccPath); err == nil && !deps.isWritable(ccPath) {
			st := getNetworkTuningStatusWith(deps)
			res.Status = st
			return res, errors.New(firstNonEmptyString(st.Message, "/proc/sys/net/ipv4/tcp_congestion_control is read-only inside this container"))
		}
	}

	if profile == NetProfileDefault {
		return disableOrRevertNetworkTuningWith(deps, false)
	}

	// Ensure tcp_bbr is loaded before checking tcp_available_congestion_control.
	_, _ = deps.runCmd("modprobe", "tcp_bbr")

	availRaw := readSysctlValue(deps, "net.ipv4.tcp_available_congestion_control")
	avail := strings.Fields(availRaw)
	bbrAlgo := selectBestBBRVariant(avail)
	if bbrAlgo == "" {
		res.Status = getNetworkTuningStatusWith(deps)
		return res, fmt.Errorf("BBR congestion control is unavailable on kernel %s (available: %s)",
			readTuningKernelRelease(deps), firstNonEmptyString(availRaw, "none"))
	}

	// Snapshot original pre-tuning sysctls before making changes.
	snapshotBackupIfAbsent(deps)

	// Build desired sysctl settings in dependency order (default_qdisc BEFORE tcp_congestion_control).
	pairs := []tunedSysctlKV{
		{Key: "net.core.default_qdisc", Value: "fq"},
		{Key: "net.ipv4.tcp_congestion_control", Value: bbrAlgo},
	}
	if profile == NetProfileVPNPerformance {
		pairs = append(pairs, vpnPerformanceSysctls()...)
	}

	requiredKeys := map[string]bool{
		"net.core.default_qdisc":          true,
		"net.ipv4.tcp_congestion_control": true,
	}

	// If downgrading from vpn-performance to standard bbr, restore non-BBR buffer keys
	// first if a pre-tuning backup exists so huge buffer overrides are not left behind.
	if profile == NetProfileBBR {
		if bkp, ok := loadNetworkTuningBackup(deps); ok {
			for _, k := range vpnPerformanceExtraKeys {
				if prevVal, exists := bkp.Values[k]; exists && prevVal != "" {
					if _, err := deps.runCmd("sysctl", "-w", k+"="+prevVal); err != nil {
						res.Warnings = append(res.Warnings, fmt.Sprintf("could not restore %s=%s: %v", k, prevVal, err))
					}
				}
			}
		}
	}

	var activePairs []tunedSysctlKV
	for _, kv := range pairs {
		if out, err := deps.runCmd("sysctl", "-w", kv.Key+"="+kv.Value); err != nil {
			if requiredKeys[kv.Key] {
				res.Status = getNetworkTuningStatusWith(deps)
				return res, fmt.Errorf("failed to apply %s=%s: %w (%s)", kv.Key, kv.Value, err, strings.TrimSpace(out))
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("skipped optional sysctl %s=%s (%v)", kv.Key, kv.Value, err))
			continue
		}
		activePairs = append(activePairs, kv)
		res.Applied = append(res.Applied, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
	}

	if err := persistNetworkTuningFiles(deps, profile, activePairs); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("could not persist sysctl config: %v", err))
	}

	// Apply live queueing discipline via tc without waiting for a reboot.
	applyLiveQueueDisciplines(deps, profile, &res)

	res.Status = getNetworkTuningStatusWith(deps)
	if !res.Status.BBRActive {
		return res, fmt.Errorf("sysctl completed but congestion control reported %q instead of %q", res.Status.CongestionControl, bbrAlgo)
	}
	if profile == NetProfileVPNPerformance {
		res.Message = fmt.Sprintf("VPN High-Throughput + Low-Latency profile active (%s + fq on %s)",
			res.Status.CongestionControl, firstNonEmptyString(res.Status.PrimaryInterface, "default"))
	} else {
		res.Message = fmt.Sprintf("Standard BBR enabled (%s + %s)", res.Status.CongestionControl, res.Status.DefaultQdisc)
	}
	return res, nil
}

func vpnPerformanceSysctls() []tunedSysctlKV {
	return []tunedSysctlKV{
		{Key: "net.core.rmem_max", Value: "33554432"},
		{Key: "net.core.wmem_max", Value: "33554432"},
		{Key: "net.core.rmem_default", Value: "1048576"},
		{Key: "net.core.wmem_default", Value: "1048576"},
		{Key: "net.ipv4.tcp_rmem", Value: "4096 131072 33554432"},
		{Key: "net.ipv4.tcp_wmem", Value: "4096 65536 33554432"},
		{Key: "net.ipv4.udp_rmem_min", Value: "16384"},
		{Key: "net.ipv4.udp_wmem_min", Value: "16384"},
		{Key: "net.core.netdev_max_backlog", Value: "16384"},
		{Key: "net.core.somaxconn", Value: "8192"},
		{Key: "net.ipv4.tcp_mtu_probing", Value: "1"},
		{Key: "net.ipv4.tcp_slow_start_after_idle", Value: "0"},
		{Key: "net.ipv4.tcp_notsent_lowat", Value: "16384"},
		{Key: "net.ipv4.tcp_fastopen", Value: "3"},
	}
}

func persistNetworkTuningFiles(deps netTuneDeps, profile string, pairs []tunedSysctlKV) error {
	cleanupLegacyBBRSysctlFiles(deps)
	var b strings.Builder
	b.WriteString("# Managed by vpn-ui (network & BBR tuning profile: " + profile + ")\n")
	for _, kv := range pairs {
		b.WriteString(kv.Key + " = " + kv.Value + "\n")
	}

	if deps.statPath != nil {
		if st, err := deps.statPath("/etc/sysctl.d"); err == nil && st.IsDir() {
			if err := deps.writeFile(networkTuningSysctlFile, []byte(b.String()), 0o644); err != nil {
				return err
			}
		} else if _, err := deps.statPath("/etc/sysctl.conf"); err == nil {
			stripManagedSysctlKeysFromFile(deps, "/etc/sysctl.conf")
			existing, _ := deps.readFile("/etc/sysctl.conf")
			content := string(existing)
			if len(content) > 0 && !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			content += b.String()
			if err := deps.writeFile("/etc/sysctl.conf", []byte(content), 0o644); err != nil {
				return err
			}
		}
	}

	if deps.statPath != nil {
		if st, err := deps.statPath("/etc/modules-load.d"); err == nil && st.IsDir() {
			if _, err := deps.runCmd("modprobe", "-n", "tcp_bbr"); err == nil {
				_ = deps.writeFile(networkTuningModulesFile, []byte("tcp_bbr\n"), 0o644)
			}
		}
	}
	return nil
}

func applyLiveQueueDisciplines(deps netTuneDeps, profile string, res *NetworkTuningResult) {
	if _, err := deps.lookPath("tc"); err != nil {
		res.Warnings = append(res.Warnings, "tc (iproute2) not found; live interface qdisc swap skipped until next reboot")
		return
	}
	primary := detectPrimaryEgressIfaceWith(deps)
	if primary != "" {
		if out, err := deps.runCmd("tc", "qdisc", "replace", "dev", primary, "root", "fq"); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("tc qdisc replace dev %s root fq failed: %s", primary, strings.TrimSpace(out)))
		} else {
			res.Applied = append(res.Applied, "tc qdisc root fq on "+primary)
		}
	}
	if profile == NetProfileVPNPerformance && deps.listNetDevs != nil {
		for _, dev := range deps.listNetDevs() {
			if dev == primary || !isVPNTunnelInterface(dev) {
				continue
			}
			if _, err := deps.runCmd("tc", "qdisc", "replace", "dev", dev, "root", "fq_codel"); err == nil {
				res.Applied = append(res.Applied, "tc qdisc root fq_codel on "+dev)
			}
		}
	}
}

func revertNetworkTuningWith(deps netTuneDeps) (NetworkTuningResult, error) {
	netTuneMu.Lock()
	defer netTuneMu.Unlock()
	if deps.goos != "linux" {
		return NetworkTuningResult{Profile: NetProfileDefault, Status: getNetworkTuningStatusWith(deps)},
			errors.New("network stack tuning is supported on Linux hosts only")
	}
	if _, err := deps.lookPath("sysctl"); err != nil {
		return NetworkTuningResult{Profile: NetProfileDefault, Status: getNetworkTuningStatusWith(deps)},
			errors.New("'sysctl' command not found in PATH")
	}
	return disableOrRevertNetworkTuningWith(deps, true)
}

func disableOrRevertNetworkTuningWith(deps netTuneDeps, removeBackup bool) (NetworkTuningResult, error) {
	res := NetworkTuningResult{Profile: NetProfileDefault}

	cleanupAllNetworkTuningFiles(deps)

	if bkp, ok := loadNetworkTuningBackup(deps); ok {
		// Restore default_qdisc before tcp_congestion_control, then any buffer keys.
		orderedKeys := make([]string, 0, len(allManagedTuningKeys))
		orderedKeys = append(orderedKeys, allManagedTuningKeys...)
		for _, key := range orderedKeys {
			prevVal, exists := bkp.Values[key]
			if !exists || prevVal == "" {
				continue
			}
			if key == "net.ipv4.tcp_congestion_control" && isBBRAlgorithm(prevVal) {
				// Disable always turns off BBR even if BBR was already on before snapshot;
				// explicit Revert restores the exact snapshotted congestion control only if removeBackup is true?
				// Even on explicit Disable ("default"), the operator asked to turn BBR off.
				if !removeBackup {
					continue
				}
			}
			if out, err := deps.runCmd("sysctl", "-w", key+"="+prevVal); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("could not restore %s=%s (%s)", key, prevVal, strings.TrimSpace(out)))
			} else {
				res.Applied = append(res.Applied, fmt.Sprintf("%s=%s", key, prevVal))
			}
		}
		if removeBackup && deps.removeFile != nil {
			_ = deps.removeFile(networkTuningBackupFile)
		}
	}

	// Guarantee congestion control leaves BBR when switching to default or when backup was absent/also BBR.
	curCC := readSysctlValue(deps, "net.ipv4.tcp_congestion_control")
	if !removeBackup || curCC == "" || isBBRAlgorithm(curCC) {
		avail := strings.Fields(readSysctlValue(deps, "net.ipv4.tcp_available_congestion_control"))
		fallbackCC := selectFallbackNonBBRCongestion(avail)
		if _, err := deps.runCmd("sysctl", "-w", "net.core.default_qdisc=fq_codel"); err != nil {
			_, _ = deps.runCmd("sysctl", "-w", "net.core.default_qdisc=pfifo_fast")
		}
		if out, err := deps.runCmd("sysctl", "-w", "net.ipv4.tcp_congestion_control="+fallbackCC); err != nil {
			res.Status = getNetworkTuningStatusWith(deps)
			return res, fmt.Errorf("failed to revert congestion control to %s: %w (%s)", fallbackCC, err, strings.TrimSpace(out))
		}
		res.Applied = append(res.Applied, "net.ipv4.tcp_congestion_control="+fallbackCC)
	}

	if _, err := deps.lookPath("tc"); err == nil {
		if primary := detectPrimaryEgressIfaceWith(deps); primary != "" {
			if _, err := deps.runCmd("tc", "qdisc", "replace", "dev", primary, "root", "fq_codel"); err == nil {
				res.Applied = append(res.Applied, "tc qdisc root fq_codel on "+primary)
			}
		}
	}

	if removeBackup && deps.removeFile != nil {
		_ = deps.removeFile(networkTuningBackupFile)
	}

	res.Status = getNetworkTuningStatusWith(deps)
	if res.Status.BBRActive && !removeBackup {
		return res, fmt.Errorf("BBR remained active (%s); check custom files under /etc/sysctl.d/", res.Status.CongestionControl)
	}
	res.Message = fmt.Sprintf("Network stack set to %s (congestion=%s, qdisc=%s)",
		res.Profile, res.Status.CongestionControl, res.Status.DefaultQdisc)
	return res, nil
}

func selectFallbackNonBBRCongestion(avail []string) string {
	hasCubic := false
	hasReno := false
	for _, a := range avail {
		switch strings.ToLower(strings.TrimSpace(a)) {
		case "cubic":
			hasCubic = true
		case "reno":
			hasReno = true
		}
	}
	if hasCubic {
		return "cubic"
	}
	if hasReno {
		return "reno"
	}
	for _, a := range avail {
		if !isBBRAlgorithm(a) && strings.TrimSpace(a) != "" {
			return strings.TrimSpace(a)
		}
	}
	return "cubic"
}

func snapshotBackupIfAbsent(deps netTuneDeps) {
	if deps.statPath == nil || deps.writeFile == nil {
		return
	}
	if _, err := deps.statPath(networkTuningBackupFile); err == nil {
		return
	}
	bkp := networkTuningBackup{Values: make(map[string]string, len(allManagedTuningKeys))}
	for _, k := range allManagedTuningKeys {
		if v := readSysctlValue(deps, k); v != "" {
			bkp.Values[k] = v
		}
	}
	raw, err := json.MarshalIndent(bkp, "", "  ")
	if err != nil {
		return
	}
	if deps.mkdirAll != nil {
		_ = deps.mkdirAll(filepath.Dir(networkTuningBackupFile), 0o755)
	}
	_ = deps.writeFile(networkTuningBackupFile, raw, 0o600)
}

func loadNetworkTuningBackup(deps netTuneDeps) (networkTuningBackup, bool) {
	if deps.readFile == nil {
		return networkTuningBackup{}, false
	}
	raw, err := deps.readFile(networkTuningBackupFile)
	if err != nil {
		return networkTuningBackup{}, false
	}
	var bkp networkTuningBackup
	if json.Unmarshal(raw, &bkp) != nil || len(bkp.Values) == 0 {
		return networkTuningBackup{}, false
	}
	return bkp, true
}

func cleanupLegacyBBRSysctlFiles(deps netTuneDeps) {
	if deps.removeFile != nil {
		_ = deps.removeFile(networkTuningLegacyBBR)
		_ = deps.removeFile(networkTuningLegacyMods)
	}
	stripManagedSysctlKeysFromFile(deps, "/etc/sysctl.conf")
	stripManagedSysctlKeysFromFile(deps, "/etc/sysctl.d/99-sysctl.conf")
}

func cleanupAllNetworkTuningFiles(deps netTuneDeps) {
	if deps.removeFile != nil {
		_ = deps.removeFile(networkTuningSysctlFile)
		_ = deps.removeFile(networkTuningModulesFile)
	}
	cleanupLegacyBBRSysctlFiles(deps)
}

func stripManagedSysctlKeysFromFile(deps netTuneDeps, path string) {
	if deps.readFile == nil || deps.writeFile == nil {
		return
	}
	raw, err := deps.readFile(path)
	if err != nil {
		return
	}
	managedSet := make(map[string]bool, len(allManagedTuningKeys))
	for _, k := range allManagedTuningKeys {
		managedSet[k] = true
	}
	lines := strings.Split(string(raw), "\n")
	var kept []string
	changed := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "# Managed by vpn-ui (BBR congestion control)") ||
			strings.HasPrefix(trim, "# Managed by vpn-ui (network & BBR tuning profile:") {
			changed = true
			continue
		}
		if eq := strings.IndexByte(trim, '='); eq > 0 && !strings.HasPrefix(trim, "#") {
			k := strings.TrimSpace(trim[:eq])
			if managedSet[k] {
				changed = true
				continue
			}
		}
		kept = append(kept, line)
	}
	if changed {
		_ = deps.writeFile(path, []byte(strings.Join(kept, "\n")), 0o644)
	}
}

func detectPrimaryEgressIfaceWith(deps netTuneDeps) string {
	// Prefer kernel routing table via `ip -4 route show default` when iproute2 exists.
	if _, err := deps.lookPath("ip"); err == nil {
		if out, cerr := deps.runCmd("ip", "-4", "route", "show", "default"); cerr == nil {
			for _, line := range strings.Split(out, "\n") {
				fields := strings.Fields(line)
				for i := 0; i+1 < len(fields); i++ {
					if fields[i] == "dev" && fields[i+1] != "" && fields[i+1] != "lo" {
						return fields[i+1]
					}
				}
			}
		}
	}
	// Fallback: parse /proc/net/route for destination 00000000.
	if raw, err := deps.readFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(raw), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "00000000" && fields[0] != "lo" {
				return fields[0]
			}
		}
	}
	return ""
}

func readInterfaceQdiscWith(deps netTuneDeps, iface string) string {
	if iface == "" {
		return ""
	}
	if _, err := deps.lookPath("tc"); err != nil {
		return ""
	}
	out, err := deps.runCmd("tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		// e.g.: qdisc fq 8001: root refcnt 2 ...
		for i, f := range fields {
			if f == "root" && len(fields) >= 2 && fields[0] == "qdisc" {
				_ = i
				return fields[1]
			}
		}
	}
	return ""
}

func isVPNTunnelInterface(name string) bool {
	for _, prefix := range []string{"wg", "awg", "tun", "tap", "ppp", "gre"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
