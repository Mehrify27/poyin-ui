package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
)

const (
	SpeedLimitEngineInCoreXray = "in-core-xray"
	SpeedLimitEngineKernelTC   = "kernel-tc-fallback"
)

// ActiveSpeedLimitEngine reports how VPN/user speed limits are enforced right
// now: via the patched Xray binary (XRAY_SPEEDLIMIT_FILE + DisableSplice) or
// via the Linux kernel tc HTB/police fallback when an unpatched official
// XTLS/Xray-core binary is active.
func ActiveSpeedLimitEngine() string {
	caps := DetectActiveXrayCapabilities()
	if caps.SupportsSpeedLimit {
		return SpeedLimitEngineInCoreXray
	}
	return SpeedLimitEngineKernelTC
}

type tcTargetRule struct {
	Iface   string
	CIDR    string
	DownBps int64
	UpBps   int64
}

type tcPlan struct {
	Interfaces []string
	Rules      []tcTargetRule
	Commands   [][]string
}

var (
	tcRuntimeMu    sync.Mutex
	tcManagedDevs  = map[string]struct{}{}
	tcLastPlanHash string
)

func vpnInterfaceFromCIDR(cidr string) (string, bool) {
	raw := strings.TrimSpace(cidr)
	if raw == "" {
		return "", false
	}
	ipStr := raw
	if ip, _, err := net.ParseCIDR(raw); err == nil && ip != nil {
		ipStr = ip.String()
	} else if parsed := net.ParseIP(raw); parsed != nil {
		ipStr = parsed.String()
	} else {
		return "", false
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return "", false
	}
	out, err := exec.Command("ip", "-o", "route", "get", ipStr).Output()
	if err != nil {
		return "", false
	}
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			dev := strings.TrimSpace(fields[i+1])
			if isAllowedVpnTCInterface(dev) {
				return dev, true
			}
		}
	}
	return "", false
}

// isAllowedVpnTCInterface guarantees kernel tc speedlimit fallback ONLY touches
// panel VPN/tunnel interfaces (ppp*, tun*, tap*, wg-*, awg-*, gre-*, ocserv*)
// and NEVER modifies primary WAN NICs (eth*, ens*, enp*, bond*, lo) or their BBR qdiscs.
func isAllowedVpnTCInterface(iface string) bool {
	dev := strings.ToLower(strings.TrimSpace(iface))
	if dev == "" {
		return false
	}
	for _, prefix := range []string{"ppp", "tun", "tap", "wg", "awg", "gre", "ocserv", "vpns"} {
		if strings.HasPrefix(dev, prefix) {
			return true
		}
	}
	return false
}

func buildTCSpeedLimitPlan(
	users []speedLimitUser,
	resolveIface func(cidr string) (string, bool),
	staleIfaces []string,
) tcPlan {
	var plan tcPlan
	ifaceSet := map[string]struct{}{}
	rulesByKey := map[string]tcTargetRule{}

	for _, u := range users {
		if (u.DownBps <= 0 && u.UpBps <= 0) || len(u.IPs) == 0 {
			continue
		}
		for _, cidr := range u.IPs {
			iface, ok := resolveIface(cidr)
			if !ok || !isAllowedVpnTCInterface(iface) {
				continue
			}
			ifaceSet[iface] = struct{}{}
			key := iface + "|" + cidr
			existing, seen := rulesByKey[key]
			if !seen {
				rulesByKey[key] = tcTargetRule{
					Iface:   iface,
					CIDR:    cidr,
					DownBps: u.DownBps,
					UpBps:   u.UpBps,
				}
			} else {
				existing.DownBps = minNonZero(existing.DownBps, u.DownBps)
				existing.UpBps = minNonZero(existing.UpBps, u.UpBps)
				rulesByKey[key] = existing
			}
		}
	}

	rules := make([]tcTargetRule, 0, len(rulesByKey))
	for _, r := range rulesByKey {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Iface != rules[j].Iface {
			return rules[i].Iface < rules[j].Iface
		}
		return rules[i].CIDR < rules[j].CIDR
	})
	plan.Rules = rules

	// Clear stale managed interfaces first, and rebuild active ones deterministically.
	staleSorted := append([]string(nil), staleIfaces...)
	sort.Strings(staleSorted)
	for _, dev := range staleSorted {
		if _, active := ifaceSet[dev]; !active && isAllowedVpnTCInterface(dev) {
			plan.Commands = append(plan.Commands,
				[]string{"qdisc", "del", "dev", dev, "root"},
				[]string{"qdisc", "del", "dev", dev, "ingress"},
			)
		}
	}

	activeIfaces := make([]string, 0, len(ifaceSet))
	for dev := range ifaceSet {
		activeIfaces = append(activeIfaces, dev)
	}
	sort.Strings(activeIfaces)
	plan.Interfaces = activeIfaces

	for _, dev := range activeIfaces {
		plan.Commands = append(plan.Commands,
			[]string{"qdisc", "del", "dev", dev, "root"},
			[]string{"qdisc", "del", "dev", dev, "ingress"},
			[]string{"qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "9999"},
			[]string{"class", "replace", "dev", dev, "parent", "1:", "classid", "1:9999", "htb", "rate", "10gbit"},
			[]string{"qdisc", "replace", "dev", dev, "handle", "ffff:", "ingress"},
		)
	}

	classIDByIface := map[string]int{}
	for _, r := range rules {
		classNum := classIDByIface[r.Iface] + 10
		if classNum > 9998 {
			continue
		}
		classIDByIface[r.Iface] = classNum
		cid := fmt.Sprintf("1:%d", classNum)
		proto := "ip"
		matchProto := "ip"
		srcKey, dstKey := "src", "dst"
		if strings.Contains(r.CIDR, ":") {
			proto = "ipv6"
			matchProto = "ip6"
			srcKey, dstKey = "src", "dst"
		}
		if r.DownBps > 0 {
			rateBits := fmt.Sprintf("%dbit", r.DownBps*8)
			plan.Commands = append(plan.Commands,
				[]string{"class", "replace", "dev", r.Iface, "parent", "1:", "classid", cid, "htb", "rate", rateBits, "ceil", rateBits},
				[]string{"filter", "add", "dev", r.Iface, "protocol", proto, "parent", "1:", "prio", "10", "u32", "match", matchProto, dstKey, r.CIDR, "flowid", cid},
			)
		}
		if r.UpBps > 0 {
			rateBits := fmt.Sprintf("%dbit", r.UpBps*8)
			burst := r.UpBps / 4
			if burst < 16384 {
				burst = 16384
			}
			plan.Commands = append(plan.Commands,
				[]string{"filter", "add", "dev", r.Iface, "parent", "ffff:", "protocol", proto, "prio", "10", "u32", "match", matchProto, srcKey, r.CIDR, "police", "rate", rateBits, "burst", fmt.Sprintf("%d", burst), "drop", "flowid", ":1"},
			)
		}
	}

	return plan
}

func tcPlanDigest(cmds [][]string) string {
	h := sha256.New()
	for _, c := range cmds {
		h.Write([]byte(strings.Join(c, " ")))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func applyKernelTCSpeedLimitsIfNeeded(users []speedLimitUser) {
	if runtime.GOOS != "linux" {
		return
	}
	caps := DetectActiveXrayCapabilities()
	tcRuntimeMu.Lock()
	defer tcRuntimeMu.Unlock()

	stale := make([]string, 0, len(tcManagedDevs))
	for dev := range tcManagedDevs {
		stale = append(stale, dev)
	}

	// Patched Xray enforces per-user speed limits natively inside the core dispatcher.
	// When switched back from unpatched official Xray, clear any kernel tc qdiscs we installed.
	if caps.SupportsSpeedLimit {
		if len(stale) > 0 {
			if _, err := exec.LookPath("tc"); err == nil {
				for _, dev := range stale {
					_ = exec.Command("tc", "qdisc", "del", "dev", dev, "root").Run()
					_ = exec.Command("tc", "qdisc", "del", "dev", dev, "ingress").Run()
				}
			}
			tcManagedDevs = map[string]struct{}{}
			tcLastPlanHash = ""
		}
		return
	}

	plan := buildTCSpeedLimitPlan(users, vpnInterfaceFromCIDR, stale)
	hash := tcPlanDigest(plan.Commands)
	if hash == tcLastPlanHash {
		return
	}
	if _, err := exec.LookPath("tc"); err != nil {
		tcLastPlanHash = hash
		return
	}

	for _, args := range plan.Commands {
		// `tc qdisc del` returns non-zero when no qdisc exists on the interface yet; that is expected.
		if len(args) >= 2 && args[1] == "del" {
			_ = exec.Command("tc", args...).Run()
			continue
		}
		_ = exec.Command("tc", args...).Run()
	}

	tcManagedDevs = make(map[string]struct{}, len(plan.Interfaces))
	for _, dev := range plan.Interfaces {
		tcManagedDevs[dev] = struct{}{}
	}
	tcLastPlanHash = hash
}
