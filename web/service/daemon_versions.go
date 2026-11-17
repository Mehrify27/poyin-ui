package service

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/corebundle"
)

const (
	// EngineCategoryUserspace identifies standalone userspace sidecar engines (Category A).
	EngineCategoryUserspace = "userspace-sidecar"
	// EngineCategoryInProcessKernel identifies in-process Go / kernel-netlink engines (Category B).
	EngineCategoryInProcessKernel = "in-process-kernel"
	// EngineCategoryDaemon identifies C/musl daemon engines (Category C).
	EngineCategoryDaemon = "daemon"
)

// ProtocolEngineInfo reports accurate runtime version, binary/kernel provenance,
// and patch status for every protocol engine managed by vpn-ui across Categories A, B, and C.
type ProtocolEngineInfo struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Category      string   `json:"category"`
	EngineName    string   `json:"engineName"`
	Protocols     string   `json:"protocols"`
	Available     bool     `json:"available"`
	Source        string   `json:"source"` // bundled | custom-override | host-path | in-process | kernel | hybrid | missing
	Version       string   `json:"version,omitempty"`
	Banner        string   `json:"banner,omitempty"`
	BinaryPath    string   `json:"binaryPath,omitempty"`
	UpdateTarget  string   `json:"updateTarget,omitempty"`
	CustomPatched bool     `json:"customPatched,omitempty"`
	PatchSet      []string `json:"patchSet,omitempty"`
	KernelModule  string   `json:"kernelModule,omitempty"`
	KernelLoaded  bool     `json:"kernelLoaded,omitempty"`
	KernelRelease string   `json:"kernelRelease,omitempty"`
	HelperTools   []string `json:"helperTools,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

var (
	// engineSemverRe extracts concise semantic versions from arbitrary CLI stdout/stderr banners.
	engineSemverRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?)`)
)

// engineProbeOps allows unit tests to simulate Linux kernel/binary state cleanly on any OS.
type engineProbeDeps struct {
	runVersionCmd func(binPath string, args []string) (string, error)
	lookPath      func(name string) (string, error)
	readFile      func(path string) ([]byte, error)
	statPath      func(path string) (os.FileInfo, error)
	moduleAvail   func(name string) bool
	moduleLoaded  func(name string) bool
	goos          string
}

func defaultEngineProbeDeps() engineProbeDeps {
	return engineProbeDeps{
		runVersionCmd: runBoundedVersionCmd,
		lookPath:      exec.LookPath,
		readFile:      os.ReadFile,
		statPath:      os.Stat,
		moduleAvail:   moduleAvailable,
		moduleLoaded:  moduleLoaded,
		goos:          runtime.GOOS,
	}
}

func runBoundedVersionCmd(binPath string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, args...).CombinedOutput()
	return string(out), err
}

func daemonVersionArgSets(name string) [][]string {
	low := strings.ToLower(filepath.Base(strings.TrimSpace(name)))
	switch {
	case low == "sing-box":
		return [][]string{{"version"}, {"--version"}}
	case low == "xray" || strings.HasPrefix(low, "xray-"):
		return [][]string{{"-version"}, {"version"}}
	case low == "xl2tpd":
		return [][]string{{"--version"}, {"-v"}}
	case low == "pptpd" || low == "pptp":
		return [][]string{{"-v"}, {"--version"}}
	case low == "accel-pppd":
		return [][]string{{"--version"}, {"-V"}}
	case low == "ip":
		return [][]string{{"-V"}, {"-Version"}}
	default:
		return [][]string{{"--version"}}
	}
}

func resolveDaemonExecutablePath(name string) string {
	return resolveDaemonExecutablePathWith(name, exec.LookPath)
}

func resolveDaemonExecutablePathWith(name string, lookPath func(string) (string, error)) string {
	if p := backend.DaemonPath(name); p != "" {
		return p
	}
	if p := backend.AccelBinPath(name); p != "" {
		return p
	}
	if p := backend.StrongswanBinPath(name); p != "" {
		return p
	}
	if lookPath != nil {
		if p, err := lookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// probeDaemonBinaryVersion runs the appropriate version flags for name at binPath,
// returning a short semantic version token and clean first-line banner. Output is
// consumed even when a tool (such as openvpn, xl2tpd, or pptpd) exits non-zero.
func probeDaemonBinaryVersion(name, binPath string) (version, banner string) {
	return probeDaemonBinaryVersionWith(name, binPath, defaultEngineProbeDeps())
}

func probeDaemonBinaryVersionWith(name, binPath string, deps engineProbeDeps) (version, banner string) {
	if strings.TrimSpace(binPath) == "" || deps.runVersionCmd == nil {
		return "", ""
	}
	for _, args := range daemonVersionArgSets(name) {
		raw, err := deps.runVersionCmd(binPath, args)
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" && err != nil {
			continue
		}
		tok, line := extractDaemonBannerAndVersion(trimmed)
		if tok != "" || line != "" {
			return tok, line
		}
	}
	return "", ""
}

func extractDaemonBannerAndVersion(raw string) (token, firstLine string) {
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		if firstLine == "" {
			firstLine = line
		}
		if m := engineSemverRe.FindStringSubmatch(line); len(m) >= 2 {
			return m[1], firstLine
		}
		if v := daemonVersionRe.FindString(line); v != "" {
			return v, firstLine
		}
	}
	return "", firstLine
}

// GetDaemonVersions collects live, accurate engine versions across all 12 VPN/proxy
// protocol families + Xray-core, categorized cleanly into:
//   - Category A: userspace sidecar / embedded engines (xray, sing-box, telemt, amneziawg-go)
//   - Category B: in-process Go & kernel-netlink engines (ssh, wireguard-c, gre)
//   - Category C: C/musl system daemons (l2tp, pptp, openvpn, openconnect, sstp, ikev2)
func (s *CoreService) GetDaemonVersions() []ProtocolEngineInfo {
	return s.collectDaemonVersions(defaultEngineProbeDeps())
}

func (s *CoreService) collectDaemonVersions(deps engineProbeDeps) []ProtocolEngineInfo {
	kernelRel := readKernelRelease(deps)
	invByTarget := map[string]CoreBinaryInfo{}
	for _, item := range s.GetCoreBinaryInventory() {
		invByTarget[item.Core] = item
	}

	probeBinEngine := func(binName, updateTarget string) (avail bool, src, binPath, ver, banner string) {
		if updateTarget != "" {
			if inv, ok := invByTarget[updateTarget]; ok {
				if inv.ActivePath != "" {
					avail = true
					src = inv.Source
					binPath = inv.ActivePath
					ver = inv.InstalledVersion
					banner = inv.Version
					if ver == "" && banner == "" {
						ver, banner = probeDaemonBinaryVersionWith(binName, binPath, deps)
					}
					return avail, src, binPath, ver, banner
				}
				return false, "missing", "", "", ""
			}
		}
		p := resolveDaemonExecutablePathWith(binName, deps.lookPath)
		if p == "" {
			return false, "missing", "", "", ""
		}
		avail = true
		binPath = p
		if bp := backend.DaemonPath(binName); bp != "" && filepath.Clean(bp) == filepath.Clean(p) {
			src = "bundled"
		} else if backend.AccelBinPath(binName) == p || backend.StrongswanBinPath(binName) == p {
			src = "bundled"
		} else {
			src = "host-path"
		}
		ver, banner = probeDaemonBinaryVersionWith(binName, p, deps)
		return avail, src, binPath, ver, banner
	}

	probeToolVer := func(tool string) string {
		p := resolveDaemonExecutablePathWith(tool, deps.lookPath)
		if p == "" {
			return ""
		}
		v, b := probeDaemonBinaryVersionWith(tool, p, deps)
		if v != "" {
			return tool + " " + v
		}
		if b != "" {
			return tool + " (" + b + ")"
		}
		return tool + " (" + p + ")"
	}

	// Category A: Xray, sing-box, telemt, amneziawg
	xrayInv := invByTarget["xray"]
	xrayAvail := xrayInv.ActivePath != ""
	xrayVer := xrayInv.InstalledVersion
	xrayBanner := xrayInv.Version
	if xrayAvail && xrayVer == "" {
		xrayVer, xrayBanner = probeDaemonBinaryVersionWith("xray", xrayInv.ActivePath, deps)
	}

	sbAvail, sbSrc, sbPath, sbVer, sbBanner := probeBinEngine("sing-box", "sing-box")
	tmAvail, tmSrc, tmPath, tmVer, tmBanner := probeBinEngine("telemt", "telemt")

	// AmneziaWG: hybrid kernel amneziawg + userspace amneziawg-go / built-in Go AWG 2.0
	awgModLoaded := deps.moduleAvail("amneziawg")
	_, awgSideSrc, awgSidePath, awgSideVer, awgSideBanner := probeBinEngine("amneziawg-go", "amneziawg-go")
	awgKVer := ""
	if raw, err := deps.readFile("/sys/module/amneziawg/version"); err == nil {
		awgKVer = strings.TrimSpace(string(raw))
	}
	_, tunErr := deps.statPath("/dev/net/tun")
	awgAvail := awgModLoaded || awgSidePath != "" || tunErr == nil
	awgSrc := "in-process"
	awgVer := config.GetVersion()
	if awgSidePath != "" && awgSideVer != "" {
		awgVer = awgSideVer
		awgSrc = awgSideSrc
	} else if awgKVer != "" {
		awgVer = awgKVer
		awgSrc = "kernel"
	}
	var awgDetails []string
	if awgModLoaded {
		if awgKVer != "" {
			awgDetails = append(awgDetails, "kernel module amneziawg "+awgKVer)
		} else {
			awgDetails = append(awgDetails, "kernel module loaded")
		}
	}
	if awgSidePath != "" {
		awgDetails = append(awgDetails, "sidecar amneziawg-go "+firstNonEmptyString(awgSideVer, "present"))
	} else if tunErr == nil {
		awgDetails = append(awgDetails, "built-in Go AWG 2.0 (/dev/net/tun)")
	}

	// Category B: In-process Go & Kernel-Netlink (SSH, WireGuard-C, GRE)
	wgModLoaded := deps.moduleAvail("wireguard")
	wgKVer := ""
	if raw, err := deps.readFile("/sys/module/wireguard/version"); err == nil {
		wgKVer = strings.TrimSpace(string(raw))
	}
	var wgHelpers []string
	if h := probeToolVer("wg"); h != "" {
		wgHelpers = append(wgHelpers, h)
	}
	if h := probeToolVer("ip"); h != "" {
		wgHelpers = append(wgHelpers, h)
	}

	greAvail := deps.moduleAvail("ip_gre")
	if !greAvail {
		if _, err := deps.statPath("/sys/class/net/gre0"); err == nil {
			greAvail = true
		}
	}
	var greHelpers []string
	if h := probeToolVer("ip"); h != "" {
		greHelpers = append(greHelpers, h)
	}
	if deps.moduleAvail("fou") {
		greHelpers = append(greHelpers, "kernel fou module available")
	}

	// Category C: C/musl Daemon Engines (L2TP, PPTP, OpenVPN, OpenConnect, SSTP, IKEv2)
	l2tpAvail, l2tpSrc, l2tpPath, l2tpVer, l2tpBanner := probeBinEngine("xl2tpd", "xl2tpd")
	pptpAvail, pptpSrc, pptpPath, pptpVer, pptpBanner := probeBinEngine("pptpd", "")
	ovpnAvail, ovpnSrc, ovpnPath, ovpnVer, ovpnBanner := probeBinEngine("openvpn", "openvpn")
	ocAvail, ocSrc, ocPath, ocVer, ocBanner := probeBinEngine("ocserv", "ocserv")
	sstpAvail, sstpSrc, sstpPath, sstpVer, sstpBanner := probeBinEngine("accel-pppd", "")
	if !sstpAvail && backend.HasAccelBundle() {
		sstpAvail, sstpSrc = true, "bundled"
	}
	ikeAvail, ikeSrc, ikePath, ikeVer, ikeBanner := probeBinEngine("charon", "")
	if !ikeAvail && backend.HasStrongswanBundle() {
		ikeAvail, ikeSrc = true, "bundled"
	}

	var pptpHelpers []string
	if h := probeToolVer("pppd"); h != "" {
		pptpHelpers = append(pptpHelpers, h)
	}
	if h := probeToolVer("pptp"); h != "" {
		pptpHelpers = append(pptpHelpers, h)
	}
	var sstpHelpers []string
	if h := probeToolVer("sstpc"); h != "" {
		sstpHelpers = append(sstpHelpers, h)
	}
	var ocHelpers []string
	if h := probeToolVer("openconnect"); h != "" {
		ocHelpers = append(ocHelpers, h)
	}
	var l2tpHelpers []string
	if ikeAvail {
		l2tpHelpers = append(l2tpHelpers, "ipsec charon "+firstNonEmptyString(ikeVer, "present"))
	} else if maj, min, ok := libreswanVersion(); ok {
		l2tpHelpers = append(l2tpHelpers, "libreswan "+formatMajorMinor(maj, min))
	}

	engines := []ProtocolEngineInfo{
		{
			ID:            "xray",
			Title:         "Xray-core",
			Category:      EngineCategoryUserspace,
			EngineName:    corebundle.XrayBinaryName(),
			Protocols:     "VLESS, VMess, Trojan, Shadowsocks, WireGuard, TUIC, Hysteria, AnyTLS",
			Available:     xrayAvail,
			Source:        firstNonEmptyString(xrayInv.Source, "missing"),
			Version:       xrayVer,
			Banner:        xrayBanner,
			BinaryPath:    xrayInv.ActivePath,
			UpdateTarget:  "xray",
			CustomPatched: xrayInv.CustomPatched,
			PatchSet:      xrayInv.PatchSet,
			Detail:        xrayInv.UpstreamWarning,
		},
		{
			ID:           "hysteria2",
			Title:        "Hysteria 2",
			Category:     EngineCategoryUserspace,
			EngineName:   "sing-box",
			Protocols:    "Hysteria 2 (QUIC)",
			Available:    sbAvail,
			Source:       sbSrc,
			Version:      sbVer,
			Banner:       sbBanner,
			BinaryPath:   sbPath,
			UpdateTarget: "sing-box",
		},
		{
			ID:            "mtproto",
			Title:         "MTProto Proxy",
			Category:      EngineCategoryUserspace,
			EngineName:    "telemt",
			Protocols:     "Telegram MTProto (FakeTLS / DD / Direct)",
			Available:     tmAvail,
			Source:        tmSrc,
			Version:       tmVer,
			Banner:        tmBanner,
			BinaryPath:    tmPath,
			UpdateTarget:  "telemt",
			CustomPatched: tmInvPatched(invByTarget["telemt"]),
			PatchSet:      tmInvPatchSet(invByTarget["telemt"]),
		},
		{
			ID:            "awg",
			Title:         "AmneziaWG",
			Category:      EngineCategoryUserspace,
			EngineName:    "amneziawg + amneziawg-go",
			Protocols:     "AmneziaWG 1.0 / 1.5 / 2.0",
			Available:     awgAvail,
			Source:        awgSrc,
			Version:       awgVer,
			Banner:        awgSideBanner,
			BinaryPath:    awgSidePath,
			UpdateTarget:  "amneziawg-go",
			KernelModule:  amneziawgModule,
			KernelLoaded:  awgModLoaded,
			KernelRelease: kernelRel,
			Detail:        strings.Join(awgDetails, "; "),
		},
		{
			ID:         "ssh",
			Title:      "SSH Tunnel + UDPGW",
			Category:   EngineCategoryInProcessKernel,
			EngineName: "Built-in Go SSH + in-process udpgw",
			Protocols:  "SSH direct-tcpip, SOCKS5/UDP via udpgw:7300",
			Available:  true,
			Source:     "in-process",
			Version:    config.GetVersion(),
			Banner:     "golang.org/x/crypto/ssh (AEAD + Curve25519/ML-KEM + pooled udpgw)",
			Detail:     "In-process Go gateway with live credential & user-limit enforcement",
		},
		{
			ID:            "wgc",
			Title:         "WireGuard (Kernel)",
			Category:      EngineCategoryInProcessKernel,
			EngineName:    "wireguard kernel + wgctrl netlink",
			Protocols:     "WireGuard (kernel L3)",
			Available:     wgModLoaded,
			Source:        kernelSourceLabel(wgModLoaded),
			Version:       firstNonEmptyString(wgKVer, kernelRel),
			KernelModule:  wgKernelModule,
			KernelLoaded:  wgModLoaded,
			KernelRelease: kernelRel,
			HelperTools:   wgHelpers,
		},
		{
			ID:            "gre",
			Title:         "GRE / FOU Tunnel",
			Category:      EngineCategoryInProcessKernel,
			EngineName:    "ip_gre kernel + netlink",
			Protocols:     "GRE, GRE-over-IPsec, FOU UDP encap",
			Available:     greAvail,
			Source:        kernelSourceLabel(greAvail),
			Version:       firstNonEmptyString(kernelRel, "kernel"),
			KernelModule:  greModule,
			KernelLoaded:  greAvail,
			KernelRelease: kernelRel,
			HelperTools:   greHelpers,
		},
		{
			ID:           "l2tp",
			Title:        "L2TP / IPsec",
			Category:     EngineCategoryDaemon,
			EngineName:   "xl2tpd + IPsec",
			Protocols:    "L2TP RAW, L2TP/IPsec PSK",
			Available:    l2tpAvail,
			Source:       l2tpSrc,
			Version:      l2tpVer,
			Banner:       l2tpBanner,
			BinaryPath:   l2tpPath,
			UpdateTarget: "xl2tpd",
			KernelModule: "l2tp_ppp",
			KernelLoaded: deps.moduleAvail("l2tp_ppp"),
			HelperTools:  l2tpHelpers,
		},
		{
			ID:           "pptp",
			Title:        "PPTP",
			Category:     EngineCategoryDaemon,
			EngineName:   "pptpd + pppd",
			Protocols:    "PPTP (MPPE)",
			Available:    pptpAvail,
			Source:       pptpSrc,
			Version:      pptpVer,
			Banner:       pptpBanner,
			BinaryPath:   pptpPath,
			KernelModule: "ppp_mppe",
			KernelLoaded: deps.moduleAvail("ppp_mppe"),
			HelperTools:  pptpHelpers,
		},
		{
			ID:           "openvpn",
			Title:        "OpenVPN",
			Category:     EngineCategoryDaemon,
			EngineName:   "openvpn",
			Protocols:    "OpenVPN TCP / UDP (LZO / LZ4 / tls-crypt)",
			Available:    ovpnAvail,
			Source:       ovpnSrc,
			Version:      ovpnVer,
			Banner:       ovpnBanner,
			BinaryPath:   ovpnPath,
			UpdateTarget: "openvpn",
		},
		{
			ID:           "openconnect",
			Title:        "OpenConnect (AnyConnect)",
			Category:     EngineCategoryDaemon,
			EngineName:   "ocserv",
			Protocols:    "Cisco AnyConnect TLS / DTLS + RADIUS",
			Available:    ocAvail,
			Source:       ocSrc,
			Version:      ocVer,
			Banner:       ocBanner,
			BinaryPath:   ocPath,
			UpdateTarget: "ocserv",
			HelperTools:  ocHelpers,
		},
		{
			ID:          "sstp",
			Title:       "SSTP",
			Category:    EngineCategoryDaemon,
			EngineName:  "accel-pppd + sstpc",
			Protocols:   "Microsoft SSTP (TLS + PPP/RADIUS)",
			Available:   sstpAvail,
			Source:      sstpSrc,
			Version:     sstpVer,
			Banner:      sstpBanner,
			BinaryPath:  sstpPath,
			HelperTools: sstpHelpers,
		},
		{
			ID:         "ikev2",
			Title:      "IKEv2 / IPsec",
			Category:   EngineCategoryDaemon,
			EngineName: "strongSwan charon",
			Protocols:  "IKEv2 EAP-MSCHAPv2 / EAP-TLS / PSK (MODP1024 compat)",
			Available:  ikeAvail,
			Source:     ikeSrc,
			Version:    ikeVer,
			Banner:     ikeBanner,
			BinaryPath: ikePath,
		},
	}
	return engines
}

func readKernelRelease(deps engineProbeDeps) string {
	if raw, err := deps.readFile("/proc/sys/kernel/osrelease"); err == nil {
		if rel := strings.TrimSpace(string(raw)); rel != "" {
			return rel
		}
	}
	return deps.goos
}

func kernelSourceLabel(avail bool) string {
	if avail {
		return "kernel"
	}
	return "missing"
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func formatMajorMinor(maj, min int) string {
	return strconv.Itoa(maj) + "." + strconv.Itoa(min)
}

func tmInvPatched(inv CoreBinaryInfo) bool {
	return inv.CustomPatched || inv.Source == "bundled"
}

func tmInvPatchSet(inv CoreBinaryInfo) []string {
	if len(inv.PatchSet) > 0 {
		return inv.PatchSet
	}
	return []string{"[access.user_modes]", "socks_user_from_account", "[general.modes] hot-reload"}
}
