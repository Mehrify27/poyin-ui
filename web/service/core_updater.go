package service

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/corebundle"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/binutil"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

const (
	maxCoreArtifactBytes  = 512 << 20 // 512 MiB cap against truncated/malicious archives
	maxValidatedJSONBytes = 32 << 20  // 32 MiB cap (XTLS/Xray-core releases?per_page=100 exceeds 10 MiB)
)

// githubReleaseAPIBase and gitlabReleaseAPIBase can be overridden in unit tests.
var (
	githubReleaseAPIBase = "https://api.github.com"
	gitlabReleaseAPIBase = "https://gitlab.com"
)

const upstreamVersionsCacheTTL = 5 * time.Minute

type cachedUpstreamVersions struct {
	fetchedAt time.Time
	items     []CoreReleaseOption
}

var (
	upstreamCacheMu       sync.Mutex
	upstreamVersionsCache = map[string]cachedUpstreamVersions{}
	shortVersionTokenRe   = regexp.MustCompile(`\bv?\d+\.\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?`)
)

// XrayPatchList enumerates the custom patches baked into vpn-ui's bundled
// Xray-core binary (patches/xray/01..06). Installing an unpatched upstream
// XTLS/Xray-core release disables these features until rolled back.
var XrayPatchList = []string{
	"Shadowsocks per-user cipher fallback",
	"Per-account rate limiter",
	"Per-account IP limit enforcement",
	"CanSpliceCopy=3 speedlimit splice disable",
	"AnyTLS / TUIC / NaiveProxy protocols",
	"Legacy reverse proxy support",
}

// CoreUpdateSpec describes a sidecar core/daemon binary that can be inspected,
// updated independently of vpn-ui, and rolled back atomically.
type CoreUpdateSpec struct {
	Target                  string
	ServiceCore             string
	Protocols               string
	UpstreamProvider        string // "github" | "gitlab"
	GithubRepo              string
	UpstreamURL             string
	UpdateMode              string // "prebuilt" | "source-go" | "custom"
	GoSourcePackage         string
	CustomPatched           bool
	PatchSet                []string
	UpstreamWarning         string
	AllowNonZeroVersionExit bool
	VersionArgs             []string
	ArchiveBinaryNames      []string
	CustomFileFunc          func() string
	BundledPathFunc         func() string
	ActivePathFunc          func() string
}

// CoreBinaryInfo reports active/bundled/override paths and metadata for one
// managed binary.
type CoreBinaryInfo struct {
	Core                        string   `json:"core"`
	ServiceCore                 string   `json:"serviceCore"`
	Protocols                   string   `json:"protocols,omitempty"`
	ActivePath                  string   `json:"activePath"`
	BundledPath                 string   `json:"bundledPath"`
	CustomPath                  string   `json:"customPath"`
	CustomDir                   string   `json:"customDir"`
	Source                      string   `json:"source"` // custom-override | bundled | host-path | missing
	Version                     string   `json:"version"`
	InstalledVersion            string   `json:"installedVersion,omitempty"`
	SHA256                      string   `json:"sha256,omitempty"`
	HasBackup                   bool     `json:"hasBackup"`
	UpstreamRepo                string   `json:"upstreamRepo,omitempty"`
	UpstreamURL                 string   `json:"upstreamUrl,omitempty"`
	UpdateMode                  string   `json:"updateMode"`
	AutoUpdatable               bool     `json:"autoUpdatable"`
	CustomPatched               bool     `json:"customPatched"`
	BinaryMode                  string   `json:"binaryMode,omitempty"`
	SupportsSpeedLimit          bool     `json:"supportsSpeedLimit,omitempty"`
	SupportsNativeForkProtocols bool     `json:"supportsNativeForkProtocols,omitempty"`
	SpeedLimitEngine            string   `json:"speedLimitEngine,omitempty"`
	ForkProtocolEngine          string   `json:"forkProtocolEngine,omitempty"`
	PatchSet                    []string `json:"patchSet,omitempty"`
	UpstreamWarning             string   `json:"upstreamWarning,omitempty"`
}

const (
	BinaryModeBundledPatched        = "bundled-patched"
	BinaryModeCustomPatched         = "custom-patched"
	BinaryModeOfficialXTLSUnpatched = "official-xtls-unpatched"
	BinaryModeMissing               = "missing"
)

// XrayBinaryCapabilities describes which custom vpn-ui patches an Xray binary
// actually supports at runtime (inferred from build markers and override metadata).
type XrayBinaryCapabilities struct {
	BinaryMode                  string `json:"binaryMode"`
	SupportsSpeedLimit          bool   `json:"supportsSpeedLimit"`
	SupportsNativeForkProtocols bool   `json:"supportsNativeForkProtocols"`
}

// CoreReleaseOption describes one upstream version available from the official repository.
type CoreReleaseOption struct {
	Tag         string `json:"tag"`
	Name        string `json:"name,omitempty"`
	Prerelease  bool   `json:"prerelease"`
	Latest      bool   `json:"latest"`
	PublishedAt string `json:"publishedAt,omitempty"`
	URL         string `json:"url,omitempty"`
	AssetName   string `json:"assetName,omitempty"`
	DownloadURL string `json:"downloadUrl,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	TarballURL  string `json:"tarballUrl,omitempty"`
	SourceOnly  bool   `json:"sourceOnly,omitempty"`
}

// CoreUpdateOptions configures an independent sidecar binary update or rollback.
type CoreUpdateOptions struct {
	Target           string
	URL              string
	File             string
	Version          string
	SHA256           string
	AllowUnpatched   bool
	RestartFunc      func(serviceCore string) error
	VerifyHealthFunc func(spec CoreUpdateSpec, destPath string) error
}

// CoreUpdateResult reports the outcome of updating or rolling back one target.
type CoreUpdateResult struct {
	Target          string `json:"target"`
	ServiceCore     string `json:"serviceCore"`
	DestPath        string `json:"destPath"`
	BackupPath      string `json:"backupPath,omitempty"`
	Source          string `json:"source"`
	Version         string `json:"version,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	PreflightTested bool   `json:"preflightTested,omitempty"`
	Restarted       bool   `json:"restarted"`
	RolledBack      bool   `json:"rolledBack"`
	Status          string `json:"status"` // updated | rolled_back | skipped
	Message         string `json:"message"`
}

var managedCoreUpdateSpecs = []CoreUpdateSpec{
	{
		Target:             "xray",
		ServiceCore:        "xray",
		Protocols:          "VLESS, VMess, Trojan, Shadowsocks, WireGuard, AnyTLS, TUIC, NaiveProxy",
		UpstreamProvider:   "github",
		GithubRepo:         "XTLS/Xray-core",
		UpstreamURL:        "https://github.com/XTLS/Xray-core/releases",
		UpdateMode:         "prebuilt",
		CustomPatched:      true,
		PatchSet:           XrayPatchList,
		UpstreamWarning:    "Installing unpatched official XTLS/Xray-core automatically switches AnyTLS, TUIC v5, and NaiveProxy to the bundled sing-box sidecar and VPN speed limits to kernel tc fallback.",
		VersionArgs:        []string{"-version"},
		ArchiveBinaryNames: []string{"xray"},
		CustomFileFunc:     corebundle.XrayBinaryName,
		BundledPathFunc: func() string {
			p := filepath.Join(config.GetBinFolderPath(), corebundle.XrayBinaryName())
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
			return ""
		},
		ActivePathFunc: func() string {
			p := corebundle.ResolveXrayBinaryPath(config.GetBinFolderPath())
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
			return ""
		},
	},
	{
		Target:             "telemt",
		ServiceCore:        "mtproto",
		Protocols:          "MTProto Proxy",
		UpstreamProvider:   "github",
		GithubRepo:         "telemt/telemt",
		UpstreamURL:        "https://github.com/telemt/telemt/releases",
		UpdateMode:         "prebuilt",
		PatchSet:           []string{"[access.user_modes]", "socks_user_from_account", "[general.modes] hot-reload"},
		UpstreamWarning:    "Bundled telemt is built from Sir-MmD/telemt fork with [access.user_modes] per-account mode enforcement.",
		VersionArgs:        []string{"--version"},
		ArchiveBinaryNames: []string{"telemt"},
		CustomFileFunc:     func() string { return "telemt" },
		BundledPathFunc:    func() string { return backend.BundledDaemonPath("telemt") },
		ActivePathFunc:     func() string { return resolveDaemonOrHost("telemt") },
	},
	{
		Target:             "sing-box",
		ServiceCore:        "hysteria2",
		Protocols:          "Hysteria 2, AnyTLS, TUIC v5, NaiveProxy",
		UpstreamProvider:   "github",
		GithubRepo:         "SagerNet/sing-box",
		UpstreamURL:        "https://github.com/SagerNet/sing-box/releases",
		UpdateMode:         "prebuilt",
		VersionArgs:        []string{"version"},
		ArchiveBinaryNames: []string{"sing-box"},
		CustomFileFunc:     func() string { return "sing-box" },
		BundledPathFunc:    func() string { return backend.BundledDaemonPath("sing-box") },
		ActivePathFunc:     func() string { return resolveDaemonOrHost("sing-box") },
	},
	{
		Target:             "amneziawg-go",
		ServiceCore:        "awg",
		Protocols:          "AmneziaWG (AWG 1.0 / 1.5 / 2.0)",
		UpstreamProvider:   "github",
		GithubRepo:         "amnezia-vpn/amneziawg-go",
		UpstreamURL:        "https://github.com/amnezia-vpn/amneziawg-go/tags",
		UpdateMode:         "source-go",
		GoSourcePackage:    ".",
		VersionArgs:        []string{"--version"},
		ArchiveBinaryNames: []string{"amneziawg-go"},
		CustomFileFunc:     func() string { return "amneziawg-go" },
		BundledPathFunc:    func() string { return backend.BundledDaemonPath("amneziawg-go") },
		ActivePathFunc:     func() string { return resolveDaemonOrHost("amneziawg-go") },
	},
	{
		Target:                  "ocserv",
		ServiceCore:             "openconnect",
		Protocols:               "OpenConnect (Cisco AnyConnect)",
		UpstreamProvider:        "gitlab",
		GithubRepo:              "openconnect/ocserv",
		UpstreamURL:             "https://gitlab.com/openconnect/ocserv/-/releases",
		UpdateMode:              "custom",
		AllowNonZeroVersionExit: true,
		VersionArgs:             []string{"--version"},
		ArchiveBinaryNames:      []string{"ocserv"},
		CustomFileFunc:          func() string { return "ocserv" },
		BundledPathFunc:         func() string { return backend.BundledDaemonPath("ocserv") },
		ActivePathFunc:          func() string { return resolveDaemonOrHost("ocserv") },
	},
	{
		Target:                  "openvpn",
		ServiceCore:             "openvpn",
		Protocols:               "OpenVPN (TCP / UDP)",
		UpstreamProvider:        "github",
		GithubRepo:              "OpenVPN/openvpn",
		UpstreamURL:             "https://github.com/OpenVPN/openvpn/releases",
		UpdateMode:              "custom",
		AllowNonZeroVersionExit: true,
		VersionArgs:             []string{"--version"},
		ArchiveBinaryNames:      []string{"openvpn"},
		CustomFileFunc:          func() string { return "openvpn" },
		BundledPathFunc:         func() string { return backend.BundledDaemonPath("openvpn") },
		ActivePathFunc:          func() string { return resolveDaemonOrHost("openvpn") },
	},
	{
		Target:                  "xl2tpd",
		ServiceCore:             "l2tp",
		Protocols:               "L2TP / IPsec",
		UpstreamProvider:        "github",
		GithubRepo:              "xelerance/xl2tpd",
		UpstreamURL:             "https://github.com/xelerance/xl2tpd/releases",
		UpdateMode:              "custom",
		AllowNonZeroVersionExit: true,
		VersionArgs:             []string{"--version"},
		ArchiveBinaryNames:      []string{"xl2tpd"},
		CustomFileFunc:          func() string { return "xl2tpd" },
		BundledPathFunc:         func() string { return backend.BundledDaemonPath("xl2tpd") },
		ActivePathFunc:          func() string { return resolveDaemonOrHost("xl2tpd") },
	},
}

func resolveDaemonOrHost(name string) string {
	if p := backend.DaemonPath(name); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// normalizeCoreUpdateTarget maps CLI/API aliases onto canonical managed core targets.
func normalizeCoreUpdateTarget(target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "xray", "xray-core":
		return "xray"
	case "telemt", "mtproto":
		return "telemt"
	case "sing-box", "singbox", "hysteria2", "hy2":
		return "sing-box"
	case "amneziawg-go", "amneziawg", "awg":
		return "amneziawg-go"
	case "ocserv", "openconnect":
		return "ocserv"
	case "openvpn", "ovpn":
		return "openvpn"
	case "xl2tpd", "l2tp":
		return "xl2tpd"
	case "all":
		return "all"
	default:
		return strings.ToLower(strings.TrimSpace(target))
	}
}

func findCoreUpdateSpec(target string) (CoreUpdateSpec, bool) {
	norm := normalizeCoreUpdateTarget(target)
	for _, s := range managedCoreUpdateSpecs {
		if s.Target == norm {
			return s, true
		}
	}
	return CoreUpdateSpec{}, false
}

// SupportedCoreUpdateTargets returns the valid target names for update-core.
func SupportedCoreUpdateTargets() []string {
	out := make([]string, 0, len(managedCoreUpdateSpecs))
	for _, s := range managedCoreUpdateSpecs {
		out = append(out, s.Target)
	}
	return out
}

type coreOverrideMeta struct {
	CustomPatched  bool   `json:"customPatched"`
	Source         string `json:"source,omitempty"`
	Version        string `json:"version,omitempty"`
	AllowUnpatched bool   `json:"allowUnpatched,omitempty"`
}

func coreMetaPath(destPath string) string {
	return destPath + ".meta.json"
}

func readCoreOverrideMeta(destPath string) (coreOverrideMeta, bool) {
	raw, err := os.ReadFile(coreMetaPath(destPath))
	if err != nil {
		return coreOverrideMeta{}, false
	}
	var m coreOverrideMeta
	if json.Unmarshal(raw, &m) != nil {
		return coreOverrideMeta{}, false
	}
	return m, true
}

func writeCoreOverrideMeta(destPath string, m coreOverrideMeta) {
	raw, err := json.Marshal(m)
	if err != nil {
		return
	}
	_ = os.WriteFile(coreMetaPath(destPath), raw, 0o644)
}

// GetCoreBinaryInventory reports active paths, bundled paths, override status,
// backups, patch metadata, and detected versions for all managed sidecar binaries.
func (s *CoreService) GetCoreBinaryInventory() []CoreBinaryInfo {
	customDir := binutil.CustomBinDir()
	out := make([]CoreBinaryInfo, 0, len(managedCoreUpdateSpecs))
	for _, spec := range managedCoreUpdateSpecs {
		out = append(out, buildCoreBinaryInfo(spec, customDir))
	}
	return out
}

// GetCoreBinaryInfo resolves metadata and installed version for a single core target.
func (s *CoreService) GetCoreBinaryInfo(target string) (CoreBinaryInfo, bool) {
	spec, ok := findCoreUpdateSpec(target)
	if !ok {
		return CoreBinaryInfo{}, false
	}
	return buildCoreBinaryInfo(spec, binutil.CustomBinDir()), true
}

const realXrayBinaryMinBytes = 512 << 10

type cachedXrayCaps struct {
	size    int64
	modUnix int64
	caps    XrayBinaryCapabilities
}

var (
	xrayCapCacheMu sync.Mutex
	xrayCapCache   = map[string]cachedXrayCaps{}
)

func invalidateXrayCapabilitiesCache() {
	xrayCapCacheMu.Lock()
	xrayCapCache = map[string]cachedXrayCaps{}
	xrayCapCacheMu.Unlock()
}

// DetectActiveXrayCapabilities inspects the currently active Xray binary on disk
// and reports whether it carries vpn-ui custom patches (speedlimit sidecar +
// native fork protocols) or is an unpatched official XTLS/Xray-core build.
func DetectActiveXrayCapabilities() XrayBinaryCapabilities {
	binPath := corebundle.ResolveXrayBinaryPath(config.GetBinFolderPath())
	if binPath == "" {
		binPath = xray.GetBinaryPath()
	}
	return DetectXrayCapabilities(binPath)
}

// DetectXrayCapabilities probes an Xray binary at binPath via override metadata
// and embedded binary markers, caching results by path, size, and mtime.
func DetectXrayCapabilities(binPath string) XrayBinaryCapabilities {
	cleanPath := filepath.Clean(strings.TrimSpace(binPath))
	if cleanPath == "" || cleanPath == "." {
		return XrayBinaryCapabilities{BinaryMode: BinaryModeMissing}
	}
	st, err := os.Stat(cleanPath)
	if err != nil || st.IsDir() {
		return XrayBinaryCapabilities{BinaryMode: BinaryModeMissing}
	}
	modUnix := st.ModTime().UnixNano()

	xrayCapCacheMu.Lock()
	if entry, ok := xrayCapCache[cleanPath]; ok && entry.size == st.Size() && entry.modUnix == modUnix {
		xrayCapCacheMu.Unlock()
		return entry.caps
	}
	xrayCapCacheMu.Unlock()

	isBundled := false
	if bp := filepath.Join(config.GetBinFolderPath(), corebundle.XrayBinaryName()); bp != "" && filepath.Clean(bp) == cleanPath {
		isBundled = true
	}

	caps := detectXrayCapabilitiesUncached(cleanPath, st.Size(), isBundled)

	xrayCapCacheMu.Lock()
	xrayCapCache[cleanPath] = cachedXrayCaps{size: st.Size(), modUnix: modUnix, caps: caps}
	xrayCapCacheMu.Unlock()
	return caps
}

func detectXrayCapabilitiesUncached(cleanPath string, size int64, isBundled bool) XrayBinaryCapabilities {
	meta, hasMeta := readCoreOverrideMeta(cleanPath)
	if hasMeta && !meta.CustomPatched {
		return XrayBinaryCapabilities{
			BinaryMode:                  BinaryModeOfficialXTLSUnpatched,
			SupportsSpeedLimit:          false,
			SupportsNativeForkProtocols: false,
		}
	}

	hasSpeedLimit, hasForkProto := scanXrayCapabilityMarkers(cleanPath)
	if hasSpeedLimit || hasForkProto {
		mode := BinaryModeCustomPatched
		if isBundled {
			mode = BinaryModeBundledPatched
		}
		return XrayBinaryCapabilities{
			BinaryMode:                  mode,
			SupportsSpeedLimit:          hasSpeedLimit,
			SupportsNativeForkProtocols: hasForkProto,
		}
	}

	if hasMeta && meta.CustomPatched {
		return XrayBinaryCapabilities{
			BinaryMode:                  BinaryModeCustomPatched,
			SupportsSpeedLimit:          true,
			SupportsNativeForkProtocols: true,
		}
	}

	// A real compiled ELF >= 512 KiB with neither vpn-ui marker is an unpatched
	// upstream XTLS/Xray-core binary (e.g. manually placed on disk). Tiny test
	// fixtures at the bundled path keep the bundled-patched capability profile.
	if size >= realXrayBinaryMinBytes || !isBundled {
		return XrayBinaryCapabilities{
			BinaryMode:                  BinaryModeOfficialXTLSUnpatched,
			SupportsSpeedLimit:          false,
			SupportsNativeForkProtocols: false,
		}
	}
	return XrayBinaryCapabilities{
		BinaryMode:                  BinaryModeBundledPatched,
		SupportsSpeedLimit:          true,
		SupportsNativeForkProtocols: true,
	}
}

func scanXrayCapabilityMarkers(binPath string) (hasSpeedLimit, hasForkProtocols bool) {
	f, err := os.Open(binPath)
	if err != nil {
		return false, false
	}
	defer f.Close()

	speedMarker := []byte("XRAY_SPEEDLIMIT_FILE")
	forkMarker := []byte("xray.proxy.naive.Account")
	anytlsMarker := []byte("xray.proxy.anytls.Account")

	const chunkSize = 64 * 1024
	const overlap = 64
	buf := make([]byte, overlap+chunkSize)
	carry := 0

	for {
		n, rerr := f.Read(buf[carry:])
		total := carry + n
		if total > 0 {
			window := buf[:total]
			if !hasSpeedLimit && bytes.Contains(window, speedMarker) {
				hasSpeedLimit = true
			}
			if !hasForkProtocols && (bytes.Contains(window, forkMarker) || bytes.Contains(window, anytlsMarker)) {
				hasForkProtocols = true
			}
			if hasSpeedLimit && hasForkProtocols {
				return true, true
			}
		}
		if rerr != nil {
			break
		}
		if total >= overlap {
			copy(buf[:overlap], buf[total-overlap:total])
			carry = overlap
		} else {
			carry = total
		}
	}
	return hasSpeedLimit, hasForkProtocols
}

func buildCoreBinaryInfo(spec CoreUpdateSpec, customDir string) CoreBinaryInfo {
	customPath := filepath.Join(customDir, spec.CustomFileFunc())
	bundledPath := spec.BundledPathFunc()
	activePath := spec.ActivePathFunc()

	source := "missing"
	if activePath != "" {
		cleanActive := filepath.Clean(activePath)
		cleanCustom := filepath.Clean(customPath)
		if cleanActive == cleanCustom || strings.HasPrefix(cleanActive, filepath.Clean(customDir)+string(os.PathSeparator)) {
			source = "custom-override"
		} else if bundledPath != "" && cleanActive == filepath.Clean(bundledPath) {
			source = "bundled"
		} else {
			source = "host-path"
		}
	}

	isCustomPatched := spec.CustomPatched
	var caps XrayBinaryCapabilities
	if spec.Target == "xray" {
		caps = DetectXrayCapabilities(activePath)
		isCustomPatched = caps.SupportsSpeedLimit || caps.SupportsNativeForkProtocols
	} else {
		if spec.Target == "telemt" && source == "bundled" {
			isCustomPatched = true
		}
		if source == "custom-override" {
			if meta, ok := readCoreOverrideMeta(customPath); ok {
				isCustomPatched = meta.CustomPatched
			}
		} else if source == "host-path" && spec.CustomPatched {
			isCustomPatched = false
		}
	}

	_, bakErr := os.Stat(customPath + ".bak")
	info := CoreBinaryInfo{
		Core:            spec.Target,
		ServiceCore:     spec.ServiceCore,
		Protocols:       spec.Protocols,
		ActivePath:      activePath,
		BundledPath:     bundledPath,
		CustomPath:      customPath,
		CustomDir:       customDir,
		Source:          source,
		HasBackup:       bakErr == nil,
		UpstreamRepo:    spec.GithubRepo,
		UpstreamURL:     spec.UpstreamURL,
		UpdateMode:      spec.UpdateMode,
		AutoUpdatable:   canAutoUpdateSpec(spec),
		CustomPatched:   isCustomPatched,
		PatchSet:        append([]string(nil), spec.PatchSet...),
		UpstreamWarning: spec.UpstreamWarning,
	}
	if spec.Target == "xray" {
		info.BinaryMode = caps.BinaryMode
		info.SupportsSpeedLimit = caps.SupportsSpeedLimit
		info.SupportsNativeForkProtocols = caps.SupportsNativeForkProtocols
		if caps.SupportsSpeedLimit {
			info.SpeedLimitEngine = SpeedLimitEngineInCoreXray
		} else {
			info.SpeedLimitEngine = SpeedLimitEngineKernelTC
		}
		if ShouldUseSingboxForkEngineForCaps(caps) {
			info.ForkProtocolEngine = "sing-box"
		} else {
			info.ForkProtocolEngine = "xray-patched"
		}
	}
	if activePath != "" {
		tok, banner := probeDaemonBinaryVersion(spec.Target, activePath)
		info.Version = firstNonEmptyString(banner, probeBinaryVersion(activePath, spec.VersionArgs))
		info.InstalledVersion = firstNonEmptyString(tok, extractVersionToken(info.Version))
		if meta, ok := readCoreOverrideMeta(customPath); ok && source == "custom-override" && info.InstalledVersion == "" {
			info.InstalledVersion = meta.Version
		}
		if sum, err := binutil.FileSHA256(activePath); err == nil {
			info.SHA256 = sum
		}
	}
	return info
}

// CanAutoUpdateTarget reports whether target can automatically download (or
// compile when Go is present) and install updates without a manual URL/file.
func CanAutoUpdateTarget(target string) bool {
	spec, ok := findCoreUpdateSpec(target)
	if !ok {
		return false
	}
	return canAutoUpdateSpec(spec)
}

func canAutoUpdateSpec(spec CoreUpdateSpec) bool {
	switch spec.UpdateMode {
	case "prebuilt":
		return spec.GithubRepo != ""
	case "source-go":
		_, err := exec.LookPath("go")
		return err == nil
	default:
		return false
	}
}

func extractVersionToken(raw string) string {
	return strings.TrimSpace(shortVersionTokenRe.FindString(raw))
}

func probeBinaryVersion(binPath string, args []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// UpdateCore installs a new binary into binutil.CustomBinDir() for target (or all
// managed targets), verifies ELF architecture + optional SHA-256, keeps a .bak,
// triggers a targeted restart ONLY of the affected core, and automatically rolls
// back if the restarted core fails health verification.
func (s *CoreService) UpdateCore(opts CoreUpdateOptions) ([]CoreUpdateResult, error) {
	norm := normalizeCoreUpdateTarget(opts.Target)
	if norm == "" {
		return nil, fmt.Errorf("core target is required (%s, or all)", strings.Join(SupportedCoreUpdateTargets(), ", "))
	}

	var specs []CoreUpdateSpec
	if norm == "all" {
		if opts.File != "" || opts.URL != "" {
			return nil, errors.New("--file and --url cannot be combined with target 'all'")
		}
		specs = append(specs, managedCoreUpdateSpecs...)
	} else {
		spec, ok := findCoreUpdateSpec(norm)
		if !ok {
			return nil, fmt.Errorf("unknown core target %q (valid: %s, all)", opts.Target, strings.Join(SupportedCoreUpdateTargets(), ", "))
		}
		specs = []CoreUpdateSpec{spec}
	}

	restartFn := opts.RestartFunc
	if restartFn == nil {
		restartFn = s.RestartCore
	}
	verifyFn := opts.VerifyHealthFunc
	if verifyFn == nil {
		verifyFn = s.verifyUpdatedCoreHealth
	}

	results := make([]CoreUpdateResult, 0, len(specs))
	var firstErr error
	for _, spec := range specs {
		if norm == "all" && !canAutoUpdateSpec(spec) {
			msg := "upstream distributes source only; provide a Custom URL/file or update the panel bundle"
			if spec.UpdateMode == "source-go" {
				msg = "upstream publishes source tags only (no Go compiler in PATH for auto-build); install Go or supply Custom URL/file"
			}
			results = append(results, CoreUpdateResult{
				Target:      spec.Target,
				ServiceCore: spec.ServiceCore,
				Status:      "skipped",
				Message:     msg,
			})
			continue
		}
		if norm == "all" && spec.CustomPatched && !opts.AllowUnpatched {
			results = append(results, CoreUpdateResult{
				Target:      spec.Target,
				ServiceCore: spec.ServiceCore,
				Status:      "skipped",
				Message:     "custom-patched core protected from bulk vanilla upstream replacement (update individually with allowUnpatched or supply a patched build)",
			})
			continue
		}
		res, err := s.updateSingleCore(spec, opts, restartFn, verifyFn)
		results = append(results, res)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return results, firstErr
}

func (s *CoreService) updateSingleCore(
	spec CoreUpdateSpec,
	opts CoreUpdateOptions,
	restartFn func(string) error,
	verifyFn func(CoreUpdateSpec, string) error,
) (CoreUpdateResult, error) {
	dest := filepath.Join(binutil.CustomBinDir(), spec.CustomFileFunc())
	res := CoreUpdateResult{
		Target:      spec.Target,
		ServiceCore: spec.ServiceCore,
		DestPath:    dest,
	}

	tmpDir, err := os.MkdirTemp("", "vpnui-core-update-*")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmpDir)

	artifactPath := ""
	expectedSHA := strings.TrimSpace(opts.SHA256)
	sourceLabel := ""
	stagedExec := filepath.Join(tmpDir, spec.Target+".bin")
	builtFromSource := false

	switch {
	case strings.TrimSpace(opts.File) != "":
		artifactPath = strings.TrimSpace(opts.File)
		sourceLabel = "local-file"
	case strings.TrimSpace(opts.URL) != "":
		dlURL := config.ApplyGHProxy(strings.TrimSpace(opts.URL))
		sourceLabel = dlURL
		artifactPath = filepath.Join(tmpDir, archiveFilenameFromURL(dlURL))
		if err := downloadArtifact(dlURL, artifactPath); err != nil {
			return res, fmt.Errorf("download %s: %w", spec.Target, err)
		}
	default:
		if spec.UpdateMode == "custom" || spec.GithubRepo == "" {
			return res, fmt.Errorf("%s (%s) has no prebuilt upstream binary releases; choose a Custom URL or local binary file", spec.Target, spec.Protocols)
		}
		if spec.CustomPatched && !opts.AllowUnpatched {
			return res, fmt.Errorf("%s carries custom vpn-ui patches (%s); refusing silent overwrite with unpatched upstream %s — pass allowUnpatched=true (--allow-unpatched) to confirm replacement or provide a custom-patched URL/file",
				spec.Target, strings.Join(spec.PatchSet, ", "), spec.GithubRepo)
		}
		dlURL, ghDigest, resolvedTag, err := resolveGithubReleaseAsset(spec, opts.Version)
		if err == nil && dlURL != "" {
			sourceLabel = dlURL
			res.Version = resolvedTag
			if expectedSHA == "" && ghDigest != "" {
				expectedSHA = ghDigest
			}
			artifactPath = filepath.Join(tmpDir, archiveFilenameFromURL(dlURL))
			if err := downloadArtifact(config.ApplyGHProxy(dlURL), artifactPath); err != nil {
				return res, fmt.Errorf("download %s (%s): %w", spec.Target, resolvedTag, err)
			}
		} else if spec.GoSourcePackage != "" {
			tag, tarballURL, serr := resolveGoTagTarball(spec, opts.Version)
			if serr != nil {
				return res, fmt.Errorf("resolve upstream tag for %s: %w", spec.Target, serr)
			}
			if _, gerr := exec.LookPath("go"); gerr != nil {
				return res, fmt.Errorf("%s (%s) publishes source tags only (no prebuilt Linux binaries); install Go toolchain on host to build %s or supply Custom URL/file", spec.Target, spec.GithubRepo, tag)
			}
			if berr := buildGoSourceBinary(spec, tag, tarballURL, stagedExec); berr != nil {
				return res, fmt.Errorf("build %s (%s) from source: %w", spec.Target, tag, berr)
			}
			sourceLabel = tarballURL
			res.Version = tag
			builtFromSource = true
		} else {
			return res, fmt.Errorf("resolve release for %s: %w", spec.Target, err)
		}
	}
	res.Source = sourceLabel

	if !builtFromSource {
		if expectedSHA != "" {
			if err := binutil.VerifySHA256(artifactPath, expectedSHA); err != nil {
				return res, err
			}
		}
		if err := extractExecutableFromArtifact(artifactPath, stagedExec, spec.ArchiveBinaryNames); err != nil {
			return res, fmt.Errorf("extract %s binary: %w", spec.Target, err)
		}
	}
	if err := os.Chmod(stagedExec, 0o755); err != nil {
		return res, err
	}
	if err := binutil.ValidateELFBinary(stagedExec, runtime.GOARCH); err != nil {
		return res, fmt.Errorf("validate %s binary: %w", spec.Target, err)
	}
	if opts.VerifyHealthFunc == nil {
		if err := RunBinaryVersionCheck(spec, stagedExec); err != nil {
			return res, fmt.Errorf("staged binary self-check failed: %w", err)
		}
		if spec.ServiceCore == "xray" {
			stagedCfgPath, cerr := s.prepareStagedXrayConfig(stagedExec, tmpDir)
			if cerr != nil {
				return res, fmt.Errorf("prepare staged xray preflight config: %w", cerr)
			}
			if stagedCfgPath != "" {
				if err := testXrayBinaryConfig(stagedExec, stagedCfgPath); err != nil {
					return res, fmt.Errorf("staged xray rejected current config: %w", err)
				}
				res.PreflightTested = true
			}
		}
	}

	sum, err := binutil.FileSHA256(stagedExec)
	if err == nil {
		res.SHA256 = sum
	}
	if ver := probeBinaryVersion(stagedExec, spec.VersionArgs); ver != "" {
		res.Version = ver
	}

	isPatchedResult := spec.CustomPatched
	if spec.Target == "xray" {
		hasSL, hasFork := scanXrayCapabilityMarkers(stagedExec)
		if hasSL || hasFork {
			isPatchedResult = true
		} else if strings.TrimSpace(opts.URL) == "" && strings.TrimSpace(opts.File) == "" {
			isPatchedResult = false
		}
	} else if strings.TrimSpace(opts.URL) == "" && strings.TrimSpace(opts.File) == "" && spec.CustomPatched {
		isPatchedResult = false
	}

	bakPath, hadPrev, err := binutil.AtomicInstallBinary(dest, stagedExec)
	if err != nil {
		return res, err
	}
	writeCoreOverrideMeta(dest, coreOverrideMeta{
		CustomPatched:  isPatchedResult,
		Source:         sourceLabel,
		Version:        res.Version,
		AllowUnpatched: opts.AllowUnpatched,
	})
	invalidateDaemonVersionCache(spec.CustomFileFunc())
	invalidateXrayCapabilitiesCache()
	if hadPrev {
		res.BackupPath = bakPath
	}

	rollbackWithReason := func(cause error) (CoreUpdateResult, error) {
		rbErr := binutil.RestoreBinary(dest, bakPath, hadPrev)
		invalidateDaemonVersionCache(spec.CustomFileFunc())
		invalidateXrayCapabilitiesCache()
		if rbErr == nil {
			_ = restartFn(spec.ServiceCore)
			res.RolledBack = true
			res.Status = "rolled_back"
			res.Message = fmt.Sprintf("update failed health check (%v); automatically rolled back to previous binary", cause)
			return res, fmt.Errorf("%s", res.Message)
		}
		res.Status = "failed"
		res.Message = fmt.Sprintf("update failed (%v) and rollback failed (%v)", cause, rbErr)
		return res, fmt.Errorf("%s", res.Message)
	}

	if err := restartFn(spec.ServiceCore); err != nil {
		return rollbackWithReason(fmt.Errorf("restart %s: %w", spec.ServiceCore, err))
	}
	res.Restarted = true

	if err := verifyFn(spec, dest); err != nil {
		return rollbackWithReason(err)
	}

	res.Status = "updated"
	res.Message = fmt.Sprintf("%s updated at %s and %s restarted cleanly", spec.Target, dest, spec.ServiceCore)
	logger.Infof("core-updater: %s", res.Message)
	return res, nil
}

// RollbackCore reverts target's custom override to its .bak backup (or removes
// a backup-less custom override so the bundled binary becomes active again) and
// runs a targeted restart for that core only.
func (s *CoreService) RollbackCore(target string, restartFn func(string) error) (CoreUpdateResult, error) {
	spec, ok := findCoreUpdateSpec(target)
	if !ok {
		return CoreUpdateResult{}, fmt.Errorf("unknown core target %q (valid: %s)", target, strings.Join(SupportedCoreUpdateTargets(), ", "))
	}
	if restartFn == nil {
		restartFn = s.RestartCore
	}

	dest := filepath.Join(binutil.CustomBinDir(), spec.CustomFileFunc())
	bakPath := dest + ".bak"
	res := CoreUpdateResult{
		Target:      spec.Target,
		ServiceCore: spec.ServiceCore,
		DestPath:    dest,
	}

	if _, err := os.Stat(bakPath); err == nil {
		if err := binutil.RestoreBinary(dest, bakPath, true); err != nil {
			return res, fmt.Errorf("restore backup %s: %w", bakPath, err)
		}
		_ = os.Remove(coreMetaPath(dest))
		invalidateDaemonVersionCache(spec.CustomFileFunc())
		invalidateXrayCapabilitiesCache()
		res.Source = "backup"
		res.Message = fmt.Sprintf("restored %s from backup", dest)
	} else if _, err := os.Stat(dest); err == nil {
		if err := binutil.RestoreBinary(dest, "", false); err != nil {
			return res, fmt.Errorf("remove custom override %s: %w", dest, err)
		}
		_ = os.Remove(coreMetaPath(dest))
		invalidateDaemonVersionCache(spec.CustomFileFunc())
		invalidateXrayCapabilitiesCache()
		res.Source = "bundled-fallback"
		res.Message = fmt.Sprintf("removed custom override %s; reverted to bundled binary", dest)
	} else {
		return res, fmt.Errorf("no custom override or backup present for %s in %s", spec.Target, binutil.CustomBinDir())
	}

	if err := restartFn(spec.ServiceCore); err != nil {
		return res, fmt.Errorf("restarted %s after rollback with error: %w", spec.ServiceCore, err)
	}
	res.Restarted = true
	res.RolledBack = true
	res.Status = "rolled_back"
	return res, nil
}

// RunBinaryVersionCheck verifies on Linux hosts that an installed binary executes
// its version flag and (for tools that exit non-zero on --version like openvpn)
// emits non-empty output cleanly without crashing at dynamic link/exec time.
func RunBinaryVersionCheck(spec CoreUpdateSpec, destPath string) error {
	if runtime.GOOS != "linux" || len(spec.VersionArgs) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, destPath, spec.VersionArgs...).CombinedOutput()
	if err == nil {
		return nil
	}
	if spec.AllowNonZeroVersionExit && len(strings.TrimSpace(string(out))) > 0 {
		if _, isExitErr := err.(*exec.ExitError); isExitErr {
			return nil
		}
	}
	return fmt.Errorf("%s failed binary execution check: %w (%s)", spec.Target, err, strings.TrimSpace(string(out)))
}

func (s *CoreService) prepareStagedXrayConfig(stagedExec, tmpDir string) (string, error) {
	if database.GetDB() != nil {
		stagedCaps := DetectXrayCapabilities(stagedExec)
		cfg, err := s.xrayService.BuildXrayConfigWithCapabilities(stagedCaps)
		if err == nil && cfg != nil {
			rawCfg, merr := json.MarshalIndent(cfg, "", "  ")
			if merr != nil {
				return "", merr
			}
			stagedCfg := filepath.Join(tmpDir, "staged-config.json")
			if werr := os.WriteFile(stagedCfg, rawCfg, 0o600); werr != nil {
				return "", werr
			}
			return stagedCfg, nil
		}
	}
	if cfgPath := xray.GetConfigPath(); cfgPath != "" {
		if st, serr := os.Stat(cfgPath); serr == nil && !st.IsDir() {
			return cfgPath, nil
		}
	}
	return "", nil
}

func testXrayBinaryConfig(binPath, configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "run", "-test", "-c", configPath)
	env := os.Environ()
	if absBinDir, err := filepath.Abs(config.GetBinFolderPath()); err == nil {
		env = append(env, "XRAY_LOCATION_ASSET="+absBinDir)
	}
	if absSL, err := filepath.Abs(xray.GetSpeedLimitPath()); err == nil {
		env = append(env, "XRAY_SPEEDLIMIT_FILE="+absSL)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (s *CoreService) verifyUpdatedCoreHealth(spec CoreUpdateSpec, destPath string) error {
	if err := RunBinaryVersionCheck(spec, destPath); err != nil {
		return err
	}

	if spec.ServiceCore == "xray" {
		startDeadline := time.Now().Add(5 * time.Second)
		startedRunning := false
		for time.Now().Before(startDeadline) {
			if errMsg := s.xrayService.GetXrayErr(); errMsg != nil {
				return fmt.Errorf("xray startup error: %w", errMsg)
			}
			if s.xrayService.IsXrayRunning() {
				startedRunning = true
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if !startedRunning {
			if errMsg := s.xrayService.GetXrayErr(); errMsg != nil {
				return fmt.Errorf("xray startup error: %w", errMsg)
			}
			if resMsg := strings.TrimSpace(s.xrayService.GetXrayResult()); resMsg != "" {
				return fmt.Errorf("xray process did not remain running after update: %s", resMsg)
			}
			return errors.New("xray process did not remain running after update")
		}
		// Soak for 2 seconds after startup so rapid initialization exits (e.g.
		// geoip/geosite read errors or invalid inbound listeners) trigger auto-rollback.
		for i := 0; i < 8; i++ {
			time.Sleep(250 * time.Millisecond)
			if errMsg := s.xrayService.GetXrayErr(); errMsg != nil {
				return fmt.Errorf("xray exited during stability check: %w", errMsg)
			}
			if !s.xrayService.IsXrayRunning() {
				if resMsg := strings.TrimSpace(s.xrayService.GetXrayResult()); resMsg != "" {
					return fmt.Errorf("xray exited during stability check: %s", resMsg)
				}
				return errors.New("xray exited during post-update stability check")
			}
		}
		return nil
	}

	// For sidecar daemons (telemt, sing-box, ocserv, awg), confirm the core stays
	// healthy across the post-restart settle window when enabled inbounds exist for it.
	counts := s.inboundCountsByCore()
	if counts[spec.ServiceCore] == 0 {
		return nil
	}
	for i := 0; i < 4; i++ {
		time.Sleep(500 * time.Millisecond)
		for _, st := range s.GetCoresStatus() {
			if st.Name == spec.ServiceCore && (st.State == CoreError || st.State == CoreStopped) {
				return fmt.Errorf("core %s entered state %s (%s)", spec.ServiceCore, st.State, st.Detail)
			}
		}
	}
	return nil
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

type githubReleasePayload struct {
	TagName     string               `json:"tag_name"`
	Name        string               `json:"name"`
	Prerelease  bool                 `json:"prerelease"`
	Draft       bool                 `json:"draft"`
	PublishedAt string               `json:"published_at"`
	HTMLURL     string               `json:"html_url"`
	TarballURL  string               `json:"tarball_url"`
	Assets      []githubReleaseAsset `json:"assets"`
}

// ListUpstreamCoreVersions fetches available official releases (or tags when the
// upstream repo does not publish release artifacts) for the given core target.
func (s *CoreService) ListUpstreamCoreVersions(target string, forceRefresh bool) (CoreUpdateSpec, []CoreReleaseOption, error) {
	spec, ok := findCoreUpdateSpec(target)
	if !ok {
		return CoreUpdateSpec{}, nil, fmt.Errorf("unknown core target %q (valid: %s)", target, strings.Join(SupportedCoreUpdateTargets(), ", "))
	}
	if spec.GithubRepo == "" {
		return spec, nil, fmt.Errorf("%s has no configured upstream repository", spec.Target)
	}

	cacheKey := strings.TrimRight(githubReleaseAPIBase, "/") + "|" + strings.TrimRight(gitlabReleaseAPIBase, "/") + "|" + runtime.GOARCH + "|" + spec.Target
	if !forceRefresh {
		upstreamCacheMu.Lock()
		cached, hit := upstreamVersionsCache[cacheKey]
		upstreamCacheMu.Unlock()
		if hit && time.Since(cached.fetchedAt) < upstreamVersionsCacheTTL {
			cp := make([]CoreReleaseOption, len(cached.items))
			copy(cp, cached.items)
			return spec, cp, nil
		}
	}

	var (
		items []CoreReleaseOption
		err   error
	)
	if spec.UpstreamProvider == "gitlab" {
		items, err = fetchGitlabReleasesOrTags(spec)
	} else {
		items, err = fetchGithubReleasesOrTags(spec)
	}
	if err != nil {
		return spec, nil, err
	}

	markLatestUpstreamOption(items)

	upstreamCacheMu.Lock()
	upstreamVersionsCache[cacheKey] = cachedUpstreamVersions{
		fetchedAt: time.Now(),
		items:     append([]CoreReleaseOption(nil), items...),
	}
	upstreamCacheMu.Unlock()

	return spec, items, nil
}

func markLatestUpstreamOption(items []CoreReleaseOption) {
	for i := range items {
		items[i].Latest = false
	}
	for i := range items {
		if !items[i].Prerelease {
			items[i].Latest = true
			return
		}
	}
	if len(items) > 0 {
		items[0].Latest = true
	}
}

func doJSONGet(rawURL string, out any) error {
	headers := map[string]string{
		"Accept":     "application/vnd.github+json, application/json",
		"User-Agent": "vpn-ui-core-updater/" + config.GetVersion(),
	}
	return fetchValidatedJSON(rawURL, 25*time.Second, headers, out)
}

// fetchValidatedJSON downloads rawURL (applying any configured GH proxy), enforces
// HTTP 200, detects HTML proxy/challenge pages or GitHub API JSON error objects
// before calling json.Unmarshal, and returns crisp human-readable errors.
func fetchValidatedJSON(rawURL string, timeout time.Duration, headers map[string]string, out any) error {
	targetURL := config.ApplyGHProxy(rawURL)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxValidatedJSONBytes+1))
	_ = resp.Body.Close()
	if rerr != nil {
		return fmt.Errorf("read response from %s: %w", rawURL, rerr)
	}
	if len(body) > maxValidatedJSONBytes {
		return fmt.Errorf("upstream %s response exceeded %d MiB size limit", rawURL, maxValidatedJSONBytes>>20)
	}

	trimmed := trimUTF8BOMAndSpace(body)
	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))

	if resp.StatusCode != http.StatusOK {
		rateNote := formatRateLimitNote(resp.Header)
		if msg := extractJSONErrorMessage(trimmed); msg != "" {
			if rateNote != "" {
				return fmt.Errorf("HTTP %d from %s: %s (%s)", resp.StatusCode, rawURL, msg, rateNote)
			}
			return fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, rawURL, msg)
		}
		if looksLikeHTMLPayload(contentType, trimmed) {
			return fmt.Errorf("HTTP %d from %s returned HTML instead of JSON (mirror/proxy error or rate-limit page)", resp.StatusCode, rawURL)
		}
		if rateNote != "" {
			return fmt.Errorf("HTTP %d from %s (%s)", resp.StatusCode, rawURL, rateNote)
		}
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}

	if len(trimmed) == 0 {
		return fmt.Errorf("empty JSON response from %s", rawURL)
	}
	if looksLikeHTMLPayload(contentType, trimmed) {
		return fmt.Errorf("upstream %s returned HTML instead of JSON (content-type: %s — check mirror, proxy, or firewall)", rawURL, firstNonEmptyString(contentType, "unknown"))
	}
	if !json.Valid(trimmed) {
		if msg := extractJSONErrorMessage(trimmed); msg != "" {
			return fmt.Errorf("API error from %s: %s", rawURL, msg)
		}
		return fmt.Errorf("invalid JSON response from %s (content-type: %s)", rawURL, firstNonEmptyString(contentType, "unknown"))
	}
	if err := json.Unmarshal(trimmed, out); err != nil {
		if msg := extractJSONErrorMessage(trimmed); msg != "" {
			return fmt.Errorf("API error from %s: %s", rawURL, msg)
		}
		return fmt.Errorf("decode response from %s: %w", rawURL, err)
	}
	return nil
}

func formatRateLimitNote(h http.Header) string {
	if h == nil {
		return ""
	}
	rem := strings.TrimSpace(h.Get("X-RateLimit-Remaining"))
	resetRaw := strings.TrimSpace(h.Get("X-RateLimit-Reset"))
	retryAfter := strings.TrimSpace(h.Get("Retry-After"))
	if rem != "0" && retryAfter == "" {
		return ""
	}
	var parts []string
	if rem == "0" {
		parts = append(parts, "GitHub API rate limit exhausted")
	}
	if resetRaw != "" {
		if ts, err := strconv.ParseInt(resetRaw, 10, 64); err == nil && ts > 0 {
			parts = append(parts, "resets at "+time.Unix(ts, 0).UTC().Format(time.RFC3339))
		}
	}
	if retryAfter != "" {
		parts = append(parts, "retry-after "+retryAfter+"s")
	}
	return strings.Join(parts, "; ")
}

func trimUTF8BOMAndSpace(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	return bytes.TrimSpace(b)
}

func looksLikeHTMLPayload(contentType string, trimmed []byte) bool {
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml") {
		return true
	}
	if len(trimmed) == 0 {
		return false
	}
	if trimmed[0] == '<' {
		return true
	}
	head := strings.ToLower(string(trimmed[:min(len(trimmed), 128)]))
	return strings.HasPrefix(head, "<!doctype") || strings.HasPrefix(head, "<html")
}

func extractJSONErrorMessage(trimmed []byte) string {
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ""
	}
	var errObj struct {
		Message          string `json:"message"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(trimmed, &errObj) != nil {
		return ""
	}
	for _, msg := range []string{errObj.Message, errObj.ErrorDescription, errObj.Error} {
		msg = strings.TrimSpace(msg)
		if msg != "" {
			return msg
		}
	}
	return ""
}

func fetchGithubReleasesOrTags(spec CoreUpdateSpec) ([]CoreReleaseOption, error) {
	base := strings.TrimRight(githubReleaseAPIBase, "/")
	var rels []githubReleasePayload
	if err := doJSONGet(fmt.Sprintf("%s/repos/%s/releases?per_page=100", base, spec.GithubRepo), &rels); err != nil {
		return nil, err
	}

	items := make([]CoreReleaseOption, 0, len(rels))
	for _, rel := range rels {
		if rel.Draft || rel.TagName == "" {
			continue
		}
		opt := CoreReleaseOption{
			Tag:         rel.TagName,
			Name:        rel.Name,
			Prerelease:  rel.Prerelease,
			PublishedAt: rel.PublishedAt,
			URL:         rel.HTMLURL,
			TarballURL:  rel.TarballURL,
		}
		if spec.UpdateMode == "prebuilt" || len(rel.Assets) > 0 {
			if name, dlURL, digest, _ := pickReleaseAsset(spec.Target, rel.Assets, runtime.GOARCH); dlURL != "" {
				opt.AssetName = name
				opt.DownloadURL = dlURL
				opt.SHA256 = digest
			}
		}
		if opt.DownloadURL == "" {
			opt.SourceOnly = true
		}
		items = append(items, opt)
	}
	if len(items) > 0 {
		return items, nil
	}

	var tags []struct {
		Name       string `json:"name"`
		TarballURL string `json:"tarball_url"`
	}
	if err := doJSONGet(fmt.Sprintf("%s/repos/%s/tags?per_page=100", base, spec.GithubRepo), &tags); err != nil {
		return nil, err
	}
	items = make([]CoreReleaseOption, 0, len(tags))
	for _, tg := range tags {
		if tg.Name == "" {
			continue
		}
		tb := tg.TarballURL
		if tb == "" {
			tb = fmt.Sprintf("%s/repos/%s/tarball/refs/tags/%s", base, spec.GithubRepo, tg.Name)
		}
		items = append(items, CoreReleaseOption{
			Tag:        tg.Name,
			Name:       tg.Name,
			URL:        fmt.Sprintf("https://github.com/%s/releases/tag/%s", spec.GithubRepo, url.PathEscape(tg.Name)),
			TarballURL: tb,
			SourceOnly: true,
		})
	}
	return items, nil
}

func fetchGitlabReleasesOrTags(spec CoreUpdateSpec) ([]CoreReleaseOption, error) {
	base := strings.TrimRight(gitlabReleaseAPIBase, "/")
	proj := url.PathEscape(spec.GithubRepo)
	var rels []struct {
		TagName         string `json:"tag_name"`
		Name            string `json:"name"`
		UpcomingRelease bool   `json:"upcoming_release"`
		ReleasedAt      string `json:"released_at"`
		CreatedAt       string `json:"created_at"`
		Links           struct {
			Self string `json:"self"`
		} `json:"_links"`
	}
	if err := doJSONGet(fmt.Sprintf("%s/api/v4/projects/%s/releases?per_page=50", base, proj), &rels); err == nil && len(rels) > 0 {
		items := make([]CoreReleaseOption, 0, len(rels))
		for _, rel := range rels {
			if rel.TagName == "" {
				continue
			}
			pub := rel.ReleasedAt
			if pub == "" {
				pub = rel.CreatedAt
			}
			link := rel.Links.Self
			if link == "" {
				link = fmt.Sprintf("%s/%s/-/releases/%s", base, spec.GithubRepo, url.PathEscape(rel.TagName))
			}
			items = append(items, CoreReleaseOption{
				Tag:         rel.TagName,
				Name:        rel.Name,
				Prerelease:  rel.UpcomingRelease,
				PublishedAt: pub,
				URL:         link,
				SourceOnly:  true,
			})
		}
		return items, nil
	}

	var tags []struct {
		Name string `json:"name"`
	}
	if err := doJSONGet(fmt.Sprintf("%s/api/v4/projects/%s/repository/tags?per_page=50", base, proj), &tags); err != nil {
		return nil, err
	}
	items := make([]CoreReleaseOption, 0, len(tags))
	for _, tg := range tags {
		if tg.Name == "" {
			continue
		}
		items = append(items, CoreReleaseOption{
			Tag:        tg.Name,
			Name:       tg.Name,
			URL:        fmt.Sprintf("%s/%s/-/tags/%s", base, spec.GithubRepo, url.PathEscape(tg.Name)),
			SourceOnly: true,
		})
	}
	return items, nil
}

func resolveGoTagTarball(spec CoreUpdateSpec, requestedVersion string) (tag string, tarballURL string, err error) {
	_, items, err := (&CoreService{}).ListUpstreamCoreVersions(spec.Target, false)
	if err != nil {
		return "", "", err
	}
	if len(items) == 0 {
		return "", "", fmt.Errorf("no tags returned for %s", spec.GithubRepo)
	}
	ver := strings.TrimSpace(requestedVersion)
	if ver == "" {
		for _, it := range items {
			if it.Latest {
				return it.Tag, it.TarballURL, nil
			}
		}
		return items[0].Tag, items[0].TarballURL, nil
	}
	for _, it := range items {
		if it.Tag == ver || strings.TrimPrefix(it.Tag, "v") == strings.TrimPrefix(ver, "v") {
			return it.Tag, it.TarballURL, nil
		}
	}
	return "", "", fmt.Errorf("version %q not found in upstream tags for %s", ver, spec.GithubRepo)
}

func buildGoSourceBinary(spec CoreUpdateSpec, versionTag, tarballURL, destExec string) error {
	srcArchive := destExec + ".src.tar.gz"
	if err := downloadArtifact(tarballURL, srcArchive); err != nil {
		return err
	}
	srcRoot := destExec + ".src"
	if err := os.MkdirAll(srcRoot, 0o700); err != nil {
		return err
	}
	if err := extractTarGzDirectory(srcArchive, srcRoot); err != nil {
		return err
	}
	modDir, err := findGoModRoot(srcRoot)
	if err != nil {
		return err
	}
	ldflags := "-s -w"
	if spec.Target == "amneziawg-go" && strings.TrimSpace(versionTag) != "" {
		ver := strings.TrimPrefix(strings.TrimSpace(versionTag), "v")
		ldflags = fmt.Sprintf("-X main.Version=%s -s -w", ver)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags="+ldflags, "-o", destExec, spec.GoSourcePackage)
	cmd.Dir = modDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func extractTarGzDirectory(gzPath, destDir string) error {
	f, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()
	cleanRoot := filepath.Clean(destDir)
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel := filepath.FromSlash(strings.TrimLeft(hdr.Name, "/"))
		if rel == "" || rel == "." {
			continue
		}
		target := filepath.Join(cleanRoot, rel)
		if target != cleanRoot && !strings.HasPrefix(target, cleanRoot+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path in source tarball: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, io.LimitReader(tr, maxCoreArtifactBytes))
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
}

func findGoModRoot(root string) (string, error) {
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
		return root, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cand := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(cand, "go.mod")); err == nil {
			return cand, nil
		}
	}
	return "", errors.New("source archive does not contain go.mod")
}

func pickReleaseAsset(target string, assets []githubReleaseAsset, goarch string) (pickedName, downloadURL, sha256Digest, sidecarChecksumURL string) {
	checksumMap := map[string]string{}
	candidates := make([]githubReleaseAsset, 0, len(assets))
	for _, a := range assets {
		lower := strings.ToLower(a.Name)
		if strings.HasSuffix(lower, ".sha256") || strings.HasSuffix(lower, ".dgst") {
			checksumMap[lower] = a.BrowserDownloadURL
			continue
		}
		candidates = append(candidates, a)
	}
	bestScore := -1
	for _, a := range candidates {
		score := scoreReleaseAsset(target, a.Name, goarch)
		if score > bestScore {
			bestScore = score
			downloadURL = a.BrowserDownloadURL
			sha256Digest = a.Digest
			pickedName = a.Name
		}
	}
	if bestScore <= 0 || downloadURL == "" {
		return "", "", "", ""
	}
	for _, suffix := range []string{".dgst", ".sha256"} {
		if cURL, ok := checksumMap[strings.ToLower(pickedName)+suffix]; ok {
			sidecarChecksumURL = cURL
			break
		}
	}
	return pickedName, downloadURL, sha256Digest, sidecarChecksumURL
}

func resolveGithubReleaseAsset(spec CoreUpdateSpec, requestedVersion string) (downloadURL, sha256Digest, tagName string, err error) {
	base := strings.TrimRight(githubReleaseAPIBase, "/")
	ver := strings.TrimSpace(requestedVersion)
	endpoints := []string{fmt.Sprintf("%s/repos/%s/releases/latest", base, spec.GithubRepo)}
	if ver != "" {
		endpoints = []string{fmt.Sprintf("%s/repos/%s/releases/tags/%s", base, spec.GithubRepo, url.PathEscape(ver))}
		if !strings.HasPrefix(ver, "v") {
			endpoints = append(endpoints, fmt.Sprintf("%s/repos/%s/releases/tags/%s", base, spec.GithubRepo, url.PathEscape("v"+ver)))
		} else {
			endpoints = append(endpoints, fmt.Sprintf("%s/repos/%s/releases/tags/%s", base, spec.GithubRepo, url.PathEscape(strings.TrimPrefix(ver, "v"))))
		}
	}

	var rel githubReleasePayload
	var lastErr error
	for _, ep := range endpoints {
		if jerr := doJSONGet(ep, &rel); jerr != nil {
			lastErr = jerr
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil && ver == "" {
		// Some repos have pre-releases only where /releases/latest returns 404.
		var rels []githubReleasePayload
		if rerr := doJSONGet(fmt.Sprintf("%s/repos/%s/releases?per_page=10", base, spec.GithubRepo), &rels); rerr == nil && len(rels) > 0 {
			for _, cand := range rels {
				if cand.Draft || cand.TagName == "" {
					continue
				}
				if !cand.Prerelease {
					rel = cand
					lastErr = nil
					break
				}
				if rel.TagName == "" {
					rel = cand
					lastErr = nil
				}
			}
		}
	}
	if lastErr != nil {
		return "", "", "", lastErr
	}

	pickedName, dlURL, digest, sidecarURL := pickReleaseAsset(spec.Target, rel.Assets, runtime.GOARCH)
	if dlURL == "" {
		return "", "", rel.TagName, fmt.Errorf("no matching linux/%s asset in %s release %s", runtime.GOARCH, spec.GithubRepo, rel.TagName)
	}
	_ = pickedName
	if digest == "" && sidecarURL != "" {
		client := &http.Client{Timeout: 25 * time.Second}
		sum, ferr := fetchSHA256FromSidecar(client, config.ApplyGHProxy(sidecarURL))
		if ferr != nil {
			if spec.GithubRepo == "XTLS/Xray-core" {
				return "", "", rel.TagName, fmt.Errorf("fetch SHA-256 digest %s for %s: %w", sidecarURL, pickedName, ferr)
			}
		} else {
			digest = sum
		}
	}
	return dlURL, digest, rel.TagName, nil
}

func scoreReleaseAsset(target, filename, goarch string) int {
	lower := strings.ToLower(filename)
	for _, skip := range []string{
		".sig", ".asc", ".dgst", ".sha256", ".sha512",
		".deb", ".rpm", ".apk", ".ipk", ".msi", ".exe", ".dmg", ".json",
		".zst", ".xz", ".bz2", ".appimage", "dsym",
		"windows", "darwin", "macos", "freebsd", "android", "openbsd", "openwrt",
	} {
		if strings.Contains(lower, skip) {
			return -1
		}
	}
	if !strings.Contains(lower, "linux") {
		return -1
	}

	var archTokens []string
	switch goarch {
	case "amd64":
		archTokens = []string{"amd64", "x86_64", "linux-64"}
	case "arm64":
		archTokens = []string{"arm64-v8a", "arm64", "aarch64"}
	case "arm":
		if strings.Contains(lower, "arm64") || strings.Contains(lower, "aarch64") {
			return -1
		}
		switch strings.TrimSpace(os.Getenv("GOARM")) {
		case "5":
			archTokens = []string{"arm32-v5", "armv5", "arm-v5"}
		case "6":
			archTokens = []string{"arm32-v6", "armv6", "arm-v6"}
		default:
			archTokens = []string{"arm32-v7a", "armv7", "arm-v7", "armv6", "arm"}
		}
	case "386":
		if strings.Contains(lower, "x86_64") || strings.Contains(lower, "amd64") || strings.Contains(lower, "linux-64") {
			return -1
		}
		archTokens = []string{"linux-32", "386", "i386", "x86"}
	default:
		archTokens = []string{goarch}
	}

	matchedArch := false
	for _, tok := range archTokens {
		if strings.Contains(lower, tok) {
			matchedArch = true
			break
		}
	}
	if !matchedArch {
		return -1
	}

	score := 10
	if strings.Contains(lower, target) || strings.Contains(lower, "xray-linux") {
		score += 5
	}
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".zip") {
		score += 3
	}
	// Prefer statically linked musl/Go builds over glibc/gnu variants so updates stay
	// portable across Linux distributions (and prefer generic baseline ISAs over -v3/-v2).
	if strings.Contains(lower, "musl") {
		score += 4
	} else if !strings.Contains(lower, "gnu") && !strings.Contains(lower, "glibc") {
		score += 3
	}
	if strings.Contains(lower, "x86_64-v") || strings.Contains(lower, "amd64-v") || strings.Contains(lower, "amd64v") {
		score -= 4
	}
	if strings.Contains(lower, "with-") || strings.Contains(lower, "naive") || strings.Contains(lower, "legacy") {
		score -= 2
	}
	return score
}

func fetchSHA256FromSidecar(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if len(f) == 64 && isHexString(f) {
				return strings.ToLower(f), nil
			}
		}
		if strings.Contains(strings.ToUpper(line), "SHA2-256") || strings.Contains(strings.ToUpper(line), "SHA256") {
			if eq := strings.Index(line, "="); eq >= 0 {
				cand := strings.TrimSpace(line[eq+1:])
				if len(cand) == 64 && isHexString(cand) {
					return strings.ToLower(cand), nil
				}
			}
		}
	}
	return "", errors.New("no sha256 digest found in sidecar")
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return s != ""
}

func archiveFilenameFromURL(rawURL string) string {
	clean := rawURL
	if q := strings.IndexByte(clean, '?'); q >= 0 {
		clean = clean[:q]
	}
	base := path.Base(clean)
	if base == "" || base == "." || base == "/" {
		return "artifact.bin"
	}
	return base
}

func downloadArtifact(rawURL, destPath string) error {
	rawURL = config.ApplyGHProxy(rawURL)
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vpn-ui-core-updater")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, rawURL)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); strings.Contains(ct, "text/html") {
		return fmt.Errorf("download %s returned HTML page instead of binary/archive (content-type: %s)", rawURL, ct)
	}

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(resp.Body, maxCoreArtifactBytes+1))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxCoreArtifactBytes {
		return fmt.Errorf("artifact exceeds max size limit (%d bytes)", maxCoreArtifactBytes)
	}
	return nil
}

func extractExecutableFromArtifact(artifactPath, destPath string, wantedNames []string) error {
	f, err := os.Open(artifactPath)
	if err != nil {
		return err
	}
	hdr := make([]byte, 32)
	n, _ := io.ReadFull(f, hdr)
	_ = f.Close()
	if n < 2 {
		return errors.New("artifact file is empty")
	}

	switch {
	case n >= 4 && bytes.Equal(hdr[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return copyBinaryFile(artifactPath, destPath)
	case n >= 4 && bytes.Equal(hdr[:4], []byte{'P', 'K', 0x03, 0x04}):
		return extractFromZip(artifactPath, destPath, wantedNames)
	case hdr[0] == 0x1f && hdr[1] == 0x8b:
		return extractFromGzipOrTarGz(artifactPath, destPath, wantedNames)
	case len(bytes.TrimSpace(hdr[:n])) > 0 && bytes.TrimSpace(hdr[:n])[0] == '<':
		return errors.New("downloaded artifact appears to be HTML/XML instead of an ELF binary or archive")
	default:
		// Allow other archive extensions or fail clearly if non-ELF.
		if strings.HasSuffix(strings.ToLower(artifactPath), ".zip") {
			return extractFromZip(artifactPath, destPath, wantedNames)
		}
		return copyBinaryFile(artifactPath, destPath)
	}
}

func copyBinaryFile(srcPath, destPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(src, maxCoreArtifactBytes))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func extractFromZip(zipPath, destPath string, wantedNames []string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if !matchesBinaryCandidate(entry.Name, wantedNames) {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			_ = rc.Close()
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(rc, maxCoreArtifactBytes+1))
		closeErr := out.Close()
		_ = rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n > maxCoreArtifactBytes {
			return errors.New("extracted zip entry exceeds size limit")
		}
		return nil
	}
	return fmt.Errorf("archive does not contain executable %v", wantedNames)
}

func extractFromGzipOrTarGz(gzPath, destPath string, wantedNames []string) error {
	f, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	gzr, err := gzip.NewReader(f)
	if err != nil {
		_ = f.Close()
		return err
	}
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Not a tar.gz — retry as a plain gzipped binary.
			_ = gzr.Close()
			_ = f.Close()
			return extractPlainGzip(gzPath, destPath)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if !matchesBinaryCandidate(hdr.Name, wantedNames) {
			continue
		}
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			_ = gzr.Close()
			_ = f.Close()
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(tr, maxCoreArtifactBytes+1))
		closeErr := out.Close()
		_ = gzr.Close()
		_ = f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n > maxCoreArtifactBytes {
			return errors.New("extracted tar entry exceeds size limit")
		}
		return nil
	}
	_ = gzr.Close()
	_ = f.Close()
	return fmt.Errorf("tar archive does not contain executable %v", wantedNames)
}

func extractPlainGzip(gzPath, destPath string) error {
	f, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(gzr, maxCoreArtifactBytes+1))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxCoreArtifactBytes {
		return errors.New("extracted gzip stream exceeds size limit")
	}
	return nil
}

func matchesBinaryCandidate(entryName string, wantedNames []string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(entryName, `\`, "/")))
	for _, w := range wantedNames {
		if base == strings.ToLower(w) {
			return true
		}
	}
	return false
}
