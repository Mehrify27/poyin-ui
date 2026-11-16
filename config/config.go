// Package config provides configuration management utilities for the vpn-ui panel,
// including version information, logging levels, database paths, and environment variable handling.
package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

//go:embed version
var version string

//go:embed name
var name string

const (
	// DefaultVersion is the fallback semantic version when embedded/linker metadata
	// is missing or below MinSupportedVersion.
	DefaultVersion = "2.0.0"
	// MinSupportedVersion ensures builds of this fork always report strictly above 1.9.4.
	MinSupportedVersion = "2.0.0"
	// DefaultRepo is the default GitHub owner/repository for releases and self-updates.
	DefaultRepo = "Mehrify27/poyin-ui"
)

// Linker-injected build metadata (-ldflags "-X github.com/mhsanaei/3x-ui/v2/config.ldVersion=...").
var (
	ldVersion string
	ldRepo    string
	ldGHProxy string
)

var (
	overrideMu      sync.RWMutex
	repoOverride    string
	ghProxyOverride string
)

// LogLevel represents the logging level for the application.
type LogLevel string

// Logging level constants
const (
	Debug   LogLevel = "debug"
	Info    LogLevel = "info"
	Notice  LogLevel = "notice"
	Warning LogLevel = "warning"
	Error   LogLevel = "error"
)

// SemVer holds a parsed Semantic Versioning 2.0.0 tuple.
type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	BuildMeta  string
}

// ParseSemVer parses a version string such as "v2.0.0", "2.0", or "2.1.0-rc.1+build".
func ParseSemVer(raw string) (SemVer, bool) {
	var sv SemVer
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	if s == "" {
		return sv, false
	}
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		sv.BuildMeta = s[idx+1:]
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		sv.Prerelease = s[idx+1:]
		if sv.Prerelease == "" {
			return sv, false
		}
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return sv, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		if p == "" {
			return sv, false
		}
		for j := 0; j < len(p); j++ {
			if p[j] < '0' || p[j] > '9' {
				return sv, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return sv, false
		}
		nums[i] = n
	}
	sv.Major, sv.Minor, sv.Patch = nums[0], nums[1], nums[2]
	return sv, true
}

func comparePrereleaseIDs(a, b string) int {
	aNum, aErr := strconv.Atoi(a)
	bNum, bErr := strconv.Atoi(b)
	aDigits := aErr == nil && isAllDigits(a)
	bDigits := bErr == nil && isAllDigits(b)
	switch {
	case aDigits && bDigits:
		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
		return 0
	case aDigits && !bDigits:
		return -1 // numeric identifiers always have lower precedence than non-numeric
	case !aDigits && bDigits:
		return 1
	default:
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// CompareSemVer compares two version strings using SemVer 2.0.0 ordering,
// returning 1 when a > b, -1 when a < b, and 0 when equal.
// If either input is not strict SemVer, it falls back to numeric dot-segment comparison.
func CompareSemVer(a, b string) int {
	sa, okA := ParseSemVer(a)
	sb, okB := ParseSemVer(b)
	if !okA || !okB {
		return compareFallbackVersions(a, b)
	}
	if sa.Major != sb.Major {
		if sa.Major > sb.Major {
			return 1
		}
		return -1
	}
	if sa.Minor != sb.Minor {
		if sa.Minor > sb.Minor {
			return 1
		}
		return -1
	}
	if sa.Patch != sb.Patch {
		if sa.Patch > sb.Patch {
			return 1
		}
		return -1
	}
	if sa.Prerelease == sb.Prerelease {
		return 0
	}
	// Release > pre-release.
	if sa.Prerelease == "" {
		return 1
	}
	if sb.Prerelease == "" {
		return -1
	}
	pa := strings.Split(sa.Prerelease, ".")
	pb := strings.Split(sb.Prerelease, ".")
	limit := len(pa)
	if len(pb) < limit {
		limit = len(pb)
	}
	for i := 0; i < limit; i++ {
		if cmp := comparePrereleaseIDs(pa[i], pb[i]); cmp != 0 {
			return cmp
		}
	}
	if len(pa) > len(pb) {
		return 1
	}
	if len(pa) < len(pb) {
		return -1
	}
	return 0
}

func compareFallbackVersions(a, b string) int {
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
		if idx := strings.IndexAny(s, "+-"); idx >= 0 {
			s = s[:idx]
		}
		return s
	}
	pa := strings.Split(clean(a), ".")
	pb := strings.Split(clean(b), ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x > y {
			return 1
		}
		if x < y {
			return -1
		}
	}
	return 0
}

// IsNewerSemVer reports whether candidate represents a strictly newer version than current.
func IsNewerSemVer(candidate, current string) bool {
	if _, ok := ParseSemVer(candidate); !ok {
		return false
	}
	if _, ok := ParseSemVer(current); !ok {
		return false
	}
	return CompareSemVer(candidate, current) > 0
}

// GetVersion returns the version string of the vpn-ui application.
func GetVersion() string {
	v := strings.TrimSpace(ldVersion)
	if v == "" {
		v = strings.TrimSpace(version)
	}
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if v == "" || CompareSemVer(v, MinSupportedVersion) < 0 {
		return DefaultVersion
	}
	return v
}

func isValidRepoSlug(repo string) bool {
	repo = strings.TrimSpace(repo)
	if repo == "" || strings.ContainsAny(repo, " \t\r\n\\") || strings.Contains(repo, "..") {
		return false
	}
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return false
	}
	return parts[0] != "" && parts[1] != ""
}

// SetRepoOverride overrides the GitHub owner/repository slug for the current process.
func SetRepoOverride(repo string) {
	overrideMu.Lock()
	defer overrideMu.Unlock()
	repoOverride = strings.TrimSpace(repo)
}

// GetRepo returns the configured GitHub repository slug (owner/name).
func GetRepo() string {
	overrideMu.RLock()
	ovr := repoOverride
	overrideMu.RUnlock()
	for _, candidate := range []string{
		ovr,
		os.Getenv("VPNUI_REPO"),
		os.Getenv("REPO"),
		ldRepo,
	} {
		candidate = strings.TrimSpace(candidate)
		if isValidRepoSlug(candidate) {
			return candidate
		}
	}
	return DefaultRepo
}

// SetGHProxyOverride overrides the GitHub mirror/proxy URL prefix for the current process.
func SetGHProxyOverride(proxy string) {
	overrideMu.Lock()
	defer overrideMu.Unlock()
	ghProxyOverride = strings.TrimSpace(proxy)
}

// GetGHProxy returns the normalized GitHub mirror/proxy prefix, if configured.
func GetGHProxy() string {
	overrideMu.RLock()
	ovr := ghProxyOverride
	overrideMu.RUnlock()
	for _, candidate := range []string{
		ovr,
		os.Getenv("VPNUI_GH_PROXY"),
		os.Getenv("GH_PROXY"),
		ldGHProxy,
	} {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			if !strings.HasSuffix(candidate, "/") {
				candidate += "/"
			}
			return candidate
		}
	}
	return ""
}

// ApplyGHProxy rewrites GitHub URLs through the configured mirror/proxy prefix when set.
func ApplyGHProxy(rawURL string) string {
	proxy := GetGHProxy()
	if proxy == "" {
		return rawURL
	}
	if strings.HasPrefix(rawURL, proxy) {
		return rawURL
	}
	for _, prefix := range []string{
		"https://github.com/",
		"https://api.github.com/",
		"https://raw.githubusercontent.com/",
	} {
		if strings.HasPrefix(rawURL, prefix) {
			return proxy + rawURL
		}
	}
	return rawURL
}

// GetName returns the name of the vpn-ui application.
func GetName() string {
	return strings.TrimSpace(name)
}

// assetVersion is the cache-busting token stamped on every asset URL. It lives
// here, set once at web-server start, because the two places that need it (the
// panel's template context and the subscription page's) both import config and
// neither can import web, which is where the embedded asset tree actually is.
//
// It is deliberately NOT GetVersion(). Assets are served with a one-year
// max-age, so the query string is the only thing that can make a browser fetch a
// new copy, and the release version does not move between builds of the same
// version. That combination silently pairs a rebuilt panel's NEW html with a
// browser's OLD javascript, which is not a degraded page but a blank one: the
// html calls a method the cached model file has not got, Vue throws mid-render
// and v-cloak leaves the area empty with nothing on screen to say why.
var assetVersion = strings.TrimSpace(version)

// SetAssetVersion records the token, which must be derived from the served asset
// bytes so that it changes exactly when they do.
func SetAssetVersion(v string) {
	if v != "" {
		assetVersion = v
	}
}

// GetAssetVersion returns the asset cache-busting token, falling back to the
// release version until the web server has computed one.
func GetAssetVersion() string {
	return assetVersion
}

// GetLogLevel returns the current logging level based on environment variables or defaults to Info.
func GetLogLevel() LogLevel {
	if IsDebug() {
		return Debug
	}
	logLevel := os.Getenv("VPNUI_LOG_LEVEL")
	if logLevel == "" {
		return Info
	}
	return LogLevel(logLevel)
}

// IsDebug returns true if debug mode is enabled via the VPNUI_DEBUG environment variable.
func IsDebug() bool {
	return os.Getenv("VPNUI_DEBUG") == "true"
}

// GetBinFolderPath returns the path to the binary folder, defaulting to "bin" if not set via VPNUI_BIN_FOLDER.
func GetBinFolderPath() string {
	binFolderPath := os.Getenv("VPNUI_BIN_FOLDER")
	if binFolderPath == "" {
		binFolderPath = "bin"
	}
	return binFolderPath
}

func getBaseDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return "."
	}
	exeDir := filepath.Dir(exePath)
	exeDirLower := strings.ToLower(filepath.ToSlash(exeDir))
	if strings.Contains(exeDirLower, "/appdata/local/temp/") || strings.Contains(exeDirLower, "/go-build") {
		wd, err := os.Getwd()
		if err != nil {
			return "."
		}
		return wd
	}
	return exeDir
}

// GetDBFolderPath returns the folder that holds the database file. It defaults to
// the directory of the binary (overridable with VPNUI_DB_FOLDER) so a copied or
// moved install carries its data with it, rather than silently sharing a fixed
// /etc/vpn-ui. Legacy installs are migrated from LegacyDBPath on first init.
func GetDBFolderPath() string {
	dbFolderPath := os.Getenv("VPNUI_DB_FOLDER")
	if dbFolderPath != "" {
		return dbFolderPath
	}
	return getBaseDir()
}

// dbBaseName is the database file's base name (without extension). It is fixed
// rather than derived from GetName() so the on-disk DB is always "vpn-ui.db".
const dbBaseName = "vpn-ui"

// GetDBPath returns the full path to the database file (next to the binary).
func GetDBPath() string {
	return fmt.Sprintf("%s/%s.db", GetDBFolderPath(), dbBaseName)
}

// LegacyDBPaths lists previous database names next to the binary to migrate from
// on first init when the current DB doesn't exist yet:
//   - <bindir>/x-ui.db — the prior next-to-binary name (before the vpn-ui rename)
//
// It deliberately does NOT reach into /etc/vpn-ui — a DB left there is not adopted.
// The current GetDBPath is never included. Empty on a custom VPNUI_DB_FOLDER.
func LegacyDBPaths() []string {
	if os.Getenv("VPNUI_DB_FOLDER") != "" {
		return nil
	}
	current := GetDBPath()
	var out []string
	for _, p := range []string{
		fmt.Sprintf("%s/x-ui.db", GetDBFolderPath()),
	} {
		if p != current {
			out = append(out, p)
		}
	}
	return out
}

// GetLogFolder returns the path to the log folder based on environment variables or platform defaults.
func GetLogFolder() string {
	logFolderPath := os.Getenv("VPNUI_LOG_FOLDER")
	if logFolderPath != "" {
		return logFolderPath
	}
	return "/var/log/vpn-ui"
}

// DB migration (moving/renaming a legacy database to GetDBPath) is handled
// cross-platform by database.InitDB via config.LegacyDBPaths — see migrateLegacyDB.
