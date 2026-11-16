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
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/corebundle"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/binutil"
)

const maxCoreArtifactBytes = 512 << 20 // 512 MiB cap against truncated/malicious archives

// githubReleaseAPIBase can be overridden in unit tests.
var githubReleaseAPIBase = "https://api.github.com"

// CoreUpdateSpec describes a sidecar core/daemon binary that can be inspected,
// updated independently of vpn-ui, and rolled back atomically.
type CoreUpdateSpec struct {
	Target             string
	ServiceCore        string
	GithubRepo         string
	VersionArgs        []string
	ArchiveBinaryNames []string
	CustomFileFunc     func() string
	BundledPathFunc    func() string
	ActivePathFunc     func() string
}

// CoreBinaryInfo reports active/bundled/override paths and metadata for one
// managed binary.
type CoreBinaryInfo struct {
	Core        string `json:"core"`
	ServiceCore string `json:"serviceCore"`
	ActivePath  string `json:"activePath"`
	BundledPath string `json:"bundledPath"`
	CustomPath  string `json:"customPath"`
	CustomDir   string `json:"customDir"`
	Source      string `json:"source"` // custom-override | bundled | host-path | missing
	Version     string `json:"version"`
	SHA256      string `json:"sha256,omitempty"`
	HasBackup   bool   `json:"hasBackup"`
}

// CoreUpdateOptions configures an independent sidecar binary update or rollback.
type CoreUpdateOptions struct {
	Target           string
	URL              string
	File             string
	Version          string
	SHA256           string
	RestartFunc      func(serviceCore string) error
	VerifyHealthFunc func(spec CoreUpdateSpec, destPath string) error
}

// CoreUpdateResult reports the outcome of updating or rolling back one target.
type CoreUpdateResult struct {
	Target      string `json:"target"`
	ServiceCore string `json:"serviceCore"`
	DestPath    string `json:"destPath"`
	BackupPath  string `json:"backupPath,omitempty"`
	Source      string `json:"source"`
	Version     string `json:"version,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Restarted   bool   `json:"restarted"`
	RolledBack  bool   `json:"rolledBack"`
	Status      string `json:"status"` // updated | rolled_back | skipped
	Message     string `json:"message"`
}

var managedCoreUpdateSpecs = []CoreUpdateSpec{
	{
		Target:             "xray",
		ServiceCore:        "xray",
		GithubRepo:         "XTLS/Xray-core",
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
		GithubRepo:         "telemt/telemt",
		VersionArgs:        []string{"--version"},
		ArchiveBinaryNames: []string{"telemt"},
		CustomFileFunc:     func() string { return "telemt" },
		BundledPathFunc:    func() string { return backend.BundledDaemonPath("telemt") },
		ActivePathFunc:     func() string { return resolveDaemonOrHost("telemt") },
	},
	{
		Target:             "sing-box",
		ServiceCore:        "hysteria2",
		GithubRepo:         "SagerNet/sing-box",
		VersionArgs:        []string{"version"},
		ArchiveBinaryNames: []string{"sing-box"},
		CustomFileFunc:     func() string { return "sing-box" },
		BundledPathFunc:    func() string { return backend.BundledDaemonPath("sing-box") },
		ActivePathFunc:     func() string { return resolveDaemonOrHost("sing-box") },
	},
	{
		Target:             "amneziawg-go",
		ServiceCore:        "awg",
		GithubRepo:         "amnezia-vpn/amneziawg-go",
		VersionArgs:        []string{"--version"},
		ArchiveBinaryNames: []string{"amneziawg-go"},
		CustomFileFunc:     func() string { return "amneziawg-go" },
		BundledPathFunc:    func() string { return backend.BundledDaemonPath("amneziawg-go") },
		ActivePathFunc:     func() string { return resolveDaemonOrHost("amneziawg-go") },
	},
	{
		Target:             "ocserv",
		ServiceCore:        "openconnect",
		GithubRepo:         "",
		VersionArgs:        []string{"--version"},
		ArchiveBinaryNames: []string{"ocserv"},
		CustomFileFunc:     func() string { return "ocserv" },
		BundledPathFunc:    func() string { return backend.BundledDaemonPath("ocserv") },
		ActivePathFunc:     func() string { return resolveDaemonOrHost("ocserv") },
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

// GetCoreBinaryInventory reports active paths, bundled paths, override status,
// backups, and detected versions for all managed sidecar binaries.
func (s *CoreService) GetCoreBinaryInventory() []CoreBinaryInfo {
	customDir := binutil.CustomBinDir()
	out := make([]CoreBinaryInfo, 0, len(managedCoreUpdateSpecs))
	for _, spec := range managedCoreUpdateSpecs {
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

		_, bakErr := os.Stat(customPath + ".bak")
		info := CoreBinaryInfo{
			Core:        spec.Target,
			ServiceCore: spec.ServiceCore,
			ActivePath:  activePath,
			BundledPath: bundledPath,
			CustomPath:  customPath,
			CustomDir:   customDir,
			Source:      source,
			HasBackup:   bakErr == nil,
		}
		if activePath != "" {
			info.Version = probeBinaryVersion(activePath, spec.VersionArgs)
			if sum, err := binutil.FileSHA256(activePath); err == nil {
				info.SHA256 = sum
			}
		}
		out = append(out, info)
	}
	return out
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
		if norm == "all" && spec.GithubRepo == "" {
			results = append(results, CoreUpdateResult{
				Target:      spec.Target,
				ServiceCore: spec.ServiceCore,
				Status:      "skipped",
				Message:     "no automatic upstream release source configured; update with --file or --url",
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

	switch {
	case strings.TrimSpace(opts.File) != "":
		artifactPath = strings.TrimSpace(opts.File)
		sourceLabel = "local-file"
	case strings.TrimSpace(opts.URL) != "":
		dlURL := strings.TrimSpace(opts.URL)
		sourceLabel = dlURL
		artifactPath = filepath.Join(tmpDir, archiveFilenameFromURL(dlURL))
		if err := downloadArtifact(dlURL, artifactPath); err != nil {
			return res, fmt.Errorf("download %s: %w", spec.Target, err)
		}
	default:
		if spec.GithubRepo == "" {
			return res, fmt.Errorf("%s has no upstream release repository; provide --url or --file", spec.Target)
		}
		dlURL, ghDigest, resolvedTag, err := resolveGithubReleaseAsset(spec, opts.Version)
		if err != nil {
			return res, fmt.Errorf("resolve release for %s: %w", spec.Target, err)
		}
		sourceLabel = dlURL
		res.Version = resolvedTag
		if expectedSHA == "" && ghDigest != "" {
			expectedSHA = ghDigest
		}
		artifactPath = filepath.Join(tmpDir, archiveFilenameFromURL(dlURL))
		if err := downloadArtifact(dlURL, artifactPath); err != nil {
			return res, fmt.Errorf("download %s (%s): %w", spec.Target, resolvedTag, err)
		}
	}
	res.Source = sourceLabel

	if expectedSHA != "" {
		if err := binutil.VerifySHA256(artifactPath, expectedSHA); err != nil {
			return res, err
		}
	}

	stagedExec := filepath.Join(tmpDir, spec.Target+".bin")
	if err := extractExecutableFromArtifact(artifactPath, stagedExec, spec.ArchiveBinaryNames); err != nil {
		return res, fmt.Errorf("extract %s binary: %w", spec.Target, err)
	}
	if err := os.Chmod(stagedExec, 0o755); err != nil {
		return res, err
	}
	if err := binutil.ValidateELFBinary(stagedExec, runtime.GOARCH); err != nil {
		return res, fmt.Errorf("validate %s binary: %w", spec.Target, err)
	}

	sum, err := binutil.FileSHA256(stagedExec)
	if err == nil {
		res.SHA256 = sum
	}
	if ver := probeBinaryVersion(stagedExec, spec.VersionArgs); ver != "" {
		res.Version = ver
	}

	bakPath, hadPrev, err := binutil.AtomicInstallBinary(dest, stagedExec)
	if err != nil {
		return res, err
	}
	if hadPrev {
		res.BackupPath = bakPath
	}

	rollbackWithReason := func(cause error) (CoreUpdateResult, error) {
		rbErr := binutil.RestoreBinary(dest, bakPath, hadPrev)
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
		res.Source = "backup"
		res.Message = fmt.Sprintf("restored %s from backup", dest)
	} else if _, err := os.Stat(dest); err == nil {
		if err := binutil.RestoreBinary(dest, "", false); err != nil {
			return res, fmt.Errorf("remove custom override %s: %w", dest, err)
		}
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

func (s *CoreService) verifyUpdatedCoreHealth(spec CoreUpdateSpec, destPath string) error {
	// Smoke check version invocation when running on matching Linux host.
	if runtime.GOOS == "linux" && len(spec.VersionArgs) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, destPath, spec.VersionArgs...).Run(); err != nil {
			return fmt.Errorf("%s failed binary execution check: %w", spec.Target, err)
		}
	}

	if spec.ServiceCore == "xray" {
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			if errMsg := s.xrayService.GetXrayErr(); errMsg != nil {
				return fmt.Errorf("xray startup error: %w", errMsg)
			}
			if s.xrayService.IsXrayRunning() {
				time.Sleep(500 * time.Millisecond)
				if s.xrayService.IsXrayRunning() {
					return nil
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
		if errMsg := s.xrayService.GetXrayErr(); errMsg != nil {
			return fmt.Errorf("xray startup error: %w", errMsg)
		}
		return errors.New("xray process did not remain running after update")
	}

	// For sidecar daemons (telemt, sing-box, ocserv, awg), confirm the core is
	// not in a broken state when enabled inbounds exist for it.
	counts := s.inboundCountsByCore()
	if counts[spec.ServiceCore] == 0 {
		return nil
	}
	time.Sleep(1500 * time.Millisecond)
	for _, st := range s.GetCoresStatus() {
		if st.Name == spec.ServiceCore && (st.State == CoreError || st.State == CoreStopped) {
			return fmt.Errorf("core %s entered state %s (%s)", spec.ServiceCore, st.State, st.Detail)
		}
	}
	return nil
}

func resolveGithubReleaseAsset(spec CoreUpdateSpec, requestedVersion string) (downloadURL, sha256Digest, tagName string, err error) {
	base := strings.TrimRight(githubReleaseAPIBase, "/")
	ver := strings.TrimSpace(requestedVersion)
	endpoints := []string{fmt.Sprintf("%s/repos/%s/releases/latest", base, spec.GithubRepo)}
	if ver != "" {
		endpoints = []string{fmt.Sprintf("%s/repos/%s/releases/tags/%s", base, spec.GithubRepo, ver)}
		if !strings.HasPrefix(ver, "v") {
			endpoints = append(endpoints, fmt.Sprintf("%s/repos/%s/releases/tags/v%s", base, spec.GithubRepo, ver))
		}
	}

	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Digest             string `json:"digest"`
		} `json:"assets"`
	}

	client := &http.Client{Timeout: 25 * time.Second}
	var lastErr error
	for _, ep := range endpoints {
		req, rerr := http.NewRequest(http.MethodGet, ep, nil)
		if rerr != nil {
			lastErr = rerr
			continue
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "vpn-ui-core-updater")
		resp, rerr := client.Do(req)
		if rerr != nil {
			lastErr = rerr
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || rerr != nil {
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, ep)
			continue
		}
		if jerr := json.Unmarshal(body, &rel); jerr != nil {
			lastErr = jerr
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return "", "", "", lastErr
	}

	type asset struct {
		name   string
		url    string
		digest string
	}
	candidates := make([]asset, 0, len(rel.Assets))
	checksumMap := map[string]string{}
	for _, a := range rel.Assets {
		lower := strings.ToLower(a.Name)
		if strings.HasSuffix(lower, ".sha256") || strings.HasSuffix(lower, ".dgst") {
			checksumMap[lower] = a.BrowserDownloadURL
			continue
		}
		candidates = append(candidates, asset{name: a.Name, url: a.BrowserDownloadURL, digest: a.Digest})
	}

	pickedName := ""
	bestScore := -1
	for _, a := range candidates {
		score := scoreReleaseAsset(spec.Target, a.name, runtime.GOARCH)
		if score > bestScore {
			bestScore = score
			downloadURL = a.url
			sha256Digest = a.digest
			pickedName = a.name
		}
	}
	if bestScore <= 0 || downloadURL == "" {
		return "", "", rel.TagName, fmt.Errorf("no matching linux/%s asset in %s release %s", runtime.GOARCH, spec.GithubRepo, rel.TagName)
	}

	// If GitHub did not populate digest directly, look for an accompanying .dgst or .sha256 file.
	if sha256Digest == "" {
		for _, suffix := range []string{".dgst", ".sha256"} {
			if cURL, ok := checksumMap[strings.ToLower(pickedName)+suffix]; ok {
				if sum, ferr := fetchSHA256FromSidecar(client, cURL); ferr == nil {
					sha256Digest = sum
					break
				}
			}
		}
	}
	return downloadURL, sha256Digest, rel.TagName, nil
}

func scoreReleaseAsset(target, filename, goarch string) int {
	lower := strings.ToLower(filename)
	for _, skip := range []string{".sig", ".asc", ".dgst", ".sha256", ".deb", ".rpm", ".apk", ".msi", ".exe", ".dmg", "windows", "darwin", "macos", "freebsd", "android", "openbsd"} {
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
	if strings.Contains(lower, "musl") || strings.Contains(lower, "legacy") == false {
		score++
	}
	if strings.Contains(lower, "with-") || strings.Contains(lower, "naive") {
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
	hdr := make([]byte, 4)
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
		if hdr.Typeflag != tar.TypeReg {
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
