package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/corebundle"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
)

// GetBinaryName returns the Xray binary filename for the current OS and architecture.
func GetBinaryName() string {
	return fmt.Sprintf("xray-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// GetBinaryPath returns the full path to the Xray binary executable, preferring
// any valid custom override under the custom binary directory.
func GetBinaryPath() string {
	return corebundle.ResolveXrayBinaryPath(config.GetBinFolderPath())
}

// GetConfigPath returns the path to the Xray configuration file in the binary folder.
func GetConfigPath() string {
	return config.GetBinFolderPath() + "/config.json"
}

// GetSpeedLimitPath returns the path to the per-account speed limit sidecar file.
//
// The rates live BESIDE config.json rather than in it: they change whenever an
// account crosses its "Limit After" threshold, and anything inside the Config graph
// makes Config.Equals report a change, which restarts Xray and drops every live
// connection on the box. The patched core watches this file's mtime instead, so a
// rate change costs a reload of one small JSON document.
func GetSpeedLimitPath() string {
	return config.GetBinFolderPath() + "/speedlimits.json"
}

// GetGeositePath returns the path to the geosite data file used by Xray.
func GetGeositePath() string {
	return config.GetBinFolderPath() + "/geosite.dat"
}

// GetGeoipPath returns the path to the geoip data file used by Xray.
func GetGeoipPath() string {
	return config.GetBinFolderPath() + "/geoip.dat"
}

// GetIPLimitLogPath returns the path to the IP limit log file.
func GetIPLimitLogPath() string {
	return config.GetLogFolder() + "/3xipl.log"
}

// GetIPLimitBannedLogPath returns the path to the banned IP log file.
func GetIPLimitBannedLogPath() string {
	return config.GetLogFolder() + "/3xipl-banned.log"
}

// GetIPLimitBannedPrevLogPath returns the path to the previous banned IP log file.
func GetIPLimitBannedPrevLogPath() string {
	return config.GetLogFolder() + "/3xipl-banned.prev.log"
}

// GetAccessPersistentLogPath returns the path to the persistent access log file.
func GetAccessPersistentLogPath() string {
	return config.GetLogFolder() + "/3xipl-ap.log"
}

// GetAccessPersistentPrevLogPath returns the path to the previous persistent access log file.
func GetAccessPersistentPrevLogPath() string {
	return config.GetLogFolder() + "/3xipl-ap.prev.log"
}

// GetAccessLogPath reads the Xray config and returns the access log file path.
func GetAccessLogPath() (string, error) {
	config, err := os.ReadFile(GetConfigPath())
	if err != nil {
		logger.Warningf("Failed to read configuration file: %s", err)
		return "", err
	}

	jsonConfig := map[string]any{}
	err = json.Unmarshal([]byte(config), &jsonConfig)
	if err != nil {
		logger.Warningf("Failed to parse JSON configuration: %s", err)
		return "", err
	}

	if jsonConfig["log"] != nil {
		jsonLog := jsonConfig["log"].(map[string]any)
		if jsonLog["access"] != nil {
			accessLogPath := jsonLog["access"].(string)
			return accessLogPath, nil
		}
	}
	return "", err
}

// AccessLogEnabled reports whether Xray is configured to write an access log at all.
// "none" is Xray's own spelling of "disabled" and is the shipped default (see
// web/service/config.json), so an empty or "none" path is the answer rather than a
// failure. Anything that reads that file needs this to tell "the log is off" apart from
// "the log is on and has nothing in it yet", which it otherwise cannot.
func AccessLogEnabled() bool {
	p, err := GetAccessLogPath()
	if err != nil {
		return false
	}
	return p != "" && p != "none"
}

// stopProcess calls Stop on the given Process instance.
func stopProcess(p *Process) {
	p.Stop()
}

// Process wraps an Xray process instance and provides management methods.
type Process struct {
	*process
}

// NewProcess creates a new Xray process and sets up cleanup on garbage collection.
func NewProcess(xrayConfig *Config) *Process {
	p := &Process{newProcess(xrayConfig)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

// NewTestProcess creates a new Xray process that uses a specific config file path.
// Used for test runs (e.g. outbound test) so the main config.json is not overwritten.
// The config file at configPath is removed when the process is stopped.
func NewTestProcess(xrayConfig *Config, configPath string) *Process {
	p := &Process{newTestProcess(xrayConfig, configPath)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

type process struct {
	mu  sync.Mutex
	cmd *exec.Cmd

	version string
	apiPort int

	onlineClients []string
	// onlineMemberships is the same tick's liveness, per (inbound, account) rather
	// than per account: "<inboundId>:<email>", with inbound 0 for a session whose
	// source inbound the collector could not name. Held here beside onlineClients
	// because both are derived from one traffic tick and neither survives a restart
	// (nothing persists liveness; the next tick rebuilds it in full).
	onlineMemberships []string

	config     *Config
	configPath string // if set, use this path instead of GetConfigPath() and remove on Stop
	logWriter  *LogWriter
	exitErr    error
	done       chan struct{}
	startTime  time.Time
}

// newProcess creates a new internal process struct for Xray.
func newProcess(config *Config) *process {
	return &process{
		version:   "Unknown",
		config:    config,
		logWriter: NewLogWriter(),
		startTime: time.Now(),
	}
}

// newTestProcess creates a process that writes and runs with a specific config path.
func newTestProcess(config *Config, configPath string) *process {
	p := newProcess(config)
	p.configPath = configPath
	return p
}

// IsRunning returns true if the Xray process is currently running.
func (p *process) IsRunning() bool {
	p.mu.Lock()
	cmd := p.cmd
	done := p.done
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return false
	}
	if done != nil {
		select {
		case <-done:
			return false
		default:
			return true
		}
	}
	return cmd.ProcessState == nil
}

// GetErr returns the last error encountered by the Xray process.
func (p *process) GetErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitErr
}

// GetResult returns the last log line or error from the Xray process.
func (p *process) GetResult() string {
	p.mu.Lock()
	exitErr := p.exitErr
	p.mu.Unlock()
	lastLine := p.logWriter.LastLine()
	if len(lastLine) == 0 && exitErr != nil {
		return exitErr.Error()
	}
	return lastLine
}

// GetVersion returns the version string of the Xray process.
func (p *process) GetVersion() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// GetAPIPort returns the API port used by the Xray process.
//
// Nil-safe on purpose. The package global this is called through is nil until a
// core has been started, and of its call sites in web/service only about half
// check that first, so the rest panicked on a panel whose core never came up
// (a config the core refused, a missing binary, a port conflict). A panic there
// is not a failed request, it kills the panel process on the request goroutine.
//
// 0 is the right answer for "no API to talk to": XrayAPI.Init refuses that port
// before it dials, and the handler methods then report that they are not
// connected rather than dereferencing a client that was never built.
func (p *Process) GetAPIPort() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.apiPort
}

// GetConfig returns the configuration used by the Xray process.
func (p *process) GetConfig() *Config {
	return p.config
}

// GetOnlineClients returns the list of online clients for the Xray process.
func (p *process) GetOnlineClients() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.onlineClients...)
}

// SetOnlineClients sets the list of online clients for the Xray process.
func (p *process) SetOnlineClients(users []string) {
	p.mu.Lock()
	p.onlineClients = append([]string(nil), users...)
	p.mu.Unlock()
}

// GetOnlineMemberships returns which (inbound, account) pairs the last tick saw
// traffic for, as "<inboundId>:<email>".
func (p *process) GetOnlineMemberships() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.onlineMemberships...)
}

// SetOnlineMemberships records which (inbound, account) pairs the last tick saw
// traffic for.
func (p *process) SetOnlineMemberships(pairs []string) {
	p.mu.Lock()
	p.onlineMemberships = append([]string(nil), pairs...)
	p.mu.Unlock()
}

// GetUptime returns the uptime of the Xray process in seconds.
func (p *Process) GetUptime() uint64 {
	p.mu.Lock()
	startTime := p.startTime
	p.mu.Unlock()
	return uint64(time.Since(startTime).Seconds())
}

// refreshAPIPort updates the API port from the inbound configs.
func (p *process) refreshAPIPort() {
	apiPort := 0
	for _, inbound := range p.config.InboundConfigs {
		if inbound.Tag == "api" {
			apiPort = inbound.Port
			break
		}
	}
	p.mu.Lock()
	p.apiPort = apiPort
	p.mu.Unlock()
}

// refreshVersion updates the version string by running the Xray binary with -version.
func (p *process) refreshVersion() {
	cmd := exec.Command(GetBinaryPath(), "-version")
	data, err := cmd.Output()
	ver := "Unknown"
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			ver = fields[1]
		}
	}
	p.mu.Lock()
	p.version = ver
	p.mu.Unlock()
}

// setEnvOverrides replaces or appends KEY=VALUE pairs cleanly without creating duplicates.
func setEnvOverrides(baseEnv []string, overrides ...string) []string {
	out := make([]string, 0, len(baseEnv)+len(overrides))
	overrideKeys := make(map[string]struct{}, len(overrides))
	for _, ov := range overrides {
		if k, _, ok := strings.Cut(ov, "="); ok {
			overrideKeys[k] = struct{}{}
		}
	}
	for _, entry := range baseEnv {
		if k, _, ok := strings.Cut(entry, "="); ok {
			if _, replaced := overrideKeys[k]; replaced {
				continue
			}
		}
		out = append(out, entry)
	}
	return append(out, overrides...)
}

// Start launches the Xray process with the current configuration.
func (p *process) Start() (err error) {
	if p.IsRunning() {
		return errors.New("xray is already running")
	}

	defer func() {
		if err != nil {
			logger.Error("Failure in running xray-core process: ", err)
			p.mu.Lock()
			p.exitErr = err
			p.mu.Unlock()
		}
	}()

	data, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return common.NewErrorf("Failed to generate XRAY configuration files: %v", err)
	}

	err = os.MkdirAll(config.GetLogFolder(), 0o770)
	if err != nil {
		logger.Warningf("Failed to create log folder: %s", err)
	}

	configPath := GetConfigPath()
	if p.configPath != "" {
		configPath = p.configPath
	}
	err = os.WriteFile(configPath, data, 0o640)
	if err != nil {
		return common.NewErrorf("Failed to write configuration file: %v", err)
	}

	cmd := exec.Command(GetBinaryPath(), "-c", configPath)

	// Hand the speed limit sidecar and asset directory (geoip.dat / geosite.dat)
	// to Xray-core out of band so custom-updated binaries outside bin/ still
	// resolve geo assets cleanly.
	speedLimitPath := GetSpeedLimitPath()
	if abs, absErr := filepath.Abs(speedLimitPath); absErr == nil {
		speedLimitPath = abs
	}
	assetDir := config.GetBinFolderPath()
	if abs, absErr := filepath.Abs(assetDir); absErr == nil {
		assetDir = abs
	}
	cmd.Env = setEnvOverrides(os.Environ(),
		"XRAY_SPEEDLIMIT_FILE="+speedLimitPath,
		"XRAY_LOCATION_ASSET="+assetDir,
	)

	cmd.Stdout = p.logWriter
	cmd.Stderr = p.logWriter

	done := make(chan struct{})
	if startErr := cmd.Start(); startErr != nil {
		return startErr
	}

	p.mu.Lock()
	p.cmd = cmd
	p.done = done
	p.exitErr = nil
	p.startTime = time.Now()
	p.mu.Unlock()

	go func() {
		defer close(done)
		runErr := cmd.Wait()
		if runErr != nil {
			logger.Error("Failure in running xray-core:", runErr)
			p.mu.Lock()
			p.exitErr = runErr
			p.mu.Unlock()
		}
	}()

	p.refreshVersion()
	p.refreshAPIPort()

	return nil
}

// Stop terminates the running Xray process and waits for it to exit and release its
// listening ports (escalating SIGTERM to SIGKILL if needed) so an immediate restart
// does not race on "address already in use".
func (p *process) Stop() error {
	if !p.IsRunning() {
		return errors.New("xray is not running")
	}

	// Remove temporary config file used for test runs so main config is never touched
	if p.configPath != "" {
		if p.configPath != GetConfigPath() {
			// Check if file exists before removing
			if _, err := os.Stat(p.configPath); err == nil {
				_ = os.Remove(p.configPath)
			}
		}
	}

	p.mu.Lock()
	cmd := p.cmd
	done := p.done
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	sigErr := cmd.Process.Signal(syscall.SIGTERM)
	if sigErr != nil {
		// Windows (and non-POSIX targets) don't implement SIGTERM; fall back to Kill.
		sigErr = cmd.Process.Kill()
	}

	if done != nil {
		select {
		case <-done:
			return sigErr
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
		}
	}
	return sigErr
}

// writeCrashReport writes a crash report to the binary folder with a timestamped filename.
func writeCrashReport(m []byte) error {
	crashReportPath := config.GetBinFolderPath() + "/core_crash_" + time.Now().Format("20060102_150405") + ".log"
	return os.WriteFile(crashReportPath, m, 0o640)
}
