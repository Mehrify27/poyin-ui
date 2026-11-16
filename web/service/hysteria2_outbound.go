package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"

	"github.com/goccy/go-json"
)

const (
	hy2OutboundsSettingKey = "hy2Outbounds"
	hy2OutProcPrefix       = "hy2-out-"
	hy2OutPortFirst        = 11310
	hy2OutPortLast         = 11809
)

// Hysteria2OutboundService manages sing-box-backed Hysteria 2 client outbounds.
// Each configured tunnel runs an isolated supervised sing-box instance exposing a
// loopback SOCKS5 proxy on 127.0.0.1:SocksPort, fronted in Xray by a synthesized
// `socks` outbound carrying the tunnel's Tag so routing rules, dialerProxy chains,
// and outbound latency tests work identically to SSH/VPN tunnels.
type Hysteria2OutboundService struct{}

// Hysteria2OutboundConfig defines one Hysteria 2 client outbound tunnel.
// Secrets (Password, ObfsPassword) are persisted in settings and stripped by List().
type Hysteria2OutboundConfig struct {
	Tag            string   `json:"tag" form:"tag"`
	Remark         string   `json:"remark,omitempty" form:"remark"`
	Address        string   `json:"address" form:"address"`
	Port           int      `json:"port" form:"port"`
	HopPorts       string   `json:"hopPorts,omitempty" form:"hopPorts"`
	HopInterval    string   `json:"hopInterval,omitempty" form:"hopInterval"`
	Password       string   `json:"password" form:"password"`
	ObfsType       string   `json:"obfsType,omitempty" form:"obfsType"`
	ObfsPassword   string   `json:"obfsPassword,omitempty" form:"obfsPassword"`
	UpMbps         int      `json:"upMbps,omitempty" form:"upMbps"`
	DownMbps       int      `json:"downMbps,omitempty" form:"downMbps"`
	ServerName     string   `json:"serverName,omitempty" form:"serverName"`
	Alpn           []string `json:"alpn,omitempty" form:"alpn"`
	AllowInsecure  bool     `json:"allowInsecure,omitempty" form:"allowInsecure"`
	PinSHA256      string   `json:"pinSHA256,omitempty" form:"pinSHA256"`
	CertificatePEM string   `json:"certificatePEM,omitempty" form:"certificatePEM"`
	SocksPort      int      `json:"socksPort" form:"socksPort"`
	Via            string   `json:"via,omitempty" form:"via"`
}

var hy2OutCfgMu sync.Mutex

func sanitizeHy2Tag(tag string) string {
	var b strings.Builder
	altered := false
	for _, r := range tag {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
			altered = true
		}
	}
	clean := b.String()
	if clean == "" {
		clean = "hy2"
		altered = true
	}
	if len(clean) > 48 {
		clean = clean[:48]
		altered = true
	}
	if altered {
		sum := sha256.Sum256([]byte(tag))
		clean += "-" + hex.EncodeToString(sum[:4])
	}
	return clean
}

func hy2OutProcName(tag string) string {
	return hy2OutProcPrefix + sanitizeHy2Tag(tag)
}

func (s *Hysteria2OutboundService) configDir(tag string) string {
	return filepath.Join(hysteria2ConfigBase, "outbound-"+sanitizeHy2Tag(tag))
}

func (s *Hysteria2OutboundService) configPath(tag string) string {
	return filepath.Join(s.configDir(tag), "config.json")
}

// InitHy2Outbound starts all persisted Hysteria 2 client outbound tunnels at boot.
func (s *Hysteria2OutboundService) InitHy2Outbound() {
	list := s.load()
	if len(list) == 0 {
		return
	}
	if !daemonInstalled("sing-box") {
		logger.Warning("hysteria2 outbound: sing-box binary is not installed; skipping", len(list), "configured tunnel(s)")
		return
	}
	bin := daemonBin("sing-box")
	for _, cfg := range list {
		if err := s.startDaemon(bin, cfg); err != nil {
			logger.Warning("hysteria2 outbound: failed to start", cfg.Tag, "on loopback port", cfg.SocksPort, ":", err)
		}
	}
}

// List returns configured Hysteria 2 outbounds with secret credentials stripped.
func (s *Hysteria2OutboundService) List() []Hysteria2OutboundConfig {
	list := s.load()
	out := make([]Hysteria2OutboundConfig, len(list))
	for i, c := range list {
		c.Password = ""
		c.ObfsPassword = ""
		out[i] = c
	}
	return out
}

// Save validates, persists, starts, and synchronizes a Hysteria 2 outbound tunnel.
func (s *Hysteria2OutboundService) Save(cfg Hysteria2OutboundConfig) (Hysteria2OutboundConfig, error) {
	hy2OutCfgMu.Lock()
	defer hy2OutCfgMu.Unlock()

	all := s.load()
	prepared, nextList, err := prepareHy2OutboundSave(cfg, all, allocateFreeLoopbackPort)
	if err != nil {
		return cfg, err
	}

	if err := s.checkViaCycle(prepared); err != nil {
		return cfg, err
	}

	if !daemonInstalled("sing-box") {
		return cfg, common.NewError("sing-box binary is not installed")
	}

	bin := daemonBin("sing-box")
	if err := s.startDaemon(bin, prepared); err != nil {
		return cfg, err
	}

	if err := s.persist(nextList); err != nil {
		_ = GetProcManager().Stop(hy2OutProcName(prepared.Tag))
		_ = os.RemoveAll(s.configDir(prepared.Tag))
		return cfg, err
	}

	syncHy2OutboundToTemplate(prepared, false)
	reconcileAllVpnCarriers()
	(&XrayService{}).SetToNeedRestart()

	prepared.Password = ""
	prepared.ObfsPassword = ""
	return prepared, nil
}

// Delete removes a Hysteria 2 outbound tunnel, stops its daemon, and updates Xray/routing state.
func (s *Hysteria2OutboundService) Delete(tag string) error {
	hy2OutCfgMu.Lock()
	defer hy2OutCfgMu.Unlock()

	tag = strings.TrimSpace(tag)
	all := s.load()
	out := make([]Hysteria2OutboundConfig, 0, len(all))
	for _, c := range all {
		if c.Tag != tag {
			out = append(out, c)
		}
	}
	if err := s.persist(out); err != nil {
		return err
	}

	syncHy2OutboundToTemplate(Hysteria2OutboundConfig{Tag: tag}, true)
	_ = GetProcManager().Stop(hy2OutProcName(tag))
	_ = os.RemoveAll(s.configDir(tag))
	reconcileAllVpnCarriers()
	(&XrayService{}).SetToNeedRestart()
	return nil
}

// Status reports whether a Hysteria 2 outbound daemon is running plus its recent logs.
func (s *Hysteria2OutboundService) Status(tag string) (bool, string) {
	pm := GetProcManager()
	name := hy2OutProcName(strings.TrimSpace(tag))
	return pm.IsRunning(name), pm.Logs(name)
}

// StopAll stops all supervised Hysteria 2 outbound daemons.
func (s *Hysteria2OutboundService) StopAll() {
	GetProcManager().StopByPrefix(hy2OutProcPrefix)
}

// RestartAll restarts all configured Hysteria 2 outbound daemons (e.g. after a sing-box binary update).
func (s *Hysteria2OutboundService) RestartAll() error {
	s.StopAll()
	list := s.load()
	if len(list) == 0 {
		return nil
	}
	if !daemonInstalled("sing-box") {
		return common.NewError("sing-box binary is not installed")
	}
	bin := daemonBin("sing-box")
	for _, cfg := range list {
		if err := s.startDaemon(bin, cfg); err != nil {
			return err
		}
	}
	return nil
}

func (s *Hysteria2OutboundService) load() []Hysteria2OutboundConfig {
	var settingService SettingService
	raw, err := settingService.getString(hy2OutboundsSettingKey)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []Hysteria2OutboundConfig
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		logger.Warning("hysteria2 outbound: bad hy2Outbounds setting:", err)
		return nil
	}
	return out
}

func (s *Hysteria2OutboundService) persist(list []Hysteria2OutboundConfig) error {
	var settingService SettingService
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return settingService.setString(hy2OutboundsSettingKey, string(b))
}

func (s *Hysteria2OutboundService) startDaemon(bin string, cfg Hysteria2OutboundConfig) error {
	rendered, err := buildHy2OutboundSingboxConfig(cfg)
	if err != nil {
		return err
	}
	dir := s.configDir(cfg.Tag)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create hysteria2 outbound config dir: %w", err)
	}
	cfgPath := s.configPath(cfg.Tag)
	changed, err := writeFileIfChangedCheck(cfgPath, rendered, 0o600)
	if err != nil {
		return fmt.Errorf("write hysteria2 outbound config: %w", err)
	}
	pm := GetProcManager()
	procName := hy2OutProcName(cfg.Tag)
	if pm.IsRunning(procName) && !changed {
		return nil
	}
	if err := pm.Start(procName, bin, []string{"run", "-c", cfgPath}, nil, dir); err != nil {
		return err
	}
	return nil
}

func (s *Hysteria2OutboundService) checkViaCycle(cfg Hysteria2OutboundConfig) error {
	if cfg.Via == "" {
		return nil
	}
	if cfg.Via == cfg.Tag {
		return fmt.Errorf("outbound %q cannot carry itself", cfg.Tag)
	}
	tunnels := (&VpnOutboundService{}).List()
	sshList := (&SshOutboundService{}).List()
	hy2List := s.load()
	replaced := false
	for i := range hy2List {
		if hy2List[i].Tag == cfg.Tag {
			hy2List[i] = cfg
			replaced = true
			break
		}
	}
	if !replaced {
		hy2List = append(hy2List, cfg)
	}
	carriers, _ := vpnOutCarrierPlanFull(tunnels, sshList, hy2List, vpnOutTemplateOutbounds())
	return vpnOutViaCheck(tunnels, vpnOutCarrierExtras(carriers), VpnOutboundConfig{
		Tag: cfg.Tag,
		Via: cfg.Via,
	})
}

func findHy2Tunnel(list []Hysteria2OutboundConfig, tag string) (Hysteria2OutboundConfig, bool) {
	for _, c := range list {
		if c.Tag == tag {
			return c, true
		}
	}
	return Hysteria2OutboundConfig{}, false
}

// hy2OutKeepStored preserves Password, ObfsPassword, and allocated SocksPort across UI edits
// where List() returned masked blank secrets, while never merging Via/TLS/hop fields so clearing
// them in the form deletes them properly.
func hy2OutKeepStored(cfg, prev Hysteria2OutboundConfig) Hysteria2OutboundConfig {
	if cfg.Password == "" {
		cfg.Password = prev.Password
	}
	if cfg.ObfsType != "" && cfg.ObfsPassword == "" {
		cfg.ObfsPassword = prev.ObfsPassword
	}
	if cfg.SocksPort <= 0 {
		cfg.SocksPort = prev.SocksPort
	}
	return cfg
}

func prepareHy2OutboundSave(cfg Hysteria2OutboundConfig, all []Hysteria2OutboundConfig, portAlloc func(used map[int]bool) (int, error)) (Hysteria2OutboundConfig, []Hysteria2OutboundConfig, error) {
	cfg.Tag = strings.TrimSpace(cfg.Tag)
	cfg.Remark = strings.TrimSpace(cfg.Remark)
	cfg.Address = strings.TrimSpace(cfg.Address)
	cfg.HopPorts = strings.TrimSpace(cfg.HopPorts)
	cfg.HopInterval = strings.TrimSpace(cfg.HopInterval)
	cfg.ObfsType = strings.ToLower(strings.TrimSpace(cfg.ObfsType))
	if cfg.ObfsType == "none" {
		cfg.ObfsType = ""
	}
	cfg.ServerName = strings.TrimSpace(cfg.ServerName)
	cfg.PinSHA256 = normalizeCertPin(cfg.PinSHA256)
	cfg.CertificatePEM = strings.TrimSpace(cfg.CertificatePEM)
	cfg.Via = strings.TrimSpace(cfg.Via)

	if cfg.Tag == "" {
		return cfg, nil, errors.New("tag is required")
	}
	if cfg.Address == "" {
		return cfg, nil, errors.New("address is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 443
	}
	if cfg.Port > 65535 {
		return cfg, nil, errors.New("port must be between 1 and 65535")
	}
	if cfg.HopPorts != "" {
		if err := validatePortListOrRange(cfg.HopPorts); err != nil {
			return cfg, nil, fmt.Errorf("invalid hopPorts (%q): %w", cfg.HopPorts, err)
		}
	}
	if cfg.HopInterval != "" {
		d, err := time.ParseDuration(cfg.HopInterval)
		if err != nil || d <= 0 {
			return cfg, nil, fmt.Errorf("invalid hopInterval (%q): must be a positive Go duration like 30s", cfg.HopInterval)
		}
	}
	if cfg.UpMbps < 0 || cfg.DownMbps < 0 {
		return cfg, nil, errors.New("upMbps and downMbps must not be negative")
	}
	switch cfg.ObfsType {
	case "", "salamander", "gecko":
	default:
		return cfg, nil, fmt.Errorf("unsupported obfsType %q (allowed: none, salamander)", cfg.ObfsType)
	}
	if cfg.ObfsType == "" {
		cfg.ObfsPassword = ""
	}
	if cfg.SocksPort > 65535 || (cfg.SocksPort > 0 && cfg.SocksPort < 1024) {
		return cfg, nil, errors.New("local socks port must be between 1024 and 65535")
	}

	if prev, hadPrev := findHy2Tunnel(all, cfg.Tag); hadPrev {
		cfg = hy2OutKeepStored(cfg, prev)
	}

	if strings.TrimSpace(cfg.Password) == "" {
		return cfg, nil, errors.New("password is required")
	}
	if cfg.ObfsType != "" && strings.TrimSpace(cfg.ObfsPassword) == "" {
		return cfg, nil, errors.New("obfsPassword is required when obfuscation is enabled")
	}

	usedPorts := make(map[int]bool, len(all))
	out := make([]Hysteria2OutboundConfig, 0, len(all)+1)
	for _, c := range all {
		if c.Tag == cfg.Tag {
			continue
		}
		if c.SocksPort > 0 {
			usedPorts[c.SocksPort] = true
		}
		if cfg.SocksPort > 0 && c.SocksPort == cfg.SocksPort {
			return cfg, nil, fmt.Errorf("local socks port %d is already used by outbound %q", cfg.SocksPort, c.Tag)
		}
		out = append(out, c)
	}

	if cfg.SocksPort <= 0 {
		port, err := portAlloc(usedPorts)
		if err != nil {
			return cfg, nil, err
		}
		cfg.SocksPort = port
	}

	out = append(out, cfg)
	return cfg, out, nil
}

func allocateFreeLoopbackPort(used map[int]bool) (int, error) {
	for port := hy2OutPortFirst; port <= hy2OutPortLast; port++ {
		if used[port] {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no free loopback port available in %d-%d", hy2OutPortFirst, hy2OutPortLast)
}

// formatSingboxServerPorts converts UI/URI port-hop expressions like "443,20000-20100"
// into sing-box's colon-separated `server_ports` syntax (`["443", "20000:20100"]`).
func formatSingboxServerPorts(hopPorts string) []string {
	var out []string
	for _, token := range strings.Split(hopPorts, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			out = append(out, strings.TrimSpace(parts[0])+":"+strings.TrimSpace(parts[1]))
		} else {
			out = append(out, token)
		}
	}
	return out
}

// buildHy2OutboundSingboxConfig builds the standalone sing-box JSON document that
// accepts local SOCKS5 traffic on 127.0.0.1:SocksPort and relays it over Hysteria 2.
func buildHy2OutboundSingboxConfig(cfg Hysteria2OutboundConfig) ([]byte, error) {
	if cfg.SocksPort <= 0 {
		return nil, errors.New("hysteria2 outbound requires a valid local SocksPort")
	}

	alpn := make([]string, 0, len(cfg.Alpn))
	for _, a := range cfg.Alpn {
		if trimmed := strings.TrimSpace(a); trimmed != "" {
			alpn = append(alpn, trimmed)
		}
	}
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}

	tlsCfg := map[string]any{
		"enabled": true,
		"alpn":    alpn,
	}
	if cfg.ServerName != "" {
		tlsCfg["server_name"] = cfg.ServerName
	}
	if cfg.AllowInsecure {
		tlsCfg["insecure"] = true
	}
	if cfg.CertificatePEM != "" {
		tlsCfg["certificate"] = []string{cfg.CertificatePEM}
	}

	hy2Outbound := map[string]any{
		"type":     "hysteria2",
		"tag":      "proxy",
		"server":   cfg.Address,
		"password": cfg.Password,
		"tls":      tlsCfg,
	}

	serverPorts := formatSingboxServerPorts(cfg.HopPorts)
	if len(serverPorts) > 0 {
		hy2Outbound["server_ports"] = serverPorts
		if cfg.HopInterval != "" {
			hy2Outbound["hop_interval"] = cfg.HopInterval
		}
	} else {
		port := cfg.Port
		if port <= 0 {
			port = 443
		}
		hy2Outbound["server_port"] = port
	}

	if cfg.UpMbps > 0 {
		hy2Outbound["up_mbps"] = cfg.UpMbps
	}
	if cfg.DownMbps > 0 {
		hy2Outbound["down_mbps"] = cfg.DownMbps
	}
	if cfg.ObfsType != "" {
		hy2Outbound["obfs"] = map[string]any{
			"type":     cfg.ObfsType,
			"password": cfg.ObfsPassword,
		}
	}

	doc := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"inbounds": []map[string]any{
			{
				"type":        "socks",
				"tag":         "hy2-socks-in",
				"listen":      "127.0.0.1",
				"listen_port": cfg.SocksPort,
			},
		},
		"outbounds": []map[string]any{
			hy2Outbound,
			{
				"type": "direct",
				"tag":  "direct",
			},
		},
		"route": map[string]any{
			"final": "proxy",
		},
	}

	rendered, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	rendered = append(rendered, '\n')
	return rendered, nil
}
