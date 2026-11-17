package service

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

const (
	hysteria2SocksPortBase    = 12300
	hysteria2ClashPortBase    = 15300
	hysteria2V2rayAPIPortBase = 16300
	hy2ProcPrefix             = "hysteria2-server-"
)

var hysteria2ConfigBase = "/etc/vpn-ui-hysteria2"

// Hysteria2Service manages sing-box-backed Hysteria 2 inbounds as supervised
// child processes alongside Xray, including certificate resolution, optional
// loopback SOCKS5 bridging into Xray, per-user gRPC traffic accounting, and
// live session/User-Limit enforcement via the Clash API.
type Hysteria2Service struct {
	inboundService InboundService
	settingService SettingService
}

// Hysteria2ExternalProxy describes an alternate endpoint (CDN, relay, port hop
// front) rendered in share links and client configs.
type Hysteria2ExternalProxy struct {
	Dest     string `json:"dest"`
	Port     int    `json:"port"`
	Remark   string `json:"remark"`
	ForceTls string `json:"forceTls,omitempty"`
}

// Hysteria2Client represents one authenticated user on a Hysteria 2 inbound.
type Hysteria2Client struct {
	ID         string `json:"id"`
	Auth       string `json:"auth"`
	Password   string `json:"password,omitempty"`
	Email      string `json:"email"`
	Enable     bool   `json:"enable"`
	ExpiryTime int64  `json:"expiryTime"`
	TotalGB    int64  `json:"totalGB"`
	Reset      int    `json:"reset"`
	SubId      string `json:"subId"`
	Comment    string `json:"comment"`
	CreatedAt  int64  `json:"created_at,omitempty"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

func (c Hysteria2Client) effectiveAuth() string {
	if strings.TrimSpace(c.Auth) != "" {
		return c.Auth
	}
	return c.Password
}

// Hysteria2Settings models the JSON Settings blob stored on a model.Hysteria2 inbound.
type Hysteria2Settings struct {
	UpMbps                int                      `json:"upMbps"`
	DownMbps              int                      `json:"downMbps"`
	IgnoreClientBandwidth bool                     `json:"ignoreClientBandwidth"`
	ObfsType              string                   `json:"obfsType"`
	ObfsPassword          string                   `json:"obfsPassword"`
	Masquerade            string                   `json:"masquerade"`
	RouteThroughXray      *bool                    `json:"routeThroughXray"`
	UserLimit             *int                     `json:"userLimit"`
	UserLimitStrategy     string                   `json:"userLimitStrategy"`
	ServerName            string                   `json:"serverName"`
	Alpn                  []string                 `json:"alpn"`
	TlsUseFile            bool                     `json:"tlsUseFile"`
	CertificateFile       string                   `json:"certificateFile"`
	CertFile              string                   `json:"certFile,omitempty"`
	KeyFile               string                   `json:"keyFile"`
	Certificate           string                   `json:"certificate"`
	Key                   string                   `json:"key"`
	AllowInsecure         bool                     `json:"allowInsecure"`
	Fingerprint           string                   `json:"fingerprint"`
	PinSHA256             string                   `json:"pinSHA256"`
	HopPorts              string                   `json:"hopPorts"`
	HopInterval           string                   `json:"hopInterval"`
	ExternalProxy         []Hysteria2ExternalProxy `json:"externalProxy"`
	Clients               []Hysteria2Client        `json:"clients"`
}

func (st Hysteria2Settings) routeViaXray() bool {
	if st.RouteThroughXray == nil {
		return true
	}
	return *st.RouteThroughXray
}

func (st Hysteria2Settings) effectiveUserLimit() int {
	if st.UserLimit == nil || *st.UserLimit < 0 {
		return 0
	}
	return *st.UserLimit
}

func (st Hysteria2Settings) effectiveStrategy() string {
	if strings.EqualFold(strings.TrimSpace(st.UserLimitStrategy), "reject") {
		return "reject"
	}
	return "accept"
}

func (st Hysteria2Settings) normalizedObfs() (string, string) {
	obfsType := strings.ToLower(strings.TrimSpace(st.ObfsType))
	if obfsType == "" || obfsType == "none" {
		return "", ""
	}
	return obfsType, st.ObfsPassword
}

func (st Hysteria2Settings) normalizedAlpn() []string {
	var out []string
	for _, raw := range st.Alpn {
		if trimmed := strings.TrimSpace(raw); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return []string{"h3"}
	}
	return out
}

type hysteria2RuntimeState struct {
	mu             sync.Mutex
	clashSecrets   map[int]string
	lastConfigHash map[int]string
	lastUserSet    map[int]map[string]bool
	prevInbound    map[int]hy2TrafficPair
	prevUsers      map[int]map[string]hy2TrafficPair
}

type hy2TrafficPair struct {
	up   int64
	down int64
}

var hy2State = &hysteria2RuntimeState{
	clashSecrets:   map[int]string{},
	lastConfigHash: map[int]string{},
	lastUserSet:    map[int]map[string]bool{},
	prevInbound:    map[int]hy2TrafficPair{},
	prevUsers:      map[int]map[string]hy2TrafficPair{},
}

func hy2ProcName(id int) string {
	return hy2ProcPrefix + strconv.Itoa(id)
}

func hy2ProcInboundID(name string) (int, bool) {
	if !strings.HasPrefix(name, hy2ProcPrefix) {
		return 0, false
	}
	id, err := strconv.Atoi(strings.TrimPrefix(name, hy2ProcPrefix))
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func (s *Hysteria2Service) configDir(inboundId int) string {
	return filepath.Join(hysteria2ConfigBase, "server-"+strconv.Itoa(inboundId))
}

func (s *Hysteria2Service) configPath(inboundId int) string {
	return filepath.Join(s.configDir(inboundId), "config.json")
}

// GetSocksPort returns the loopback SOCKS5 port bridging Hysteria 2 traffic into Xray.
func (s *Hysteria2Service) GetSocksPort(inbound *model.Inbound) int {
	return hysteria2SocksPortBase + inbound.Id
}

// GetClashAPIPort returns the loopback Clash REST controller port for an inbound.
func (s *Hysteria2Service) GetClashAPIPort(inbound *model.Inbound) int {
	return hysteria2ClashPortBase + inbound.Id
}

// GetV2rayAPIPort returns the loopback V2Ray StatsService gRPC port for an inbound.
func (s *Hysteria2Service) GetV2rayAPIPort(inbound *model.Inbound) int {
	return hysteria2V2rayAPIPortBase + inbound.Id
}

// Available reports whether the sing-box binary is installed and executable.
func (s *Hysteria2Service) Available() bool {
	return daemonInstalled("sing-box")
}

// AnyRunning reports whether at least one managed Hysteria 2 sing-box daemon is running.
func (s *Hysteria2Service) AnyRunning() bool {
	return GetProcManager().AnyRunningWithPrefix(hy2ProcPrefix)
}

// GetHysteria2Inbounds returns all enabled Hysteria 2 inbounds from the database.
func (s *Hysteria2Service) GetHysteria2Inbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	if db == nil {
		return nil, common.NewError("database not initialized")
	}
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).
		Where("protocol = ? AND enable = ?", model.Hysteria2, true).
		Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	return inbounds, nil
}

// parseSettings decodes an inbound's Settings JSON (and reads SNI/fingerprint/cert
// fallbacks from streamSettings when present so shared or migrated payloads work cleanly).
func (s *Hysteria2Service) parseSettings(inbound *model.Inbound) (Hysteria2Settings, error) {
	var settings Hysteria2Settings
	if inbound == nil {
		return settings, common.NewError("inbound is nil")
	}
	if strings.TrimSpace(inbound.Settings) != "" {
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			return settings, err
		}
	}
	if strings.TrimSpace(inbound.StreamSettings) != "" {
		var stream struct {
			TlsSettings struct {
				ServerName string   `json:"serverName"`
				Alpn       []string `json:"alpn"`
				Settings   struct {
					AllowInsecure bool   `json:"allowInsecure"`
					Fingerprint   string `json:"fingerprint"`
				} `json:"settings"`
				Certificates []struct {
					CertificateFile string `json:"certificateFile"`
					KeyFile         string `json:"keyFile"`
					Certificate     string `json:"certificate"`
					Key             string `json:"key"`
				} `json:"certificates"`
			} `json:"tlsSettings"`
			ExternalProxy []Hysteria2ExternalProxy `json:"externalProxy"`
		}
		if err := json.Unmarshal([]byte(inbound.StreamSettings), &stream); err == nil {
			if strings.TrimSpace(settings.ServerName) == "" && strings.TrimSpace(stream.TlsSettings.ServerName) != "" {
				settings.ServerName = strings.TrimSpace(stream.TlsSettings.ServerName)
			}
			if len(settings.Alpn) == 0 && len(stream.TlsSettings.Alpn) > 0 {
				settings.Alpn = stream.TlsSettings.Alpn
			}
			if !settings.AllowInsecure && stream.TlsSettings.Settings.AllowInsecure {
				settings.AllowInsecure = true
			}
			if strings.TrimSpace(settings.Fingerprint) == "" && strings.TrimSpace(stream.TlsSettings.Settings.Fingerprint) != "" {
				settings.Fingerprint = strings.TrimSpace(stream.TlsSettings.Settings.Fingerprint)
			}
			if len(settings.ExternalProxy) == 0 && len(stream.ExternalProxy) > 0 {
				settings.ExternalProxy = stream.ExternalProxy
			}
			if strings.TrimSpace(settings.CertificateFile) == "" && strings.TrimSpace(settings.CertFile) == "" && strings.TrimSpace(settings.Certificate) == "" && len(stream.TlsSettings.Certificates) > 0 {
				c := stream.TlsSettings.Certificates[0]
				if strings.TrimSpace(c.CertificateFile) != "" && strings.TrimSpace(c.KeyFile) != "" {
					settings.TlsUseFile = true
					settings.CertificateFile = c.CertificateFile
					settings.CertFile = c.CertificateFile
					settings.KeyFile = c.KeyFile
				} else if strings.TrimSpace(c.Certificate) != "" && strings.TrimSpace(c.Key) != "" {
					settings.Certificate = c.Certificate
					settings.Key = c.Key
				}
			}
		}
	}
	if strings.TrimSpace(settings.CertificateFile) == "" {
		settings.CertificateFile = settings.CertFile
	}
	return settings, nil
}

// GetSocksConfig returns the loopback SOCKS5 Xray inbound used when routeThroughXray is enabled.
func (s *Hysteria2Service) GetSocksConfig(inbound *model.Inbound) *xray.InboundConfig {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		logger.Warning("Hysteria2: parse settings for socks config failed:", err)
		return nil
	}
	if !settings.routeViaXray() {
		return nil
	}

	disabled := getDisabledAccountEmails()
	nowMs := time.Now().UnixMilli()
	var accounts []singboxSocksAccount
	for _, c := range settings.Clients {
		if !c.Enable || disabled[c.Email] {
			continue
		}
		if c.ExpiryTime > 0 && c.ExpiryTime <= nowMs {
			continue
		}
		auth := c.effectiveAuth()
		if auth == "" || strings.TrimSpace(c.Email) == "" {
			continue
		}
		accounts = append(accounts, singboxSocksAccount{User: c.Email, Pass: auth})
	}
	return buildLoopbackSocksInbound(inbound, s.GetSocksPort(inbound), accounts)
}

func (s *Hysteria2Service) getDisabledEmails() map[string]bool {
	return getDisabledAccountEmails()
}

func (s *Hysteria2Service) getOrCreateClashSecret(inboundId int) string {
	hy2State.mu.Lock()
	if sec := hy2State.clashSecrets[inboundId]; sec != "" {
		hy2State.mu.Unlock()
		return sec
	}
	hy2State.mu.Unlock()

	sec := loadOrCreateClashSecret(s.configPath(inboundId))
	hy2State.mu.Lock()
	hy2State.clashSecrets[inboundId] = sec
	hy2State.mu.Unlock()
	return sec
}

// resolveTLSCerts ensures a valid certificate and key pair on disk for an inbound
// and returns (certPath, keyPath, materialFingerprint, err).
func (s *Hysteria2Service) resolveTLSCerts(inbound *model.Inbound, settings Hysteria2Settings) (string, string, string, error) {
	return resolveSidecarTLSCerts(s.configDir(inbound.Id), sidecarTLSInput{
		ServerName:      settings.ServerName,
		Listen:          inbound.Listen,
		CertificateFile: firstNonEmptyString(settings.CertificateFile, settings.CertFile),
		KeyFile:         settings.KeyFile,
		Certificate:     settings.Certificate,
		Key:             settings.Key,
		StreamSettings:  inbound.StreamSettings,
	}, &s.settingService)
}

// ResolveCertPinSHA256 returns the lowercase colonless hex SHA-256 hash of the
// leaf certificate configured (or auto-generated) for this Hysteria 2 inbound.
func (s *Hysteria2Service) ResolveCertPinSHA256(inbound *model.Inbound) string {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return ""
	}
	if pin := normalizeCertPin(settings.PinSHA256); pin != "" {
		return pin
	}
	certPath, _, _, err := s.resolveTLSCerts(inbound, settings)
	if err != nil || certPath == "" {
		return ""
	}
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func normalizeCertPin(pin string) string {
	cleaned := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(pin), ":", ""), " ", ""))
	if strings.HasPrefix(cleaned, "sha256/") {
		cleaned = strings.TrimPrefix(cleaned, "sha256/")
	}
	return cleaned
}

func buildMasqueradeOption(raw string) any {
	m := strings.TrimSpace(raw)
	if m == "" {
		return nil
	}
	lower := strings.ToLower(m)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return map[string]any{
			"type":         "proxy",
			"url":          m,
			"rewrite_host": true,
		}
	}
	if strings.HasPrefix(lower, "file://") {
		return map[string]any{
			"type":      "file",
			"directory": strings.TrimPrefix(m, "file://"),
		}
	}
	if strings.HasPrefix(lower, "string:") {
		return map[string]any{
			"type":        "string",
			"status_code": 200,
			"headers":     map[string]string{"Content-Type": "text/plain"},
			"content":     strings.TrimPrefix(m, "string:"),
		}
	}
	return map[string]any{
		"type":         "proxy",
		"url":          "https://" + m,
		"rewrite_host": true,
	}
}

type singboxHy2User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// buildServerConfig builds the sing-box JSON configuration document for a Hysteria 2 inbound.
func (s *Hysteria2Service) buildServerConfig(inbound *model.Inbound, settings Hysteria2Settings, certPath, keyPath, clashSecret string) ([]byte, map[string]bool, error) {
	disabled := s.getDisabledEmails()
	nowMs := time.Now().UnixMilli()

	var users []singboxHy2User
	var statUsers []string
	activeUserSet := make(map[string]bool)
	for _, c := range settings.Clients {
		if !c.Enable || disabled[c.Email] {
			continue
		}
		if c.ExpiryTime > 0 && c.ExpiryTime <= nowMs {
			continue
		}
		auth := c.effectiveAuth()
		email := strings.TrimSpace(c.Email)
		if email == "" || auth == "" {
			continue
		}
		users = append(users, singboxHy2User{Name: email, Password: auth})
		statUsers = append(statUsers, email)
		activeUserSet[email] = true
	}
	if users == nil {
		users = []singboxHy2User{}
	}

	listen := strings.TrimSpace(inbound.Listen)
	if listen == "" {
		listen = "::"
	}
	tag := strings.TrimSpace(inbound.Tag)
	if tag == "" {
		tag = hy2ProcName(inbound.Id)
	}

	tlsObj := map[string]any{
		"enabled":          true,
		"alpn":             settings.normalizedAlpn(),
		"certificate_path": certPath,
		"key_path":         keyPath,
	}
	if sni := strings.TrimSpace(settings.ServerName); sni != "" {
		tlsObj["server_name"] = sni
	}

	hy2Inbound := map[string]any{
		"type":                    "hysteria2",
		"tag":                     tag,
		"listen":                  listen,
		"listen_port":             inbound.Port,
		"ignore_client_bandwidth": settings.IgnoreClientBandwidth,
		"users":                   users,
		"tls":                     tlsObj,
	}
	if settings.UpMbps > 0 {
		hy2Inbound["up_mbps"] = settings.UpMbps
	}
	if settings.DownMbps > 0 {
		hy2Inbound["down_mbps"] = settings.DownMbps
	}
	if obfsType, obfsPass := settings.normalizedObfs(); obfsType != "" {
		hy2Inbound["obfs"] = map[string]any{
			"type":     obfsType,
			"password": obfsPass,
		}
	}
	if masq := buildMasqueradeOption(settings.Masquerade); masq != nil {
		hy2Inbound["masquerade"] = masq
	}

	var outbounds []map[string]any
	var routeRules []map[string]any
	finalOutbound := "direct"

	if settings.routeViaXray() {
		socksAccounts := make([]singboxSocksAccount, 0, len(users))
		for _, u := range users {
			socksAccounts = append(socksAccounts, singboxSocksAccount{User: u.Name, Pass: u.Password})
		}
		outbounds, routeRules, finalOutbound = buildSingboxRouteOutboundsForXray(tag, s.GetSocksPort(inbound), socksAccounts)
	} else {
		outbounds = append(outbounds, map[string]any{
			"type": "direct",
			"tag":  "direct",
		})
	}

	statsCfg := map[string]any{
		"enabled":  true,
		"inbounds": []string{tag},
	}
	if len(statUsers) > 0 {
		statsCfg["users"] = statUsers
	}

	cfg := map[string]any{
		"log": map[string]any{
			"level":     "warn",
			"timestamp": true,
		},
		"inbounds":  []any{hy2Inbound},
		"outbounds": outbounds,
		"route": map[string]any{
			"final": finalOutbound,
		},
		"experimental": map[string]any{
			"v2ray_api": map[string]any{
				"listen": fmt.Sprintf("127.0.0.1:%d", s.GetV2rayAPIPort(inbound)),
				"stats":  statsCfg,
			},
			"clash_api": map[string]any{
				"external_controller": fmt.Sprintf("127.0.0.1:%d", s.GetClashAPIPort(inbound)),
				"secret":              clashSecret,
			},
		},
	}
	if len(routeRules) > 0 {
		cfg["route"].(map[string]any)["rules"] = routeRules
	}

	rendered, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	rendered = append(rendered, '\n')
	return rendered, activeUserSet, nil
}

// GenerateServerConfig renders and writes config.json for one Hysteria 2 inbound.
// Returns (changed, activeUsers, err) where changed is true when config or TLS cert bytes differ.
func (s *Hysteria2Service) GenerateServerConfig(inbound *model.Inbound) (bool, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return false, err
	}
	certPath, keyPath, certHash, err := s.resolveTLSCerts(inbound, settings)
	if err != nil {
		return false, err
	}
	clashSecret := s.getOrCreateClashSecret(inbound.Id)

	renderedBytes, activeUsers, err := s.buildServerConfig(inbound, settings, certPath, keyPath, clashSecret)
	if err != nil {
		return false, err
	}
	rendered := applyCoreConfigOverride("hysteria2", inbound.Id, "config.json", string(renderedBytes))
	cfgPath := s.configPath(inbound.Id)

	combinedHash := sha256Hex([]byte(rendered + "|cert|" + certHash))
	hy2State.mu.Lock()
	prevHash := hy2State.lastConfigHash[inbound.Id]
	hy2State.lastUserSet[inbound.Id] = activeUsers
	hy2State.mu.Unlock()

	wrote, err := writeFileIfChangedCheck(cfgPath, []byte(rendered), 0o600)
	if err != nil {
		return false, err
	}
	changed := wrote || (prevHash != "" && prevHash != combinedHash)
	hy2State.mu.Lock()
	hy2State.lastConfigHash[inbound.Id] = combinedHash
	hy2State.mu.Unlock()
	return changed, nil
}

// GenerateAllConfigs generates sing-box configs for all enabled Hysteria 2 inbounds.
func (s *Hysteria2Service) GenerateAllConfigs() error {
	inbounds, err := s.GetHysteria2Inbounds()
	if err != nil {
		return err
	}
	var firstErr error
	for _, inbound := range inbounds {
		if _, err := s.GenerateServerConfig(inbound); err != nil {
			logger.Warning("Hysteria2: generate config failed for inbound", inbound.Id, ":", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// InitHysteria2 reaps any stale Hysteria 2 sing-box daemons and starts enabled inbounds.
func (s *Hysteria2Service) InitHysteria2() {
	inbounds, err := s.GetHysteria2Inbounds()
	if err != nil {
		logger.Warning("Hysteria2: list inbounds failed:", err)
		return
	}
	if !s.Available() {
		if len(inbounds) > 0 {
			logger.Warning("Hysteria2: sing-box binary is not installed; skipping startup")
		}
		return
	}
	if commandExists("pkill") {
		_ = exec.Command("pkill", "-KILL", "-f", hysteria2ConfigBase+"/server-").Run()
	}
	if len(inbounds) == 0 {
		return
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("Hysteria2: startup failed:", err)
	}
}

// RestartServices restarts all enabled Hysteria 2 sing-box processes and stops stale ones.
func (s *Hysteria2Service) RestartServices() error {
	inbounds, err := s.GetHysteria2Inbounds()
	if err != nil {
		return err
	}
	wanted := make(map[string]*model.Inbound, len(inbounds))
	for _, inb := range inbounds {
		wanted[hy2ProcName(inb.Id)] = inb
	}

	mgr := GetProcManager()
	for _, name := range mgr.namesWithPrefix(hy2ProcPrefix) {
		if wanted[name] == nil {
			_ = mgr.Stop(name)
		}
	}
	if len(inbounds) == 0 {
		return nil
	}
	if !s.Available() {
		return common.NewError("sing-box binary is not installed")
	}

	bin := daemonBin("sing-box")
	for _, inb := range inbounds {
		if _, err := s.GenerateServerConfig(inb); err != nil {
			return err
		}
		if err := s.startInboundDaemon(bin, inb); err != nil {
			return err
		}
	}
	return nil
}

// EnsureServicesRunning preserves already-healthy unchanged daemons and starts or
// restarts only those whose config changed or whose process exited.
func (s *Hysteria2Service) EnsureServicesRunning() error {
	inbounds, err := s.GetHysteria2Inbounds()
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(inbounds))
	for _, inb := range inbounds {
		wanted[hy2ProcName(inb.Id)] = true
	}
	mgr := GetProcManager()
	for _, name := range mgr.namesWithPrefix(hy2ProcPrefix) {
		if !wanted[name] {
			_ = mgr.Stop(name)
		}
	}
	if len(inbounds) == 0 || !s.Available() {
		return nil
	}

	bin := daemonBin("sing-box")
	for _, inb := range inbounds {
		changed, err := s.GenerateServerConfig(inb)
		if err != nil {
			logger.Warning("Hysteria2: config reconcile failed for inbound", inb.Id, ":", err)
			continue
		}
		name := hy2ProcName(inb.Id)
		if !changed && mgr.IsRunning(name) {
			continue
		}
		if err := s.startInboundDaemon(bin, inb); err != nil {
			logger.Warning("Hysteria2: start daemon failed for inbound", inb.Id, ":", err)
		}
	}
	return nil
}

func (s *Hysteria2Service) startInboundDaemon(bin string, inb *model.Inbound) error {
	dir := s.configDir(inb.Id)
	cfgPath := s.configPath(inb.Id)
	hy2State.mu.Lock()
	delete(hy2State.prevInbound, inb.Id)
	delete(hy2State.prevUsers, inb.Id)
	hy2State.mu.Unlock()
	return GetProcManager().Start(hy2ProcName(inb.Id), bin, []string{"run", "-c", cfgPath}, nil, dir)
}

// StopServices stops all running Hysteria 2 sing-box daemons.
func (s *Hysteria2Service) StopServices() error {
	GetProcManager().StopByPrefix(hy2ProcPrefix)
	return nil
}

// RemoveInboundConfig stops the daemon and removes on-disk configuration for an inbound.
func (s *Hysteria2Service) RemoveInboundConfig(inboundId int) {
	_ = GetProcManager().Stop(hy2ProcName(inboundId))
	hy2State.mu.Lock()
	delete(hy2State.clashSecrets, inboundId)
	delete(hy2State.lastConfigHash, inboundId)
	delete(hy2State.lastUserSet, inboundId)
	delete(hy2State.prevInbound, inboundId)
	delete(hy2State.prevUsers, inboundId)
	hy2State.mu.Unlock()
	_ = os.RemoveAll(s.configDir(inboundId))
}

// DisableClients disconnects disabled/expired/over-quota users immediately and removes them from running configs.
func (s *Hysteria2Service) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}
	inbounds, err := s.GetHysteria2Inbounds()
	if err != nil {
		return
	}
	disableSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		if trimmed := strings.TrimSpace(e); trimmed != "" {
			disableSet[trimmed] = true
		}
	}
	for _, inb := range inbounds {
		s.closeUserConnections(inb, disableSet)
	}
	if err := s.EnsureServicesRunning(); err != nil {
		logger.Warning("Hysteria2: ensure running after DisableClients failed:", err)
	}
}

// KillDisabledSessions enforces disabled accounts and per-inbound User Limit caps via Clash API and config reconcile.
func (s *Hysteria2Service) KillDisabledSessions() {
	inbounds, err := s.GetHysteria2Inbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	disabled := s.getDisabledEmails()
	if err := s.EnsureServicesRunning(); err != nil {
		logger.Warning("Hysteria2: reconcile during KillDisabledSessions failed:", err)
	}
	for _, inb := range inbounds {
		if !GetProcManager().IsRunning(hy2ProcName(inb.Id)) {
			continue
		}
		if len(disabled) > 0 {
			s.closeUserConnections(inb, disabled)
		}
		settings, err := s.parseSettings(inb)
		if err != nil {
			continue
		}
		if limit := settings.effectiveUserLimit(); limit > 0 {
			s.enforceUserLimit(inb, limit, settings.effectiveStrategy(), settings.Clients)
		}
	}
}

func resolveConnectionUser(conn clashConnection, clients []Hysteria2Client) string {
	if u := strings.TrimSpace(conn.Metadata.User); u != "" {
		return u
	}
	if idx, ok := resolveChainIndex(conn.Chains); ok && idx < len(clients) {
		if email := strings.TrimSpace(clients[idx].Email); email != "" {
			return email
		}
	}
	return ""
}

func (s *Hysteria2Service) fetchConnections(inb *model.Inbound) ([]clashConnection, error) {
	return fetchClashConnections(s.GetClashAPIPort(inb), s.getOrCreateClashSecret(inb.Id))
}

func (s *Hysteria2Service) closeConnection(inb *model.Inbound, connID string) {
	closeClashConnection(s.GetClashAPIPort(inb), s.getOrCreateClashSecret(inb.Id), connID)
}

func (s *Hysteria2Service) closeUserConnections(inb *model.Inbound, targets map[string]bool) {
	settings, err := s.parseSettings(inb)
	if err != nil {
		return
	}
	conns, err := s.fetchConnections(inb)
	if err != nil {
		return
	}
	for _, conn := range conns {
		user := resolveConnectionUser(conn, settings.Clients)
		if user != "" && targets[user] {
			s.closeConnection(inb, conn.ID)
		}
	}
}

func (s *Hysteria2Service) enforceUserLimit(inb *model.Inbound, limit int, strategy string, clients []Hysteria2Client) {
	if limit <= 0 {
		return
	}
	enforceClashIPLimits(
		s.GetClashAPIPort(inb),
		s.getOrCreateClashSecret(inb.Id),
		strategy,
		func(conn clashConnection) string { return resolveConnectionUser(conn, clients) },
		func(string) int { return limit },
	)
}

// CollectAllTraffic queries per-inbound sing-box v2ray_api gRPC stats and returns
// direct-mode inbound stats plus per-user traffic deltas attributed to each inbound.
func (s *Hysteria2Service) CollectAllTraffic() ([]*xray.Traffic, []*xray.ClientTraffic) {
	inbounds, err := s.GetHysteria2Inbounds()
	if err != nil || len(inbounds) == 0 {
		return nil, nil
	}

	var inboundTraffics []*xray.Traffic
	var clientTraffics []*xray.ClientTraffic
	mgr := GetProcManager()

	for _, inb := range inbounds {
		if !mgr.IsRunning(hy2ProcName(inb.Id)) {
			continue
		}
		settings, parseErr := s.parseSettings(inb)
		if parseErr != nil {
			continue
		}
		inbStats, cliStats := s.collectInboundStats(inb, !settings.routeViaXray())
		if len(inbStats) > 0 {
			inboundTraffics = append(inboundTraffics, inbStats...)
		}
		if len(cliStats) > 0 {
			clientTraffics = append(clientTraffics, cliStats...)
		}
	}
	return inboundTraffics, clientTraffics
}

// CollectTraffic returns per-user Hysteria 2 traffic deltas attributed to their source inbound.
func (s *Hysteria2Service) CollectTraffic() []*xray.ClientTraffic {
	_, clients := s.CollectAllTraffic()
	return clients
}

func (s *Hysteria2Service) collectInboundStats(inb *model.Inbound, includeInbound bool) ([]*xray.Traffic, []*xray.ClientTraffic) {
	tag := strings.TrimSpace(inb.Tag)
	if tag == "" {
		tag = hy2ProcName(inb.Id)
	}
	return querySingboxV2rayStats(s.GetV2rayAPIPort(inb), inb.Id, tag, includeInbound, nil)
}

// Hysteria2Logs returns the combined stdout/stderr ring buffers for all Hysteria 2 daemons.
func (s *Hysteria2Service) Hysteria2Logs() string {
	return GetProcManager().LogsByPrefix(hy2ProcPrefix)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func regularFileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func fileHashPair(a, b string) string {
	ba, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	h := sha256.New()
	h.Write(ba)
	h.Write([]byte{'|'})
	h.Write(bb)
	return hex.EncodeToString(h.Sum(nil))
}

func writeFileIfChanged(path string, content []byte, mode os.FileMode) error {
	_, err := writeFileIfChangedCheck(path, content, mode)
	return err
}

func writeFileIfChangedCheck(path string, content []byte, mode os.FileMode) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, content) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}
