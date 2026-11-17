package service

import (
	"encoding/json"
	"fmt"
	"net"
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
	singboxForkSocksPortBase    = 12300
	singboxForkClashPortBase    = 25300
	singboxForkV2rayAPIPortBase = 26300
	singboxForkProcPrefix       = "singbox-fork-"
)

var singboxForkConfigBase = "/etc/vpn-ui-singbox"

// SingboxForkService runs AnyTLS, TUIC v5, and NaiveProxy inbounds natively inside
// the sing-box sidecar and bridges egress traffic into Xray over loopback SOCKS5.
// This allows stock unpatched official XTLS/Xray-core binaries to run without
// crashing on fork-only protocols while preserving Xray routing, geo-rules, outbounds,
// quota enforcement, per-user traffic attribution, and IP limit enforcement.
type SingboxForkService struct {
	settingService SettingService
}

func isForkProtocol(p model.Protocol) bool {
	return p == model.ANYTLS || p == model.TUIC || p == model.NAIVE
}

// ShouldUseSingboxForkEngine reports whether AnyTLS, TUIC v5, and NaiveProxy should
// currently run through the sing-box sidecar rather than Xray-core.
func ShouldUseSingboxForkEngine() bool {
	var ss SettingService
	if ss.GetForkProtocolEngine() == "sing-box" {
		return true
	}
	if ss.GetForkProtocolEngine() == "xray" {
		return false
	}
	caps := DetectActiveXrayCapabilities()
	return !caps.SupportsNativeForkProtocols
}

// ShouldUseSingboxForkEngineForCaps evaluates fork engine routing against a specific
// Xray binary capability profile (used to preflight a staged binary before swap).
func ShouldUseSingboxForkEngineForCaps(caps XrayBinaryCapabilities) bool {
	var ss SettingService
	switch ss.GetForkProtocolEngine() {
	case "sing-box":
		return true
	case "xray":
		return false
	default:
		return !caps.SupportsNativeForkProtocols
	}
}

type singboxForkUser struct {
	Email    string
	AuthUser string
	UUID     string
	Password string
	LimitIP  int
}

type singboxForkRuntimeState struct {
	mu             sync.Mutex
	clashSecrets   map[int]string
	lastConfigHash map[int]string
	userEmailMap   map[int]map[string]string
	users          map[int][]singboxForkUser
}

var sfState = &singboxForkRuntimeState{
	clashSecrets:   map[int]string{},
	lastConfigHash: map[int]string{},
	userEmailMap:   map[int]map[string]string{},
	users:          map[int][]singboxForkUser{},
}

func singboxForkProcName(id int) string {
	return singboxForkProcPrefix + strconv.Itoa(id)
}

func (s *SingboxForkService) configDir(inboundId int) string {
	return filepath.Join(singboxForkConfigBase, "server-"+strconv.Itoa(inboundId))
}

func (s *SingboxForkService) configPath(inboundId int) string {
	return filepath.Join(s.configDir(inboundId), "config.json")
}

func (s *SingboxForkService) GetSocksPort(inbound *model.Inbound) int {
	return singboxForkSocksPortBase + inbound.Id
}

func (s *SingboxForkService) GetClashAPIPort(inbound *model.Inbound) int {
	return singboxForkClashPortBase + inbound.Id
}

func (s *SingboxForkService) GetV2rayAPIPort(inbound *model.Inbound) int {
	return singboxForkV2rayAPIPortBase + inbound.Id
}

func (s *SingboxForkService) Available() bool {
	return daemonInstalled("sing-box")
}

func (s *SingboxForkService) AnyRunning() bool {
	return GetProcManager().AnyRunningWithPrefix(singboxForkProcPrefix)
}

func (s *SingboxForkService) GetManagedInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	if db == nil {
		return nil, common.NewError("database not initialized")
	}
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).
		Where("protocol IN ? AND enable = ?", []model.Protocol{model.ANYTLS, model.TUIC, model.NAIVE}, true).
		Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	return inbounds, nil
}

func (s *SingboxForkService) getOrCreateClashSecret(inboundId int) string {
	sfState.mu.Lock()
	if sec := sfState.clashSecrets[inboundId]; sec != "" {
		sfState.mu.Unlock()
		return sec
	}
	sfState.mu.Unlock()

	sec := loadOrCreateClashSecret(s.configPath(inboundId))
	sfState.mu.Lock()
	sfState.clashSecrets[inboundId] = sec
	sfState.mu.Unlock()
	return sec
}

type forkStreamConfig struct {
	Security    string
	ServerName  string
	Alpn        []string
	RealityDest string
	PrivateKey  string
	ShortIDs    []string
}

func parseForkStreamConfig(streamRaw string) forkStreamConfig {
	var out forkStreamConfig
	if strings.TrimSpace(streamRaw) == "" {
		return out
	}
	var doc struct {
		Security    string `json:"security"`
		TlsSettings struct {
			ServerName string   `json:"serverName"`
			Alpn       []string `json:"alpn"`
		} `json:"tlsSettings"`
		RealitySettings struct {
			Target      string   `json:"target"`
			Dest        string   `json:"dest"`
			ServerNames []string `json:"serverNames"`
			PrivateKey  string   `json:"privateKey"`
			ShortIds    []string `json:"shortIds"`
		} `json:"realitySettings"`
	}
	if err := json.Unmarshal([]byte(streamRaw), &doc); err != nil {
		return out
	}
	out.Security = strings.ToLower(strings.TrimSpace(doc.Security))
	out.ServerName = strings.TrimSpace(doc.TlsSettings.ServerName)
	for _, a := range doc.TlsSettings.Alpn {
		if trimmed := strings.TrimSpace(a); trimmed != "" {
			out.Alpn = append(out.Alpn, trimmed)
		}
	}
	out.RealityDest = strings.TrimSpace(doc.RealitySettings.Target)
	if out.RealityDest == "" {
		out.RealityDest = strings.TrimSpace(doc.RealitySettings.Dest)
	}
	if out.ServerName == "" && len(doc.RealitySettings.ServerNames) > 0 {
		out.ServerName = strings.TrimSpace(doc.RealitySettings.ServerNames[0])
	}
	out.PrivateKey = strings.TrimSpace(doc.RealitySettings.PrivateKey)
	for _, sid := range doc.RealitySettings.ShortIds {
		if trimmed := strings.TrimSpace(sid); trimmed != "" {
			out.ShortIDs = append(out.ShortIDs, trimmed)
		}
	}
	return out
}

func splitRealityHandshake(dest, fallbackSNI string) (string, int) {
	raw := strings.TrimSpace(dest)
	if raw == "" {
		raw = strings.TrimSpace(fallbackSNI)
	}
	if raw == "" {
		return "example.com", 443
	}
	if host, portStr, err := net.SplitHostPort(raw); err == nil {
		p, perr := strconv.Atoi(portStr)
		if perr == nil && p > 0 {
			return host, p
		}
		return host, 443
	}
	return raw, 443
}

func (s *SingboxForkService) extractActiveUsers(inbound *model.Inbound) ([]singboxForkUser, map[string]any, error) {
	var rawMap map[string]any
	if strings.TrimSpace(inbound.Settings) != "" {
		if err := json.Unmarshal([]byte(inbound.Settings), &rawMap); err != nil {
			return nil, nil, err
		}
	}
	if rawMap == nil {
		rawMap = map[string]any{}
	}

	var clientsStruct struct {
		Clients []model.Client `json:"clients"`
	}
	if strings.TrimSpace(inbound.Settings) != "" {
		_ = json.Unmarshal([]byte(inbound.Settings), &clientsStruct)
	}

	disabled := getDisabledAccountEmails()
	nowMs := time.Now().UnixMilli()
	out := make([]singboxForkUser, 0, len(clientsStruct.Clients))
	for _, c := range clientsStruct.Clients {
		email := strings.TrimSpace(c.Email)
		if email == "" || !c.Enable || disabled[c.Email] || disabled[email] {
			continue
		}
		if c.ExpiryTime > 0 && c.ExpiryTime <= nowMs {
			continue
		}
		authUser := email
		if inbound.Protocol == model.NAIVE && strings.TrimSpace(c.Username) != "" {
			authUser = strings.TrimSpace(c.Username)
		}
		if inbound.Protocol == model.TUIC && (strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Password) == "") {
			continue
		}
		if (inbound.Protocol == model.ANYTLS || inbound.Protocol == model.NAIVE) && strings.TrimSpace(c.Password) == "" {
			continue
		}
		out = append(out, singboxForkUser{
			Email:    email,
			AuthUser: authUser,
			UUID:     strings.TrimSpace(c.ID),
			Password: c.Password,
			LimitIP:  c.LimitIP,
		})
	}
	return out, rawMap, nil
}

// GetSocksConfig returns the loopback SOCKS5 Xray inbound bridging one sing-box
// AnyTLS/TUIC/NaiveProxy daemon into Xray when sing-box fork mode is active.
func (s *SingboxForkService) GetSocksConfig(inbound *model.Inbound) *xray.InboundConfig {
	if inbound == nil || !isForkProtocol(inbound.Protocol) {
		return nil
	}
	users, _, err := s.extractActiveUsers(inbound)
	if err != nil {
		logger.Warning("sing-box fork: extract users failed for inbound", inbound.Id, ":", err)
		return nil
	}
	accounts := make([]singboxSocksAccount, 0, len(users))
	for _, u := range users {
		accounts = append(accounts, singboxSocksAccount{User: u.Email, Pass: u.Password})
	}
	return buildLoopbackSocksInbound(inbound, s.GetSocksPort(inbound), accounts)
}

func normalizeNaiveNetworkForSingbox(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return ""
	}
	hasTCP, hasUDP := false, false
	for _, part := range strings.Split(trimmed, ",") {
		switch strings.TrimSpace(part) {
		case "tcp", "h2", "http2":
			hasTCP = true
		case "udp", "h3", "http3", "quic":
			hasUDP = true
		}
	}
	if hasTCP && !hasUDP {
		return "tcp"
	}
	if hasUDP && !hasTCP {
		return "udp"
	}
	return ""
}

func (s *SingboxForkService) buildServerConfig(inbound *model.Inbound, clashSecret string) ([]byte, string, []singboxForkUser, error) {
	if inbound == nil || !isForkProtocol(inbound.Protocol) {
		return nil, "", nil, common.NewError("unsupported sing-box fork inbound protocol")
	}

	users, rawSettings, err := s.extractActiveUsers(inbound)
	if err != nil {
		return nil, "", nil, err
	}
	streamCfg := parseForkStreamConfig(inbound.StreamSettings)

	var (
		certPath string
		keyPath  string
		certHash string
	)
	useReality := inbound.Protocol == model.ANYTLS && streamCfg.Security == "reality" && streamCfg.PrivateKey != ""
	if !useReality {
		certPath, keyPath, certHash, err = resolveSidecarTLSCerts(s.configDir(inbound.Id), sidecarTLSInput{
			ServerName:     streamCfg.ServerName,
			Listen:         inbound.Listen,
			StreamSettings: inbound.StreamSettings,
		}, &s.settingService)
		if err != nil {
			return nil, "", nil, err
		}
	} else {
		certHash = sha256Hex([]byte(streamCfg.PrivateKey + "|" + streamCfg.RealityDest + "|" + strings.Join(streamCfg.ShortIDs, ",")))
	}

	listen := strings.TrimSpace(inbound.Listen)
	if listen == "" {
		listen = "::"
	}
	tag := strings.TrimSpace(inbound.Tag)
	if tag == "" {
		tag = singboxForkProcName(inbound.Id)
	}

	tlsObj := map[string]any{"enabled": true}
	if streamCfg.ServerName != "" {
		tlsObj["server_name"] = streamCfg.ServerName
	}
	if useReality {
		hHost, hPort := splitRealityHandshake(streamCfg.RealityDest, streamCfg.ServerName)
		shortIDs := streamCfg.ShortIDs
		if len(shortIDs) == 0 {
			shortIDs = []string{""}
		}
		tlsObj["reality"] = map[string]any{
			"enabled": true,
			"handshake": map[string]any{
				"server":      hHost,
				"server_port": hPort,
			},
			"private_key": streamCfg.PrivateKey,
			"short_id":    shortIDs,
		}
	} else {
		tlsObj["certificate_path"] = certPath
		tlsObj["key_path"] = keyPath
		alpn := streamCfg.Alpn
		if inbound.Protocol == model.TUIC && len(alpn) == 0 {
			alpn = []string{"h3"}
		}
		if len(alpn) > 0 {
			tlsObj["alpn"] = alpn
		}
	}

	sbInbound := map[string]any{
		"type":        string(inbound.Protocol),
		"tag":         tag,
		"listen":      listen,
		"listen_port": inbound.Port,
		"tls":         tlsObj,
	}

	statUsers := make([]string, 0, len(users))
	socksAccounts := make([]singboxSocksAccount, 0, len(users))
	routeOutbounds := make([]map[string]any, 0, len(users)+1)
	routeRules := make([]map[string]any, 0, len(users))
	socksPort := s.GetSocksPort(inbound)

	switch inbound.Protocol {
	case model.ANYTLS:
		inUsers := make([]map[string]any, 0, len(users))
		for _, u := range users {
			inUsers = append(inUsers, map[string]any{
				"name":     u.Email,
				"password": u.Password,
			})
			statUsers = append(statUsers, u.Email)
		}
		sbInbound["users"] = inUsers
		if rawPS, ok := rawSettings["paddingScheme"].([]any); ok && len(rawPS) > 0 {
			scheme := make([]string, 0, len(rawPS))
			for _, line := range rawPS {
				if sv, ok := line.(string); ok && strings.TrimSpace(sv) != "" {
					scheme = append(scheme, strings.TrimSpace(sv))
				}
			}
			if len(scheme) > 0 {
				sbInbound["padding_scheme"] = scheme
			}
		}

	case model.TUIC:
		inUsers := make([]map[string]any, 0, len(users))
		for _, u := range users {
			inUsers = append(inUsers, map[string]any{
				"name":     u.Email,
				"uuid":     u.UUID,
				"password": u.Password,
			})
			statUsers = append(statUsers, u.Email)
		}
		sbInbound["users"] = inUsers
		cc := "cubic"
		if rawCC, ok := rawSettings["congestionControl"].(string); ok && strings.TrimSpace(rawCC) != "" {
			cc = strings.TrimSpace(rawCC)
		}
		sbInbound["congestion_control"] = cc
		if at, ok := parseSettingSeconds(rawSettings["authTimeout"]); ok && at > 0 {
			sbInbound["auth_timeout"] = fmt.Sprintf("%ds", at)
		} else {
			sbInbound["auth_timeout"] = "3s"
		}
		if hb, ok := parseSettingSeconds(rawSettings["heartbeat"]); ok && hb > 0 {
			sbInbound["heartbeat"] = fmt.Sprintf("%ds", hb)
		} else {
			sbInbound["heartbeat"] = "10s"
		}
		if zr, ok := rawSettings["zeroRttHandshake"].(bool); ok {
			sbInbound["zero_rtt_handshake"] = zr
		}

	case model.NAIVE:
		inUsers := make([]map[string]any, 0, len(users))
		for _, u := range users {
			inUsers = append(inUsers, map[string]any{
				"username": u.AuthUser,
				"password": u.Password,
			})
			statUsers = append(statUsers, u.AuthUser)
		}
		sbInbound["users"] = inUsers
		if netRaw, ok := rawSettings["network"].(string); ok {
			if normNet := normalizeNaiveNetworkForSingbox(netRaw); normNet != "" {
				sbInbound["network"] = normNet
			}
		}
	}

	for i, u := range users {
		socksAccounts = append(socksAccounts, singboxSocksAccount{User: u.Email, Pass: u.Password})
		outTag := fmt.Sprintf("xray-u-%d", i)
		routeOutbounds = append(routeOutbounds, map[string]any{
			"type":        "socks",
			"tag":         outTag,
			"server":      "127.0.0.1",
			"server_port": socksPort,
			"version":     "5",
			"username":    u.Email,
			"password":    u.Password,
		})
		routeRules = append(routeRules, map[string]any{
			"inbound":   []string{tag},
			"auth_user": []string{u.AuthUser},
			"outbound":  outTag,
		})
	}
	fallbackOut := map[string]any{
		"type":        "socks",
		"tag":         "xray-fallback",
		"server":      "127.0.0.1",
		"server_port": socksPort,
		"version":     "5",
	}
	if len(socksAccounts) > 0 {
		fallbackOut["username"] = socksAccounts[0].User
		fallbackOut["password"] = socksAccounts[0].Pass
	}
	routeOutbounds = append(routeOutbounds, fallbackOut)

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
		"inbounds":  []any{sbInbound},
		"outbounds": routeOutbounds,
		"route": map[string]any{
			"final": "xray-fallback",
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
		return nil, "", nil, err
	}
	rendered = append(rendered, '\n')
	return rendered, certHash, users, nil
}

func parseSettingSeconds(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	default:
		return 0, false
	}
}

func (s *SingboxForkService) GenerateServerConfig(inbound *model.Inbound) (bool, error) {
	clashSecret := s.getOrCreateClashSecret(inbound.Id)
	renderedBytes, certHash, users, err := s.buildServerConfig(inbound, clashSecret)
	if err != nil {
		return false, err
	}
	rendered := applyCoreConfigOverride(string(inbound.Protocol), inbound.Id, "config.json", string(renderedBytes))
	cfgPath := s.configPath(inbound.Id)

	combinedHash := sha256Hex([]byte(rendered + "|cert|" + certHash))
	userMap := make(map[string]string, len(users))
	for _, u := range users {
		userMap[u.AuthUser] = u.Email
		userMap[u.Email] = u.Email
	}

	sfState.mu.Lock()
	prevHash := sfState.lastConfigHash[inbound.Id]
	sfState.userEmailMap[inbound.Id] = userMap
	sfState.users[inbound.Id] = append([]singboxForkUser(nil), users...)
	sfState.mu.Unlock()

	wrote, err := writeFileIfChangedCheck(cfgPath, []byte(rendered), 0o600)
	if err != nil {
		return false, err
	}
	changed := wrote || (prevHash != "" && prevHash != combinedHash)
	sfState.mu.Lock()
	sfState.lastConfigHash[inbound.Id] = combinedHash
	sfState.mu.Unlock()
	return changed, nil
}

func (s *SingboxForkService) GenerateAllConfigs() error {
	if !ShouldUseSingboxForkEngine() {
		return nil
	}
	inbounds, err := s.GetManagedInbounds()
	if err != nil {
		return err
	}
	var firstErr error
	for _, inbound := range inbounds {
		if _, err := s.GenerateServerConfig(inbound); err != nil {
			logger.Warning("sing-box fork: generate config failed for inbound", inbound.Id, ":", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (s *SingboxForkService) InitServices() {
	inbounds, err := s.GetManagedInbounds()
	if err != nil {
		logger.Warning("sing-box fork: list inbounds failed:", err)
		return
	}
	if commandExists("pkill") {
		_ = exec.Command("pkill", "-KILL", "-f", singboxForkConfigBase+"/server-").Run()
	}
	if !ShouldUseSingboxForkEngine() || len(inbounds) == 0 {
		return
	}
	if !s.Available() {
		logger.Warning("sing-box binary is not installed; skipping AnyTLS/TUIC/NaiveProxy sidecar startup")
		return
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("sing-box fork: startup failed:", err)
	}
}

func (s *SingboxForkService) RestartServices() error {
	if !ShouldUseSingboxForkEngine() {
		return s.StopServices()
	}
	inbounds, err := s.GetManagedInbounds()
	if err != nil {
		return err
	}
	wanted := make(map[string]*model.Inbound, len(inbounds))
	for _, inb := range inbounds {
		wanted[singboxForkProcName(inb.Id)] = inb
	}
	mgr := GetProcManager()
	for _, name := range mgr.namesWithPrefix(singboxForkProcPrefix) {
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
		if err := mgr.Start(singboxForkProcName(inb.Id), bin, []string{"run", "-c", s.configPath(inb.Id)}, nil, s.configDir(inb.Id)); err != nil {
			return err
		}
	}
	return nil
}

func (s *SingboxForkService) EnsureServicesRunning() error {
	if !ShouldUseSingboxForkEngine() {
		return s.StopServices()
	}
	inbounds, err := s.GetManagedInbounds()
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(inbounds))
	for _, inb := range inbounds {
		wanted[singboxForkProcName(inb.Id)] = true
	}
	mgr := GetProcManager()
	for _, name := range mgr.namesWithPrefix(singboxForkProcPrefix) {
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
			logger.Warning("sing-box fork: config reconcile failed for inbound", inb.Id, ":", err)
			continue
		}
		name := singboxForkProcName(inb.Id)
		if !changed && mgr.IsRunning(name) {
			continue
		}
		if err := mgr.Start(name, bin, []string{"run", "-c", s.configPath(inb.Id)}, nil, s.configDir(inb.Id)); err != nil {
			logger.Warning("sing-box fork: start daemon failed for inbound", inb.Id, ":", err)
		}
	}
	return nil
}

func (s *SingboxForkService) StopServices() error {
	GetProcManager().StopByPrefix(singboxForkProcPrefix)
	return nil
}

func (s *SingboxForkService) RemoveInboundConfig(inboundId int) {
	_ = GetProcManager().Stop(singboxForkProcName(inboundId))
	sfState.mu.Lock()
	delete(sfState.clashSecrets, inboundId)
	delete(sfState.lastConfigHash, inboundId)
	delete(sfState.userEmailMap, inboundId)
	delete(sfState.users, inboundId)
	sfState.mu.Unlock()
	_ = os.RemoveAll(s.configDir(inboundId))
}

func (s *SingboxForkService) DisableClients(emails []string) {
	if !ShouldUseSingboxForkEngine() || len(emails) == 0 {
		return
	}
	inbounds, err := s.GetManagedInbounds()
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
		logger.Warning("sing-box fork: ensure running after DisableClients failed:", err)
	}
}

func (s *SingboxForkService) KillDisabledSessions() {
	if !ShouldUseSingboxForkEngine() {
		return
	}
	inbounds, err := s.GetManagedInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	disabled := getDisabledAccountEmails()
	if err := s.EnsureServicesRunning(); err != nil {
		logger.Warning("sing-box fork: reconcile during KillDisabledSessions failed:", err)
	}
	for _, inb := range inbounds {
		if !GetProcManager().IsRunning(singboxForkProcName(inb.Id)) {
			continue
		}
		if len(disabled) > 0 {
			s.closeUserConnections(inb, disabled)
		}
		sfState.mu.Lock()
		users := append([]singboxForkUser(nil), sfState.users[inb.Id]...)
		sfState.mu.Unlock()
		if len(users) == 0 {
			continue
		}
		limitByEmail := make(map[string]int, len(users))
		for _, u := range users {
			capLimit := inb.IPLimit
			if u.LimitIP > 0 {
				capLimit = u.LimitIP
			}
			if capLimit > 0 {
				limitByEmail[u.Email] = capLimit
			}
		}
		if len(limitByEmail) == 0 {
			continue
		}
		strategy := normIPLimitStrategy(inb)
		enforceClashIPLimits(
			s.GetClashAPIPort(inb),
			s.getOrCreateClashSecret(inb.Id),
			strategy,
			func(conn clashConnection) string { return s.resolveConnEmail(inb.Id, conn, users) },
			func(email string) int { return limitByEmail[email] },
		)
	}
}

func (s *SingboxForkService) resolveConnEmail(inboundID int, conn clashConnection, users []singboxForkUser) string {
	if u := strings.TrimSpace(conn.Metadata.User); u != "" {
		sfState.mu.Lock()
		var mapped string
		if m := sfState.userEmailMap[inboundID]; m != nil {
			mapped = m[u]
		}
		sfState.mu.Unlock()
		if mapped != "" {
			return mapped
		}
		return u
	}
	if idx, ok := resolveChainIndex(conn.Chains); ok && idx < len(users) {
		return users[idx].Email
	}
	return ""
}

func (s *SingboxForkService) closeUserConnections(inb *model.Inbound, targets map[string]bool) {
	conns, err := fetchClashConnections(s.GetClashAPIPort(inb), s.getOrCreateClashSecret(inb.Id))
	if err != nil {
		return
	}
	sfState.mu.Lock()
	users := append([]singboxForkUser(nil), sfState.users[inb.Id]...)
	sfState.mu.Unlock()
	secret := s.getOrCreateClashSecret(inb.Id)
	port := s.GetClashAPIPort(inb)
	for _, conn := range conns {
		email := s.resolveConnEmail(inb.Id, conn, users)
		if email != "" && targets[email] {
			closeClashConnection(port, secret, conn.ID)
		}
	}
}

func (s *SingboxForkService) CollectAllTraffic() ([]*xray.Traffic, []*xray.ClientTraffic) {
	if !ShouldUseSingboxForkEngine() {
		return nil, nil
	}
	inbounds, err := s.GetManagedInbounds()
	if err != nil || len(inbounds) == 0 {
		return nil, nil
	}
	var inboundTraffics []*xray.Traffic
	var clientTraffics []*xray.ClientTraffic
	mgr := GetProcManager()
	for _, inb := range inbounds {
		if !mgr.IsRunning(singboxForkProcName(inb.Id)) {
			continue
		}
		tag := strings.TrimSpace(inb.Tag)
		if tag == "" {
			tag = singboxForkProcName(inb.Id)
		}
		sfState.mu.Lock()
		uMap := make(map[string]string, len(sfState.userEmailMap[inb.Id]))
		for k, v := range sfState.userEmailMap[inb.Id] {
			uMap[k] = v
		}
		sfState.mu.Unlock()
		inbStats, cliStats := querySingboxV2rayStats(
			s.GetV2rayAPIPort(inb),
			inb.Id,
			tag,
			false,
			func(rawUser string) string {
				if mapped, ok := uMap[rawUser]; ok {
					return mapped
				}
				return rawUser
			},
		)
		if len(inbStats) > 0 {
			inboundTraffics = append(inboundTraffics, inbStats...)
		}
		if len(cliStats) > 0 {
			clientTraffics = append(clientTraffics, cliStats...)
		}
	}
	return inboundTraffics, clientTraffics
}

func (s *SingboxForkService) Logs() string {
	return GetProcManager().LogsByPrefix(singboxForkProcPrefix)
}
