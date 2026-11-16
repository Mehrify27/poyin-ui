package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"

	statsService "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
)

func initHy2TestEnv(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	prevBase := hysteria2ConfigBase
	hysteria2ConfigBase = t.TempDir()
	t.Cleanup(func() {
		hysteria2ConfigBase = prevBase
		hy2State.mu.Lock()
		hy2State.clashSecrets = map[int]string{}
		hy2State.lastConfigHash = map[int]string{}
		hy2State.lastUserSet = map[int]map[string]bool{}
		hy2State.prevInbound = map[int]hy2TrafficPair{}
		hy2State.prevUsers = map[int]map[string]hy2TrafficPair{}
		hy2State.mu.Unlock()
	})
}

func TestHysteria2DefaultsAndValidation(t *testing.T) {
	defs, err := DefaultSettingsFor(model.Hysteria2)
	if err != nil {
		t.Fatalf("DefaultSettingsFor: %v", err)
	}
	if defs == "" {
		t.Fatal("expected non-empty default settings for hysteria2")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(defs), &m); err != nil {
		t.Fatalf("invalid default JSON: %v", err)
	}
	if rtx, ok := m["routeThroughXray"].(bool); !ok || !rtx {
		t.Fatalf("expected routeThroughXray=true by default, got %v", m["routeThroughXray"])
	}
	if err := ValidateProtocolSettings(model.Hysteria2, defs); err != nil {
		t.Fatalf("default settings failed validation: %v", err)
	}

	validCases := []string{
		`{"upMbps":100,"downMbps":200,"obfsType":"salamander","obfsPassword":"secret","hopPorts":"443,20000-20100","hopInterval":"30s","userLimit":4,"userLimitStrategy":"reject","clients":[]}`,
		`{"obfsType":"none","clients":[]}`,
	}
	for _, tc := range validCases {
		if err := ValidateProtocolSettings(model.Hysteria2, tc); err != nil {
			t.Fatalf("expected valid settings %s to pass, got: %v", tc, err)
		}
	}

	invalidCases := []struct {
		name string
		raw  string
	}{
		{"negative upMbps", `{"upMbps":-1,"clients":[]}`},
		{"bad obfsType", `{"obfsType":"invalid","clients":[]}`},
		{"missing obfsPassword", `{"obfsType":"salamander","obfsPassword":"","clients":[]}`},
		{"bad hopPorts", `{"hopPorts":"70000-80000","clients":[]}`},
		{"reversed hopPorts", `{"hopPorts":"300-200","clients":[]}`},
		{"bad strategy", `{"userLimitStrategy":"drop","clients":[]}`},
	}
	for _, tc := range invalidCases {
		if err := ValidateProtocolSettings(model.Hysteria2, tc.raw); err == nil {
			t.Fatalf("%s: expected validation error, got nil", tc.name)
		}
	}
}

func TestHysteria2ConfigGenerationAndCertFallback(t *testing.T) {
	initHy2TestEnv(t)
	var svc Hysteria2Service

	inb := &model.Inbound{
		Id:       12,
		Tag:      "inbound-hy2-12",
		Listen:   "0.0.0.0",
		Port:     8443,
		Protocol: model.Hysteria2,
		Enable:   true,
		Settings: `{
			"upMbps": 50,
			"downMbps": 100,
			"ignoreClientBandwidth": false,
			"obfsType": "salamander",
			"obfsPassword": "mask-password",
			"masquerade": "https://example.org",
			"routeThroughXray": true,
			"serverName": "hy2.example.com",
			"alpn": ["h3"],
			"clients": [
				{"email": "alice", "auth": "alice-secret", "enable": true},
				{"email": "bob", "auth": "bob-secret", "enable": false}
			]
		}`,
	}

	// Pin calculation auto-mints an idempotent self-signed ECDSA cert when none supplied.
	pin1 := svc.ResolveCertPinSHA256(inb)
	if len(pin1) != 64 {
		t.Fatalf("expected 64-char sha256 pin hex, got %q", pin1)
	}
	pin2 := svc.ResolveCertPinSHA256(inb)
	if pin1 != pin2 {
		t.Fatalf("self-signed cert pin must be idempotent: %s vs %s", pin1, pin2)
	}

	certBytes, err := os.ReadFile(filepath.Join(svc.configDir(inb.Id), "selfsigned.crt"))
	if err != nil {
		t.Fatalf("expected selfsigned.crt to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(svc.configDir(inb.Id), "selfsigned.key")); err != nil {
		t.Fatalf("expected selfsigned.key to exist: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatal("failed to decode generated PEM cert")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("invalid generated x509 cert: %v", err)
	}

	// Render sing-box config and inspect structure.
	settings, err := svc.parseSettings(inb)
	if err != nil {
		t.Fatalf("parseSettings: %v", err)
	}
	certPath, keyPath, _, err := svc.resolveTLSCerts(inb, settings)
	if err != nil {
		t.Fatalf("resolveTLSCerts: %v", err)
	}
	rendered, activeUsers, err := svc.buildServerConfig(inb, settings, certPath, keyPath, "clash-sec-12")
	if err != nil {
		t.Fatalf("buildServerConfig: %v", err)
	}
	if !activeUsers["alice"] || activeUsers["bob"] {
		t.Fatalf("activeUsers mismatch: %+v", activeUsers)
	}

	var doc map[string]any
	if err := json.Unmarshal(rendered, &doc); err != nil {
		t.Fatalf("invalid sing-box JSON: %v", err)
	}
	inbounds := doc["inbounds"].([]any)
	hyIn := inbounds[0].(map[string]any)
	if hyIn["type"] != "hysteria2" || int(hyIn["listen_port"].(float64)) != 8443 {
		t.Fatalf("unexpected hysteria2 inbound: %v", hyIn)
	}
	if int(hyIn["up_mbps"].(float64)) != 50 || int(hyIn["down_mbps"].(float64)) != 100 {
		t.Fatalf("bandwidth not serialized: %v", hyIn)
	}
	obfs := hyIn["obfs"].(map[string]any)
	if obfs["type"] != "salamander" || obfs["password"] != "mask-password" {
		t.Fatalf("unexpected obfs block: %v", obfs)
	}
	masq := hyIn["masquerade"].(map[string]any)
	if masq["type"] != "proxy" || masq["url"] != "https://example.org" {
		t.Fatalf("unexpected masquerade block: %v", masq)
	}
	users := hyIn["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["name"] != "alice" {
		t.Fatalf("disabled client leaked into sing-box users: %v", users)
	}

	// Verify loopback Xray SOCKS bridge matches sing-box route outbounds.
	socksCfg := svc.GetSocksConfig(inb)
	if socksCfg == nil || socksCfg.Port != 12300+inb.Id || socksCfg.Protocol != "socks" {
		t.Fatalf("unexpected Xray bridge config: %+v", socksCfg)
	}
	var socksSettings struct {
		Auth     string `json:"auth"`
		UDP      bool   `json:"udp"`
		Accounts []struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(socksCfg.Settings, &socksSettings); err != nil {
		t.Fatalf("unmarshal socks settings: %v", err)
	}
	if socksSettings.Auth != "password" || !socksSettings.UDP || len(socksSettings.Accounts) != 1 || socksSettings.Accounts[0].User != "alice" {
		t.Fatalf("unexpected bridge accounts: %+v", socksSettings)
	}

	// When routeThroughXray is false, no Xray bridge is built.
	rtxFalse := false
	settingsDirect := settings
	settingsDirect.RouteThroughXray = &rtxFalse
	inbDirect := *inb
	inbDirect.Settings = strings.Replace(inb.Settings, `"routeThroughXray": true`, `"routeThroughXray": false`, 1)
	if got := svc.GetSocksConfig(&inbDirect); got != nil {
		t.Fatalf("expected nil socks bridge when routeThroughXray=false, got %+v", got)
	}
	docDirectBytes, _, err := svc.buildServerConfig(&inbDirect, settingsDirect, certPath, keyPath, "clash-sec-12")
	if err != nil {
		t.Fatalf("buildServerConfig direct: %v", err)
	}
	var docDirect map[string]any
	if err := json.Unmarshal(docDirectBytes, &docDirect); err != nil {
		t.Fatal(err)
	}
	if docDirect["route"].(map[string]any)["final"] != "direct" {
		t.Fatalf("expected direct final route, got %v", docDirect["route"])
	}
}

func TestHysteria2ClashAPIUserLimitAndDisable(t *testing.T) {
	initHy2TestEnv(t)

	const secret = "test-clash-secret"
	var (
		mu         sync.Mutex
		closed     []string
		authHeader string
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	inbID := port - hysteria2ClashPortBase

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeader = r.Header.Get("Authorization")
		mu.Unlock()
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/") {
			mu.Lock()
			closed = append(closed, strings.TrimPrefix(r.URL.Path, "/connections/"))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/connections" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id":     "c-old",
						"chains": []string{"xray-u-0"},
						"start":  "2026-01-01T00:00:01Z",
						"metadata": map[string]any{
							"sourceIP": "198.51.100.1",
						},
					},
					{
						"id":     "c-new",
						"chains": []string{"xray-u-0"},
						"start":  "2026-01-01T00:05:00Z",
						"metadata": map[string]any{
							"sourceIP": "198.51.100.2",
						},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	hy2State.mu.Lock()
	hy2State.clashSecrets[inbID] = secret
	hy2State.mu.Unlock()

	var svc Hysteria2Service
	inb := &model.Inbound{Id: inbID}
	clients := []Hysteria2Client{{Email: "alice", Auth: "pw", Enable: true}}

	// Reject strategy evicts newest IP ("c-new").
	svc.enforceUserLimit(inb, 1, "reject", clients)
	mu.Lock()
	gotAuth := authHeader
	gotClosed := append([]string(nil), closed...)
	closed = nil
	mu.Unlock()
	if gotAuth != "Bearer "+secret {
		t.Fatalf("expected Bearer auth header, got %q", gotAuth)
	}
	if len(gotClosed) != 1 || gotClosed[0] != "c-new" {
		t.Fatalf("reject strategy should close newest IP c-new, got %v", gotClosed)
	}

	// Accept strategy evicts oldest IP ("c-old").
	svc.enforceUserLimit(inb, 1, "accept", clients)
	mu.Lock()
	gotClosed = append([]string(nil), closed...)
	closed = nil
	mu.Unlock()
	if len(gotClosed) != 1 || gotClosed[0] != "c-old" {
		t.Fatalf("accept strategy should close oldest IP c-old, got %v", gotClosed)
	}

	// closeUserConnections closes all connections for target user.
	hy2State.mu.Lock()
	hy2State.clashSecrets[inbID] = secret
	hy2State.mu.Unlock()
	conns, err := svc.fetchConnections(inb)
	if err != nil || len(conns) != 2 {
		t.Fatalf("fetchConnections: err=%v len=%d", err, len(conns))
	}
	if got := resolveConnectionUser(conns[0], clients); got != "alice" {
		t.Fatalf("resolveConnectionUser: got %q, want alice", got)
	}
}

type fakeHy2StatsServer struct {
	statsService.UnimplementedStatsServiceServer
	stats []*statsService.Stat
}

func (f *fakeHy2StatsServer) QueryStats(_ context.Context, _ *statsService.QueryStatsRequest) (*statsService.QueryStatsResponse, error) {
	return &statsService.QueryStatsResponse{Stat: f.stats}, nil
}

func TestHysteria2V2rayStatsAttribution(t *testing.T) {
	initHy2TestEnv(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	inbID := port - hysteria2V2rayAPIPortBase

	gs := grpc.NewServer()
	statsService.RegisterStatsServiceServer(gs, &fakeHy2StatsServer{
		stats: []*statsService.Stat{
			{Name: "user>>>alice>>>traffic>>>uplink", Value: 1200},
			{Name: "user>>>alice>>>traffic>>>downlink", Value: 3400},
			{Name: "inbound>>>inbound-hy2>>>traffic>>>uplink", Value: 1200},
			{Name: "inbound>>>inbound-hy2>>>traffic>>>downlink", Value: 3400},
		},
	})
	go func() { _ = gs.Serve(ln) }()
	defer gs.Stop()

	var svc Hysteria2Service
	inb := &model.Inbound{Id: inbID, Tag: "inbound-hy2"}
	inbTraffics, clientTraffics := svc.collectInboundStats(inb, true)
	if len(inbTraffics) != 1 || inbTraffics[0].Up != 1200 || inbTraffics[0].Down != 3400 || !inbTraffics[0].IsInbound {
		t.Fatalf("unexpected inbound traffic: %+v", inbTraffics)
	}
	if len(clientTraffics) != 1 {
		t.Fatalf("expected 1 client traffic record, got %d", len(clientTraffics))
	}
	ct := clientTraffics[0]
	if ct.Email != "alice" || ct.InboundId != inbID || ct.Up != 1200 || ct.Down != 3400 {
		t.Fatalf("unexpected client traffic attribution: %+v", ct)
	}
}
