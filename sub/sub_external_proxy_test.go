package sub

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestExtractExternalProxiesTypeSafety(t *testing.T) {
	stream := map[string]any{
		"externalProxy": []any{
			map[string]any{"dest": "edge1.example.com", "port": int(8443), "forceTls": "", "remark": nil},
			map[string]any{"dest": "edge2.example.com", "port": "9443"},
			map[string]any{"dest": "", "port": 0},
			"malformed-entry",
		},
	}
	specs := extractExternalProxies(stream, nil, "origin.example.com", 443)
	if len(specs) != 3 {
		t.Fatalf("specs len = %d, want 3: %+v", len(specs), specs)
	}
	if specs[0].Dest != "edge1.example.com" || specs[0].Port != 8443 || specs[0].ForceTls != "same" || specs[0].Remark != "" {
		t.Fatalf("unexpected spec[0]: %+v", specs[0])
	}
	if specs[1].Dest != "edge2.example.com" || specs[1].Port != 9443 || specs[1].ForceTls != "same" {
		t.Fatalf("unexpected spec[1]: %+v", specs[1])
	}
	if specs[2].Dest != "origin.example.com" || specs[2].Port != 443 {
		t.Fatalf("unexpected fallback spec[2]: %+v", specs[2])
	}

	settingsFallback := map[string]any{
		"externalProxy": []any{
			map[string]any{"dest": "wg-relay.example.com", "port": 51821, "remark": "Relay"},
		},
	}
	wgSpecs := extractExternalProxies(nil, settingsFallback, "origin.example.com", 51820)
	if len(wgSpecs) != 1 || wgSpecs[0].Dest != "wg-relay.example.com" || wgSpecs[0].Port != 51821 {
		t.Fatalf("settings fallback failed: %+v", wgSpecs)
	}
}

func TestSubServiceExternalProxyMultiProtocol(t *testing.T) {
	s := NewSubService(false, "-ieo")
	s.address = "panel.example.com"

	// VLESS with int port, omitted forceTls and remark should not panic
	vlessInb := &model.Inbound{
		Remark:   "VLESS",
		Protocol: model.VLESS,
		Port:     443,
		Listen:   "0.0.0.0",
		Settings: `{"decryption":"none","clients":[{"id":"11111111-1111-1111-1111-111111111111","email":"u@example.com","enable":true}]}`,
		StreamSettings: `{
			"network":"tcp",
			"security":"tls",
			"tlsSettings":{"serverName":"sni.example.com"},
			"externalProxy":[
				{"dest":"cdn1.example.com","port":2053},
				{"dest":"plain.example.com","port":"80","forceTls":"none","remark":"HTTP"}
			]
		}`,
	}
	vlessLinks := strings.Split(s.getLink(vlessInb, "u@example.com"), "\n")
	if len(vlessLinks) != 2 {
		t.Fatalf("expected 2 vless links, got %d: %v", len(vlessLinks), vlessLinks)
	}
	if !strings.Contains(vlessLinks[0], "@cdn1.example.com:2053?") || !strings.Contains(vlessLinks[0], "security=tls") {
		t.Fatalf("unexpected vless link[0]: %s", vlessLinks[0])
	}
	if !strings.Contains(vlessLinks[1], "@plain.example.com:80?") || !strings.Contains(vlessLinks[1], "security=none") {
		t.Fatalf("unexpected vless link[1]: %s", vlessLinks[1])
	}

	// VMess with omitted forceTls/remark
	vmessInb := &model.Inbound{
		Remark:   "VMESS",
		Protocol: model.VMESS,
		Port:     443,
		Settings: `{"clients":[{"id":"11111111-1111-1111-1111-111111111111","email":"u@example.com","security":"auto","enable":true}]}`,
		StreamSettings: `{
			"network":"ws",
			"security":"tls",
			"externalProxy":[{"dest":"vmess-cdn.example.com","port":8443}]
		}`,
	}
	vmessLink := s.getLink(vmessInb, "u@example.com")
	if !strings.HasPrefix(vmessLink, "vmess://") {
		t.Fatalf("unexpected vmess link: %s", vmessLink)
	}
	rawJSON, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(vmessLink, "vmess://"))
	if err != nil {
		t.Fatalf("decode vmess: %v", err)
	}
	var vmessObj map[string]any
	if err := json.Unmarshal(rawJSON, &vmessObj); err != nil {
		t.Fatalf("unmarshal vmess: %v", err)
	}
	if vmessObj["add"] != "vmess-cdn.example.com" || vmessObj["tls"] != "tls" {
		t.Fatalf("unexpected vmess payload: %+v", vmessObj)
	}

	// TUIC and Naive with externalProxy
	tuicInb := &model.Inbound{
		Remark:   "TUIC",
		Protocol: model.TUIC,
		Port:     443,
		Settings: `{"clients":[{"id":"11111111-1111-1111-1111-111111111111","password":"pw","email":"u@example.com","enable":true}]}`,
		StreamSettings: `{
			"network":"tcp",
			"security":"tls",
			"tlsSettings":{"serverName":"tuic.example.com"},
			"externalProxy":[{"dest":"edge-tuic.example.com","port":2096,"remark":"EU"}]
		}`,
	}
	tuicLink := s.getLink(tuicInb, "u@example.com")
	if !strings.HasPrefix(tuicLink, "tuic://") || !strings.Contains(tuicLink, "@edge-tuic.example.com:2096?") {
		t.Fatalf("unexpected tuic externalProxy link: %s", tuicLink)
	}

	naiveInb := &model.Inbound{
		Remark:   "NAIVE",
		Protocol: model.NAIVE,
		Port:     443,
		Settings: `{"clients":[{"username":"alice","password":"pw","email":"u@example.com","enable":true}]}`,
		StreamSettings: `{
			"security":"tls",
			"tlsSettings":{"serverName":"naive.example.com"},
			"externalProxy":[{"dest":"edge-naive.example.com","port":8443,"remark":"Relay"}]
		}`,
	}
	naiveLink := s.getLink(naiveInb, "u@example.com")
	if !strings.HasPrefix(naiveLink, "naive+https://alice:pw@edge-naive.example.com:8443") {
		t.Fatalf("unexpected naive externalProxy link: %s", naiveLink)
	}

	// Native Xray WireGuard with externalProxy
	srvKey, _ := wgtypes.GeneratePrivateKey()
	cliKey, _ := wgtypes.GeneratePrivateKey()
	wgSettings, _ := json.Marshal(map[string]any{
		"secretKey": srvKey.String(),
		"pubKey":    srvKey.PublicKey().String(),
		"mtu":       1380,
		"clients": []any{
			map[string]any{
				"email":     "u@example.com",
				"addresses": []string{"10.8.0.2/32"},
				"devices": []any{
					map[string]any{
						"privKey": cliKey.String(),
						"pubKey":  cliKey.PublicKey().String(),
					},
				},
			},
		},
	})
	wgInb := &model.Inbound{
		Id:             9,
		Remark:         "WG-Xray",
		Protocol:       model.WireGuard,
		Port:           51820,
		Settings:       string(wgSettings),
		StreamSettings: `{"externalProxy":[{"dest":"wg1.example.com","port":51821,"remark":"Relay1"},{"dest":"wg2.example.com","port":51822,"remark":"Relay2"}]}`,
	}
	wgLinks := strings.Split(s.getLink(wgInb, "u@example.com"), "\n")
	if len(wgLinks) != 2 {
		t.Fatalf("expected 2 wireguard externalProxy links, got %d: %v", len(wgLinks), wgLinks)
	}
	u0, err := url.Parse(wgLinks[0])
	if err != nil || u0.Scheme != "wireguard" || u0.Host != "wg1.example.com:51821" {
		t.Fatalf("unexpected wg link[0]: %q (%v)", wgLinks[0], err)
	}
}

func TestSubClashAndJsonExternalProxyNoMutation(t *testing.T) {
	subSvc := NewSubService(false, "-ieo")
	subSvc.address = "panel.example.com"
	clashSvc := NewSubClashService(subSvc)
	jsonSvc := NewSubJsonService("", "", "", "", subSvc)

	inb := &model.Inbound{
		Remark:   "VLESS",
		Protocol: model.VLESS,
		Listen:   "0.0.0.0",
		Port:     443,
		Settings: `{"decryption":"none","clients":[{"id":"11111111-1111-1111-1111-111111111111","email":"u@example.com","enable":true}]}`,
		StreamSettings: `{
			"network":"ws",
			"security":"none",
			"externalProxy":[
				{"dest":"tls-edge.example.com","port":8443,"forceTls":"tls"},
				{"dest":"plain-edge.example.com","port":8080,"forceTls":"same"}
			]
		}`,
	}
	client := model.Client{
		ID:     "11111111-1111-1111-1111-111111111111",
		Email:  "u@example.com",
		Enable: true,
	}

	proxies := clashSvc.getProxies(inb, client, "panel.example.com")
	if len(proxies) != 2 {
		t.Fatalf("clash proxies len = %d, want 2", len(proxies))
	}
	if inb.Port != 443 || inb.Listen != "0.0.0.0" {
		t.Fatalf("clash getProxies mutated inbound: %s:%d", inb.Listen, inb.Port)
	}
	if proxies[0]["tls"] != true || proxies[1]["tls"] == true {
		t.Fatalf("clash streamSettings leaked forceTls across proxies: %+v", proxies)
	}

	jsonConfigs := jsonSvc.getConfig(inb, client, "panel.example.com")
	if len(jsonConfigs) != 2 {
		t.Fatalf("json configs len = %d, want 2", len(jsonConfigs))
	}
	if inb.Port != 443 || inb.Listen != "0.0.0.0" {
		t.Fatalf("json getConfig mutated inbound: %s:%d", inb.Listen, inb.Port)
	}

	var cfg1, cfg2 map[string]any
	if err := json.Unmarshal(jsonConfigs[0], &cfg1); err != nil {
		t.Fatalf("unmarshal cfg1: %v", err)
	}
	if err := json.Unmarshal(jsonConfigs[1], &cfg2); err != nil {
		t.Fatalf("unmarshal cfg2: %v", err)
	}
	obs2, _ := cfg2["outbounds"].([]any)
	firstOb2, _ := obs2[0].(map[string]any)
	stream2, _ := firstOb2["streamSettings"].(map[string]any)
	if stream2["security"] != "none" {
		t.Fatalf("json getConfig leaked security=tls from first externalProxy to second: %+v", stream2)
	}
}

func TestVlessFlowFallbackAcrossLinkClashAndJson(t *testing.T) {
	subSvc := NewSubService(false, "-ieo")
	subSvc.address = "panel.example.com"
	clashSvc := NewSubClashService(subSvc)
	jsonSvc := NewSubJsonService("", "", "", "", subSvc)

	extractJSONFlow := func(t *testing.T, raw json.RawMessage) string {
		t.Helper()
		var cfg map[string]any
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("unmarshal json config: %v", err)
		}
		obs, _ := cfg["outbounds"].([]any)
		if len(obs) == 0 {
			t.Fatalf("missing outbounds in json config: %+v", cfg)
		}
		firstOb, _ := obs[0].(map[string]any)
		settings, _ := firstOb["settings"].(map[string]any)
		vnext, _ := settings["vnext"].([]any)
		if len(vnext) == 0 {
			t.Fatalf("missing vnext in outbound settings: %+v", settings)
		}
		srv, _ := vnext[0].(map[string]any)
		users, _ := srv["users"].([]any)
		if len(users) == 0 {
			t.Fatalf("missing users in vnext: %+v", srv)
		}
		usr, _ := users[0].(map[string]any)
		flow, _ := usr["flow"].(string)
		return flow
	}

	// (a) TCP + TLS with empty client flow inherits inbound settings.flow
	inbFallback := &model.Inbound{
		Remark:         "VLESS-TCP-TLS",
		Protocol:       model.VLESS,
		Listen:         "0.0.0.0",
		Port:           443,
		Settings:       `{"decryption":"none","flow":"xtls-rprx-vision","clients":[{"id":"11111111-1111-1111-1111-111111111111","email":"empty@example.com","flow":"","enable":true}]}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"sni.example.com"}}`,
	}
	linkA := sgetLinkOrFail(t, subSvc, inbFallback, "empty@example.com")
	uA, err := url.Parse(linkA)
	if err != nil {
		t.Fatalf("parse linkA: %v", err)
	}
	if got := uA.Query().Get("flow"); got != "xtls-rprx-vision" {
		t.Fatalf("linkA flow = %q, want %q (%s)", got, "xtls-rprx-vision", linkA)
	}
	clientEmpty := model.Client{ID: "11111111-1111-1111-1111-111111111111", Email: "empty@example.com", Enable: true}
	proxiesA := clashSvc.getProxies(inbFallback, clientEmpty, "panel.example.com")
	if len(proxiesA) != 1 || proxiesA[0]["flow"] != "xtls-rprx-vision" {
		t.Fatalf("clash proxiesA flow mismatch: %+v", proxiesA)
	}
	jsonA := jsonSvc.getConfig(inbFallback, clientEmpty, "panel.example.com")
	if len(jsonA) != 1 {
		t.Fatalf("jsonA len = %d, want 1", len(jsonA))
	}
	if got := extractJSONFlow(t, []byte(jsonA[0])); got != "xtls-rprx-vision" {
		t.Fatalf("jsonA flow = %q, want %q", got, "xtls-rprx-vision")
	}

	// (b) WS + none must NOT emit flow even if stale inbound settings.flow exists
	inbWS := &model.Inbound{
		Remark:         "VLESS-WS-NONE",
		Protocol:       model.VLESS,
		Listen:         "0.0.0.0",
		Port:           8080,
		Settings:       `{"decryption":"none","flow":"xtls-rprx-vision","clients":[{"id":"22222222-2222-2222-2222-222222222222","email":"ws@example.com","flow":"","enable":true}]}`,
		StreamSettings: `{"network":"ws","security":"none","wsSettings":{"path":"/ws"}}`,
	}
	linkB := sgetLinkOrFail(t, subSvc, inbWS, "ws@example.com")
	uB, err := url.Parse(linkB)
	if err != nil {
		t.Fatalf("parse linkB: %v", err)
	}
	if got := uB.Query().Get("flow"); got != "" {
		t.Fatalf("ws+none linkB unexpectedly emitted flow=%q (%s)", got, linkB)
	}
	clientWS := model.Client{ID: "22222222-2222-2222-2222-222222222222", Email: "ws@example.com", Enable: true}
	proxiesB := clashSvc.getProxies(inbWS, clientWS, "panel.example.com")
	if len(proxiesB) != 1 {
		t.Fatalf("clash proxiesB len = %d, want 1", len(proxiesB))
	}
	if flowVal, exists := proxiesB[0]["flow"]; exists && flowVal != "" {
		t.Fatalf("clash ws+none unexpectedly emitted flow=%v: %+v", flowVal, proxiesB[0])
	}
	jsonB := jsonSvc.getConfig(inbWS, clientWS, "panel.example.com")
	if len(jsonB) != 1 {
		t.Fatalf("jsonB len = %d, want 1", len(jsonB))
	}
	if got := extractJSONFlow(t, []byte(jsonB[0])); got != "" {
		t.Fatalf("jsonB ws+none unexpectedly emitted flow=%q", got)
	}

	// (c) TCP + TLS with explicit client flow overrides inbound settings.flow
	inbOverride := &model.Inbound{
		Remark:         "VLESS-TCP-OVERRIDE",
		Protocol:       model.VLESS,
		Listen:         "0.0.0.0",
		Port:           443,
		Settings:       `{"decryption":"none","flow":"xtls-rprx-vision","clients":[{"id":"33333333-3333-3333-3333-333333333333","email":"explicit@example.com","flow":"xtls-rprx-vision-udp443","enable":true}]}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"sni.example.com"}}`,
	}
	linkC := sgetLinkOrFail(t, subSvc, inbOverride, "explicit@example.com")
	uC, err := url.Parse(linkC)
	if err != nil {
		t.Fatalf("parse linkC: %v", err)
	}
	if got := uC.Query().Get("flow"); got != "xtls-rprx-vision-udp443" {
		t.Fatalf("linkC flow = %q, want %q (%s)", got, "xtls-rprx-vision-udp443", linkC)
	}
	clientExplicit := model.Client{
		ID:     "33333333-3333-3333-3333-333333333333",
		Email:  "explicit@example.com",
		Flow:   "xtls-rprx-vision-udp443",
		Enable: true,
	}
	proxiesC := clashSvc.getProxies(inbOverride, clientExplicit, "panel.example.com")
	if len(proxiesC) != 1 || proxiesC[0]["flow"] != "xtls-rprx-vision-udp443" {
		t.Fatalf("clash proxiesC flow mismatch: %+v", proxiesC)
	}
	jsonC := jsonSvc.getConfig(inbOverride, clientExplicit, "panel.example.com")
	if len(jsonC) != 1 {
		t.Fatalf("jsonC len = %d, want 1", len(jsonC))
	}
	if got := extractJSONFlow(t, []byte(jsonC[0])); got != "xtls-rprx-vision-udp443" {
		t.Fatalf("jsonC flow = %q, want %q", got, "xtls-rprx-vision-udp443")
	}
}

func sgetLinkOrFail(t *testing.T, s *SubService, inb *model.Inbound, email string) string {
	t.Helper()
	link := s.getLink(inb, email)
	if link == "" {
		t.Fatalf("getLink(%s, %s) returned empty string", inb.Remark, email)
	}
	return link
}
