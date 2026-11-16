package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/xray"
)

func TestPrepareHy2OutboundSaveValidationAndSecrets(t *testing.T) {
	stubAlloc := func(used map[int]bool) (int, error) {
		for p := hy2OutPortFirst; p <= hy2OutPortLast; p++ {
			if !used[p] {
				return p, nil
			}
		}
		return 0, nil
	}

	// Missing fields fail clearly.
	badInputs := []Hysteria2OutboundConfig{
		{Address: "hy2.example.com", Password: "pw"},
		{Tag: "hy2-1", Password: "pw"},
		{Tag: "hy2-1", Address: "hy2.example.com"},
		{Tag: "hy2-1", Address: "hy2.example.com", Password: "pw", ObfsType: "salamander"},
		{Tag: "hy2-1", Address: "hy2.example.com", Password: "pw", HopPorts: "200-100"},
		{Tag: "hy2-1", Address: "hy2.example.com", Password: "pw", HopInterval: "not-a-duration"},
	}
	for i, bad := range badInputs {
		if _, _, err := prepareHy2OutboundSave(bad, nil, stubAlloc); err == nil {
			t.Fatalf("case %d: expected validation error for %+v", i, bad)
		}
	}

	// Valid create allocates port, defaults 443, and normalizes obfs "none".
	saved1, list1, err := prepareHy2OutboundSave(Hysteria2OutboundConfig{
		Tag:          "hy2-1",
		Address:      "hy2.example.com",
		Password:     "top-secret",
		ObfsType:     "none",
		ObfsPassword: "stale",
		Via:          "  wg-a  ",
	}, nil, stubAlloc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if saved1.Port != 443 || saved1.SocksPort != hy2OutPortFirst || saved1.ObfsType != "" || saved1.ObfsPassword != "" || saved1.Via != "wg-a" {
		t.Fatalf("unexpected prepared config: %+v", saved1)
	}

	// Edit preserves blank secrets & SocksPort, while clearing Via and changing port.
	edited, _, err := prepareHy2OutboundSave(Hysteria2OutboundConfig{
		Tag:     "hy2-1",
		Address: "hy2.example.com",
		Port:    8443,
		Via:     "",
	}, list1, stubAlloc)
	if err != nil {
		t.Fatalf("edit failed: %v", err)
	}
	if edited.Password != "top-secret" || edited.SocksPort != hy2OutPortFirst || edited.Port != 8443 || edited.Via != "" {
		t.Fatalf("unexpected edited config: %+v", edited)
	}
}

func TestBuildHy2OutboundSingboxConfig(t *testing.T) {
	// Single port configuration
	singleBytes, err := buildHy2OutboundSingboxConfig(Hysteria2OutboundConfig{
		Tag:       "hy2-single",
		Address:   "edge.example.com",
		Port:      8443,
		Password:  "secret-pw",
		SocksPort: 11310,
	})
	if err != nil {
		t.Fatalf("buildHy2OutboundSingboxConfig single: %v", err)
	}
	var singleDoc map[string]any
	if err := json.Unmarshal(singleBytes, &singleDoc); err != nil {
		t.Fatal(err)
	}
	inb := singleDoc["inbounds"].([]any)[0].(map[string]any)
	if inb["type"] != "socks" || inb["listen"] != "127.0.0.1" || int(inb["listen_port"].(float64)) != 11310 {
		t.Fatalf("unexpected local socks inbound: %v", inb)
	}
	hyOut := singleDoc["outbounds"].([]any)[0].(map[string]any)
	if hyOut["type"] != "hysteria2" || int(hyOut["server_port"].(float64)) != 8443 || hyOut["password"] != "secret-pw" {
		t.Fatalf("unexpected single hysteria2 outbound: %v", hyOut)
	}
	if _, hasPorts := hyOut["server_ports"]; hasPorts {
		t.Fatal("server_ports must be omitted when hopPorts is empty")
	}

	// Port hopping configuration omits server_port and formats server_ports with colon separator.
	hopBytes, err := buildHy2OutboundSingboxConfig(Hysteria2OutboundConfig{
		Tag:          "hy2-hop",
		Address:      "edge.example.com",
		Port:         443,
		HopPorts:     "443, 20000-20100",
		HopInterval:  "30s",
		Password:     "pw",
		ObfsType:     "salamander",
		ObfsPassword: "obfs-pw",
		UpMbps:       50,
		DownMbps:     200,
		ServerName:   "sni.example.com",
		AllowInsecure: true,
		SocksPort:    11311,
	})
	if err != nil {
		t.Fatalf("buildHy2OutboundSingboxConfig hop: %v", err)
	}
	var hopDoc map[string]any
	if err := json.Unmarshal(hopBytes, &hopDoc); err != nil {
		t.Fatal(err)
	}
	hopOut := hopDoc["outbounds"].([]any)[0].(map[string]any)
	if _, hasSinglePort := hopOut["server_port"]; hasSinglePort {
		t.Fatal("server_port must be omitted when server_ports is set")
	}
	sp := hopOut["server_ports"].([]any)
	if len(sp) != 2 || sp[0] != "443" || sp[1] != "20000:20100" {
		t.Fatalf("unexpected sing-box server_ports format: %v", sp)
	}
	if hopOut["hop_interval"] != "30s" {
		t.Fatalf("missing hop_interval: %v", hopOut)
	}
	obfs := hopOut["obfs"].(map[string]any)
	if obfs["type"] != "salamander" || obfs["password"] != "obfs-pw" {
		t.Fatalf("unexpected obfs block: %v", obfs)
	}
	tlsCfg := hopOut["tls"].(map[string]any)
	if tlsCfg["server_name"] != "sni.example.com" || tlsCfg["insecure"] != true {
		t.Fatalf("unexpected tls block: %v", tlsCfg)
	}
}

func TestApplyHysteria2OutboundsAndTemplateReconcile(t *testing.T) {
	cfg := &xray.Config{OutboundConfigs: []byte(`[
		{"tag":"direct","protocol":"freedom"},
		{"tag":"hy2-1","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":11310}]}}
	]`)}

	if err := applyHysteria2OutboundsWith(cfg, []Hysteria2OutboundConfig{
		{Tag: "hy2-1", SocksPort: 11350},
		{Tag: "hy2-2", SocksPort: 11351},
		{Tag: "hy2-down", SocksPort: 0},
	}); err != nil {
		t.Fatal(err)
	}

	byTag := tags(t, cfg.OutboundConfigs)
	if len(byTag) != 3 {
		t.Fatalf("expected 3 outbounds, got %d: %v", len(byTag), byTag)
	}
	if port(t, byTag["hy2-1"]) != 11350 {
		t.Fatalf("stale hy2 port not replaced: %v", byTag["hy2-1"])
	}
	if port(t, byTag["hy2-2"]) != 11351 {
		t.Fatalf("missing hy2 outbound not synthesized: %v", byTag["hy2-2"])
	}
	if _, ok := byTag["hy2-down"]; ok {
		t.Fatal("outbound without bound loopback port must be skipped")
	}

	rawTpl := `{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`
	reconciled := reconcileXrayTemplateOutboundsFull(rawTpl, nil, nil, []Hysteria2OutboundConfig{
		{Tag: "hy2-reconcile", SocksPort: 11320},
	})
	if !strings.Contains(reconciled, `"hy2-reconcile"`) || !strings.Contains(reconciled, `11320`) {
		t.Fatalf("reconcileXrayTemplateOutboundsFull did not insert hy2 outbound: %s", reconciled)
	}
}

func TestCreateTestConfigFullSynthesizesHy2Outbound(t *testing.T) {
	cfg := (&OutboundService{}).createTestConfigFull(
		"hy2-edge",
		[]any{map[string]any{"tag": "direct", "protocol": "freedom"}},
		31899,
		nil,
		nil,
		[]Hysteria2OutboundConfig{{Tag: "hy2-edge", SocksPort: 11388}},
	)
	byTag := tags(t, cfg.OutboundConfigs)
	ob, ok := byTag["hy2-edge"]
	if !ok {
		t.Fatal("createTestConfigFull dropped hy2-edge")
	}
	if ob["protocol"] != "socks" || port(t, ob) != 11388 {
		t.Fatalf("unexpected synthesized test outbound: %v", ob)
	}
}
