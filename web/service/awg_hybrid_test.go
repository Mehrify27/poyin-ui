package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestAwgBackwardCompatAndClientRendering(t *testing.T) {
	// Legacy AWG 1.0 settings JSON (no backend, s3, s4, i1..i5 keys).
	legacyJSON := `{
		"serverPrivKey": "uN9Y2L0F1Z2xM5M6e0aQe4r1k3uY2z3H2V1P0k1A3F0=",
		"serverPubKey":  "x9R1Y2L0F1Z2xM5M6e0aQe4r1k3uY2z3H2V1P0k1A3F0=",
		"dns1": "1.1.1.1",
		"dns2": "1.0.0.1",
		"mtu": 1420,
		"jc": 4,
		"jmin": 8,
		"jmax": 80,
		"s1": 77,
		"s2": 90,
		"h1": "123456",
		"h2": "223456",
		"h3": "323456",
		"h4": "423456",
		"ipRanges": ["10.66.0.2-10.66.0.254"],
		"userLimit": 1,
		"clients": [
			{
				"email": "alice",
				"enable": true,
				"devices": [
					{
						"privKey": "cPrivKeyPlaceholder==",
						"pubKey": "cPubKeyPlaceholder=="
					}
				]
			}
		]
	}`

	var st awgSettings
	if err := json.Unmarshal([]byte(legacyJSON), &st); err != nil {
		t.Fatalf("unmarshal legacy awgSettings failed: %v", err)
	}
	obfs1 := st.resolveObfs()
	if obfs1.Backend != AwgBackendAuto || obfs1.RequiresAWG2() {
		t.Fatalf("legacy AWG 1.0 resolveObfs unexpected: %+v", obfs1)
	}

	var outSt awgOutSettings
	legacyOutJSON := `{
		"privateKey": "p",
		"peerPublicKey": "q",
		"endpoint": "1.2.3.4:51820",
		"jc": 5, "jmin": 10, "jmax": 60, "s1": 20, "s2": 30,
		"h1": "111", "h2": "222", "h3": "333", "h4": "444"
	}`
	if err := json.Unmarshal([]byte(legacyOutJSON), &outSt); err != nil {
		t.Fatalf("unmarshal legacy awgOutSettings failed: %v", err)
	}
	if outObfs := outSt.obfs(); outObfs.Backend != AwgBackendAuto || outObfs.RequiresAWG2() || outObfs.S1 != 20 {
		t.Fatalf("legacy awgOutSettings.obfs() unexpected: %+v", outObfs)
	}

	svc := &AwgService{}
	inbound1 := &model.Inbound{Id: 1, Protocol: model.AWG, Port: 51820, Settings: legacyJSON}
	cfgs1, err := svc.RenderClientConfigs(inbound1, "alice", "vpn.example.com")
	if err != nil || len(cfgs1) != 1 {
		t.Fatalf("RenderClientConfigs(AWG 1.0) failed: len=%d err=%v", len(cfgs1), err)
	}
	if strings.Contains(cfgs1[0].Config, "S3 =") || strings.Contains(cfgs1[0].Config, "S4 =") || strings.Contains(cfgs1[0].Config, "I1 =") {
		t.Fatalf("AWG 1.0 client config must omit S3/S4/I1..I5, got:\n%s", cfgs1[0].Config)
	}
	params1, err := svc.RenderClientParams(inbound1, "alice", "vpn.example.com")
	if err != nil || len(params1) != 1 || params1[0].S3 != 0 || params1[0].I1 != "" {
		t.Fatalf("RenderClientParams(AWG 1.0) unexpected: %+v, err=%v", params1, err)
	}

	// Modern AWG 2.0 config.
	v2JSON := `{
		"serverPrivKey": "uN9Y2L0F1Z2xM5M6e0aQe4r1k3uY2z3H2V1P0k1A3F0=",
		"serverPubKey":  "x9R1Y2L0F1Z2xM5M6e0aQe4r1k3uY2z3H2V1P0k1A3F0=",
		"dns1": "1.1.1.1",
		"mtu": 1420,
		"backend": "userspace",
		"jc": 4, "jmin": 8, "jmax": 80,
		"s1": 77, "s2": 90, "s3": 15, "s4": 25,
		"h1": "100000-200000", "h2": "200001-300000", "h3": "300001-400000", "h4": "400001-500000",
		"i1": "<b 0x16030100><c><t><r 12>",
		"i2": "<rc 8>",
		"ipRanges": ["10.66.0.2-10.66.0.254"],
		"userLimit": 1,
		"clients": [
			{
				"email": "alice",
				"enable": true,
				"devices": [{"privKey": "cPriv==", "pubKey": "cPub=="}]
			}
		]
	}`
	inbound2 := &model.Inbound{Id: 2, Protocol: model.AWG, Port: 51821, Settings: v2JSON}
	cfgs2, err := svc.RenderClientConfigs(inbound2, "alice", "vpn.example.com")
	if err != nil || len(cfgs2) != 1 {
		t.Fatalf("RenderClientConfigs(AWG 2.0) failed: len=%d err=%v", len(cfgs2), err)
	}
	for _, wantLine := range []string{
		"S3 = 15",
		"S4 = 25",
		"H1 = 100000-200000",
		"I1 = <b 0x16030100><c><t><r 12>",
		"I2 = <rc 8>",
	} {
		if !strings.Contains(cfgs2[0].Config, wantLine) {
			t.Fatalf("AWG 2.0 config missing %q:\n%s", wantLine, cfgs2[0].Config)
		}
	}
	params2, err := svc.RenderClientParams(inbound2, "alice", "vpn.example.com")
	if err != nil || len(params2) != 1 || params2[0].S3 != 15 || params2[0].S4 != 25 || params2[0].H1 != "100000-200000" || params2[0].I1 != "<b 0x16030100><c><t><r 12>" {
		t.Fatalf("RenderClientParams(AWG 2.0) unexpected: %+v, err=%v", params2, err)
	}
}

func TestValidateAwgSettingsV2(t *testing.T) {
	filled, err := FillSettingsDefaults(model.AWG, `{}`)
	if err != nil {
		t.Fatalf("FillSettingsDefaults(AWG) failed: %v", err)
	}
	if err := ValidateProtocolSettings(model.AWG, filled); err != nil {
		t.Fatalf("ValidateProtocolSettings rejected default AWG JSON: %v", err)
	}

	validCases := []string{
		`{"jc":4,"jmin":8,"jmax":80,"s1":77,"s2":90}`,
		`{"backend":"auto","s3":12,"s4":24,"h1":"1000-2000","h2":"2001-3000","h3":"3001-4000","h4":"4001-5000","i1":"<b 0xdead><c><rd 4>"}`,
		`{"backend":"userspace"}`,
	}
	for _, raw := range validCases {
		if err := ValidateProtocolSettings(model.AWG, raw); err != nil {
			t.Fatalf("ValidateProtocolSettings unexpectedly rejected %s: %v", raw, err)
		}
	}

	invalidCases := []struct {
		name string
		body string
	}{
		{"invalid backend", `{"backend":"ebpf"}`},
		{"negative s3", `{"s3":-1}`},
		{"negative s4", `{"s4":-5}`},
		{"oversized s4", `{"s4":65520}`},
		{"overlapping headers", `{"h1":"100-200","h2":"150-250","h3":"300","h4":"400"}`},
		{"bad cps syntax", `{"i1":"not-a-tag"}`},
		{"jmin exceeds jmax", `{"jmin":100,"jmax":50}`},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateProtocolSettings(model.AWG, tc.body); err == nil {
				t.Fatalf("expected error for %s (%s), got nil", tc.name, tc.body)
			}
		})
	}
}
