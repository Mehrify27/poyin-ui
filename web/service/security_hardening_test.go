package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/entity"
)

const (
	testValidWgPriv = "WJBYsg2KO4OHc00UkfDXi79cawNyZNJfPWdtF6vb1mw="
	testValidWgPub  = "W6WUZ4OXkeTjygoaWIlMnbZBqibaP2lSFzhUeOQ2kVY="
)

func TestWireGuardAndAWGConfigInjectionBlocked(t *testing.T) {
	// 1. Inbound protocol validation must reject PostUp/newline injections and bad server keys.
	badSettings := []struct {
		proto model.Protocol
		name  string
		body  string
	}{
		{
			proto: model.WGC,
			name:  "wgc externalProxy dest newline PostUp",
			body: `{
				"serverPrivKey": "` + testValidWgPriv + `",
				"serverPubKey": "` + testValidWgPub + `",
				"ipRanges": ["10.66.0.2-10.66.0.254"],
				"externalProxy": [{"dest": "1.2.3.4\nPostUp = /bin/sh", "port": 51820}],
				"clients": [{"email": "alice", "enable": true, "privKey": "` + testValidWgPriv + `", "pubKey": "` + testValidWgPub + `"}]
			}`,
		},
		{
			proto: model.WGC,
			name:  "wgc invalid serverPrivKey",
			body: `{
				"serverPrivKey": "not-a-valid-key",
				"serverPubKey": "` + testValidWgPub + `",
				"ipRanges": ["10.66.0.2-10.66.0.254"],
				"clients": []
			}`,
		},
		{
			proto: model.AWG,
			name:  "awg client privKey PreDown injection",
			body: `{
				"serverPrivKey": "` + testValidWgPriv + `",
				"serverPubKey": "` + testValidWgPub + `",
				"ipRanges": ["10.67.0.2-10.67.0.254"],
				"clients": [{"email": "bob", "enable": true, "privKey": "` + testValidWgPriv + `\r\nPreDown = id", "pubKey": "` + testValidWgPub + `"}]
			}`,
		},
	}

	for _, tc := range badSettings {
		if err := ValidateProtocolSettings(tc.proto, tc.body); err == nil {
			t.Fatalf("%s: expected ValidateProtocolSettings to reject injection", tc.name)
		}
	}

	// 2. RenderClientConfigs for WG-C and AWG must refuse injected endpointHost or stored INI injection.
	wgcInb := &model.Inbound{
		Id:       42,
		Port:     51820,
		Protocol: model.WGC,
		Settings: `{
			"serverPrivKey": "` + testValidWgPriv + `",
			"serverPubKey": "` + testValidWgPub + `",
			"ipRanges": ["10.66.0.2-10.66.0.254"],
			"dns1": "1.1.1.1",
			"clients": [{"email": "alice", "enable": true, "privKey": "` + testValidWgPriv + `", "pubKey": "` + testValidWgPub + `"}]
		}`,
	}
	if _, err := (&WgcService{}).RenderClientConfigs(wgcInb, "alice", "vpn.example.com\nPostUp = curl evil"); err == nil {
		t.Fatalf("WgcService.RenderClientConfigs accepted newline PostUp injection in endpointHost")
	}

	awgInb := &model.Inbound{
		Id:       43,
		Port:     51821,
		Protocol: model.AWG,
		Settings: `{
			"serverPrivKey": "` + testValidWgPriv + `",
			"serverPubKey": "` + testValidWgPub + `",
			"ipRanges": ["10.67.0.2-10.67.0.254"],
			"h1": "10\nPostUp = id",
			"clients": [{"email": "bob", "enable": true, "privKey": "` + testValidWgPriv + `", "pubKey": "` + testValidWgPub + `"}]
		}`,
	}
	if _, err := (&AwgService{}).RenderClientConfigs(awgInb, "bob", "vpn.example.com"); err == nil {
		t.Fatalf("AwgService.RenderClientConfigs accepted injected newline PostUp in h1")
	}

	// 3. Outbound drivers (WireGuard & AmneziaWG) must accept clean config and reject injected scalars.
	wgDrv := &wgOutDriver{}
	validWG, _ := json.Marshal(wgOutSettings{
		PrivateKey:    testValidWgPriv,
		PeerPublicKey: testValidWgPub,
		Endpoint:      "198.51.100.1:51820",
		Address:       "10.0.0.2/32",
		Mtu:           1280,
	})
	if err := wgDrv.Validate(VpnOutboundConfig{Tag: "wg1", Kind: "wireguard", Settings: validWG}); err != nil {
		t.Fatalf("valid wgOutSettings rejected: %v", err)
	}
	injWG, _ := json.Marshal(wgOutSettings{
		PrivateKey:    testValidWgPriv,
		PeerPublicKey: testValidWgPub,
		Endpoint:      "198.51.100.1:51820\nPostUp = id",
		Address:       "10.0.0.2/32",
		Mtu:           1280,
	})
	if err := wgDrv.Validate(VpnOutboundConfig{Tag: "wg1", Kind: "wireguard", Settings: injWG}); err == nil {
		t.Fatalf("wgOutDriver.Validate accepted newline PostUp in Endpoint")
	}

	awgDrv := &awgOutDriver{}
	injAWG, _ := json.Marshal(awgOutSettings{
		PrivateKey:    testValidWgPriv,
		PeerPublicKey: testValidWgPub,
		Endpoint:      "198.51.100.2:51820",
		Address:       "10.0.0.2/32",
		H1:            "10\r\nPreDown = id",
	})
	if err := awgDrv.Validate(VpnOutboundConfig{Tag: "awg1", Kind: "awg", Settings: injAWG}); err == nil {
		t.Fatalf("awgOutDriver.Validate accepted CRLF PreDown in H1")
	}
}

func TestSystemdSaveServiceValidation(t *testing.T) {
	svc := &SystemdService{}
	allowed := "/usr/local/vpn-ui/vpn-ui"

	// Traversal or shell hook in unit must be rejected before systemctl / disk writes.
	if err := svc.SaveService(SaveServiceRequest{Name: "../evil", Unit: DefaultUnit("vpn-ui")}); err == nil {
		t.Fatalf("SaveService accepted traversal service name")
	}

	cleanUnit := `[Unit]
Description=vpn-ui
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/vpn-ui/vpn-ui

[Install]
WantedBy=multi-user.target
`
	if name, _, err := validateSaveServiceRequest(SaveServiceRequest{Name: "vpn-ui.service", Unit: cleanUnit}, allowed); err != nil || name != "vpn-ui" {
		t.Fatalf("expected clean unit matching binary to validate, got (%q, %v)", name, err)
	}

	maliciousExec := strings.Replace(cleanUnit, "ExecStart=/usr/local/vpn-ui/vpn-ui", "ExecStart=/bin/sh -c id", 1)
	if _, _, err := validateSaveServiceRequest(SaveServiceRequest{Name: "vpn-ui", Unit: maliciousExec}, allowed); err == nil {
		t.Fatalf("validateSaveServiceRequest accepted unauthorized ExecStart=/bin/sh")
	}
	hookInjected := strings.Replace(cleanUnit, "Type=simple", "Type=simple\nExecStartPre=/bin/touch /tmp/pwn", 1)
	if _, _, err := validateSaveServiceRequest(SaveServiceRequest{Name: "vpn-ui", Unit: hookInjected}, allowed); err == nil {
		t.Fatalf("validateSaveServiceRequest accepted ExecStartPre hook")
	}
}

func TestAdminAndUserPasswordHygiene(t *testing.T) {
	adminSvc := newAdminDB(t)
	t.Cleanup(func() { _ = database.CloseDB() })

	userSvc := &UserService{}
	for _, bad := range []string{"", "   ", "admin", "Admin", "ADMIN"} {
		if err := userSvc.UpdateFirstUser("root", bad); err == nil {
			t.Fatalf("UpdateFirstUser accepted forbidden password %q", bad)
		}
		if err := userSvc.UpdateUser(1, "root", bad); err == nil {
			t.Fatalf("UpdateUser accepted forbidden password %q", bad)
		}
		if _, err := adminSvc.AddAdmin(AdminSpec{
			Username: "ops1",
			Password: bad,
			Enable:   true,
		}); err == nil {
			t.Fatalf("AddAdmin accepted forbidden password %q", bad)
		}
	}

	created, err := adminSvc.AddAdmin(AdminSpec{
		Username: "ops1",
		Password: "Str0ng!Password9",
		Enable:   true,
	})
	if err != nil {
		t.Fatalf("AddAdmin valid password failed: %v", err)
	}
	if err := adminSvc.UpdateAdmin(created.Id, AdminSpec{
		Username: "ops1",
		Password: "admin",
		Enable:   true,
	}); err == nil {
		t.Fatalf("UpdateAdmin accepted literal 'admin' password")
	}
}

func TestAllSettingRejectsInvalidTrustedProxies(t *testing.T) {
	newAdminDB(t)
	t.Cleanup(func() { _ = database.CloseDB() })

	ss := &SettingService{}
	base := &entity.AllSetting{
		WebPort:       2053,
		SubPort:       2096,
		WebBasePath:   "/",
		SubPath:       "/sub/",
		SubJsonPath:   "/json/",
		SubClashPath:  "/clash/",
		PageSize:      25,
		SessionMaxAge: 60,
		TimeLocation:  "UTC",
		SubUpdates:    10,
	}

	bad := *base
	bad.TrustedProxies = "not-an-ip-or-cidr"
	if err := ss.UpdateAllSetting(&bad); err == nil {
		t.Fatalf("UpdateAllSetting accepted invalid TrustedProxies")
	}

	good := *base
	good.TrustedProxies = "127.0.0.1,10.0.0.0/8"
	if err := ss.UpdateAllSetting(&good); err != nil {
		t.Fatalf("UpdateAllSetting rejected valid TrustedProxies: %v", err)
	}
	if got := ss.GetTrustedProxyPrefixes(); len(got) != 2 {
		t.Fatalf("GetTrustedProxyPrefixes len = %d, want 2", len(got))
	}

	none := *base
	none.TrustedProxies = "none"
	if err := ss.UpdateAllSetting(&none); err != nil {
		t.Fatalf("UpdateAllSetting rejected TrustedProxies=none: %v", err)
	}
	if got := ss.GetTrustedProxyPrefixes(); len(got) != 0 {
		t.Fatalf("GetTrustedProxyPrefixes(none) len = %d, want 0", len(got))
	}
}
