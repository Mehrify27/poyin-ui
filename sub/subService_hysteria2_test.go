package sub

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func hysteria2TestInbound(listen string, port int, settings string) *model.Inbound {
	return &model.Inbound{
		Id:       42,
		Remark:   "hy2-node",
		Listen:   listen,
		Port:     port,
		Protocol: model.Hysteria2,
		Enable:   true,
		Settings: settings,
	}
}

func TestGenHysteria2LinkAndParity(t *testing.T) {
	s := &SubService{address: "vpn.example.com", remarkModel: "-i"}

	inb := hysteria2TestInbound("0.0.0.0", 443, `{
		"serverName": "cdn.example.com",
		"alpn": ["h3"],
		"allowInsecure": true,
		"pinSHA256": "aabbcc",
		"fingerprint": "chrome",
		"obfsType": "salamander",
		"obfsPassword": "obfs-key",
		"hopPorts": "20000-20100",
		"clients": [
			{"email": "alice", "auth": "p@ss:word", "enable": true}
		]
	}`)

	got := s.genHysteriaLink(inb, "alice")
	want := "hysteria2://p%40ss%3Aword@vpn.example.com:443?alpn=h3&fp=chrome&insecure=1&mport=20000-20100&obfs=salamander&obfs-password=obfs-key&pinSHA256=aabbcc&sni=cdn.example.com#hy2-node"
	if got != want {
		t.Fatalf("genHysteriaLink mismatch:\n got=%q\nwant=%q", got, want)
	}

	// External proxy fan-out produces one link per endpoint.
	inbExt := hysteria2TestInbound("0.0.0.0", 443, `{
		"serverName": "edge.example.com",
		"clients": [{"email": "bob", "auth": "pw", "enable": true}],
		"externalProxy": [
			{"dest": "198.51.100.1", "port": 8443, "remark": "relay1"},
			{"dest": "2001:db8::1", "port": 9443, "remark": "v6"}
		]
	}`)
	extOut := s.genHysteriaLink(inbExt, "bob")
	lines := strings.Split(extOut, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 fanned-out links, got %d: %q", len(lines), extOut)
	}
	if !strings.HasPrefix(lines[0], "hysteria2://pw@198.51.100.1:8443?") || !strings.HasPrefix(lines[1], "hysteria2://pw@[2001:db8::1]:9443?") {
		t.Fatalf("unexpected external proxy endpoints: %v", lines)
	}
}

func TestBuildClashHysteria2Proxy(t *testing.T) {
	subSvc := &SubService{address: "vpn.example.com", remarkModel: "-i"}
	clashSvc := NewSubClashService(subSvc)

	inb := hysteria2TestInbound("0.0.0.0", 443, `{
		"serverName": "cdn.example.com",
		"alpn": ["h3"],
		"allowInsecure": true,
		"fingerprint": "chrome",
		"pinSHA256": "deadbeef",
		"obfsType": "salamander",
		"obfsPassword": "mask-pw",
		"hopPorts": "20000-20100",
		"hopInterval": "45s",
		"upMbps": 80,
		"downMbps": 300,
		"clients": [{"email": "alice", "auth": "alice-pw", "enable": true}]
	}`)
	client := model.Client{Email: "alice", Auth: "alice-pw", Enable: true}
	proxies := clashSvc.getProxies(inb, client, "vpn.example.com")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	p := proxies[0]
	if p["type"] != "hysteria2" || p["password"] != "alice-pw" || p["sni"] != "cdn.example.com" {
		t.Fatalf("unexpected base fields: %v", p)
	}
	if p["skip-cert-verify"] != true || p["fingerprint"] != "deadbeef" || p["client-fingerprint"] != "chrome" {
		t.Fatalf("unexpected TLS fields: %v", p)
	}
	if p["obfs"] != "salamander" || p["obfs-password"] != "mask-pw" || p["ports"] != "20000-20100" || p["hop-interval"] != 45 {
		t.Fatalf("unexpected obfs/hop fields: %v", p)
	}
	if p["up"] != "80 Mbps" || p["down"] != "300 Mbps" {
		t.Fatalf("unexpected bandwidth fields: %v", p)
	}
}

func TestSubJsonHysteria2DoesNotPanicAndMapsFields(t *testing.T) {
	jsonSvc := NewSubJsonService("", "", "", "", &SubService{address: "vpn.example.com", remarkModel: "-i"})

	// Native hysteria2 inbound has no StreamSettings; must not panic on missing hysteriaSettings.
	inb := hysteria2TestInbound("203.0.113.10", 443, `{
		"serverName": "sni.example.com",
		"obfsType": "salamander",
		"obfsPassword": "obfs-secret",
		"allowInsecure": true,
		"clients": [{"email": "alice", "auth": "hy2-auth", "enable": true}]
	}`)
	raw := jsonSvc.genHy(inb, map[string]any{}, model.Client{Email: "alice", Auth: "hy2-auth"})
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("invalid subJson output: %v\nraw=%s", err, string(raw))
	}
	if parsed["protocol"] != "hysteria" {
		t.Fatalf("expected xray outbound protocol hysteria, got %v", parsed["protocol"])
	}
	stream := parsed["streamSettings"].(map[string]any)
	hyStream := stream["hysteriaSettings"].(map[string]any)
	if hyStream["auth"] != "hy2-auth" || int(hyStream["version"].(float64)) != 2 {
		t.Fatalf("unexpected hysteriaSettings: %v", hyStream)
	}
	finalmask := stream["finalmask"].(map[string]any)
	udpMask := finalmask["udp"].([]any)[0].(map[string]any)
	if udpMask["type"] != "salamander" {
		t.Fatalf("missing salamander finalmask: %v", finalmask)
	}

	// Xray-native hysteria inbound with empty/nil StreamSettings must not panic either.
	inbNilStream := &model.Inbound{
		Protocol: model.Hysteria,
		Listen:   "203.0.113.10",
		Port:     443,
		Settings: `{"version":2}`,
	}
	raw2 := jsonSvc.genHy(inbNilStream, map[string]any{}, model.Client{Email: "bob", Auth: "pw2"})
	if len(raw2) == 0 {
		t.Fatal("expected non-empty JSON output for nil StreamSettings")
	}
}

func TestRenderHysteria2ConfigFiles(t *testing.T) {
	s := &SubService{address: "vpn.example.com", remarkModel: "-ieo"}
	inb := hysteria2TestInbound("0.0.0.0", 443, `{
		"serverName": "cdn.example.com",
		"hopPorts": "443,20000-20050",
		"hopInterval": "30s",
		"obfsType": "salamander",
		"obfsPassword": "s-pw",
		"upMbps": 40,
		"downMbps": 120,
		"allowInsecure": true,
		"clients": [{"email": "alice", "auth": "secret-pw", "enable": true}]
	}`)

	files := s.inboundConfigFiles(inb, "alice", "vpn.example.com")
	if len(files) != 1 {
		t.Fatalf("expected 1 downloadable sing-box config file, got %d", len(files))
	}
	f := files[0]
	if f.Protocol != string(model.Hysteria2) || f.ContentType != "application/json" || !strings.HasSuffix(f.Filename, ".json") {
		t.Fatalf("unexpected file metadata: %+v", f)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(f.Content), &doc); err != nil {
		t.Fatalf("invalid sing-box JSON profile: %v", err)
	}
	hyOut := doc["outbounds"].([]any)[0].(map[string]any)
	if hyOut["type"] != "hysteria2" || hyOut["password"] != "secret-pw" || hyOut["hop_interval"] != "30s" {
		t.Fatalf("unexpected sing-box outbound: %v", hyOut)
	}
	sp := hyOut["server_ports"].([]any)
	if len(sp) != 2 || sp[0] != "443" || sp[1] != "20000:20050" {
		t.Fatalf("unexpected server_ports in sing-box client config: %v", sp)
	}
}
