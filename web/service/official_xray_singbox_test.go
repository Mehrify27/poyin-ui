package service

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/binutil"
)

func TestRepoHasNoMHSanaeiRuntimeURLs(t *testing.T) {
	root := filepath.Join("..", "..")
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		slash := filepath.ToSlash(rel)
		if d.IsDir() {
			switch slash {
			case ".git", "node_modules", "web/frontend/node_modules", "web/frontend/dist", "third_party", "build/out":
				return fs.SkipDir
			}
			return nil
		}
		if slash == "go.mod" || slash == "go.sum" || strings.HasPrefix(slash, "README") || slash == "gre-plan.md" || strings.HasSuffix(slash, "_test.go") {
			return nil
		}
		switch {
		case strings.HasSuffix(slash, ".go"),
			strings.HasSuffix(slash, ".sh"),
			strings.HasSuffix(slash, ".yml"),
			strings.HasSuffix(slash, ".yaml"),
			strings.HasSuffix(slash, ".html"),
			strings.HasSuffix(slash, ".ts"),
			strings.HasSuffix(slash, ".vue"):
		default:
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		lines := strings.Split(string(raw), "\n")
		for idx, line := range lines {
			low := strings.ToLower(line)
			if !strings.Contains(low, "mhsanaei") {
				continue
			}
			// Go package imports stay aligned with go.mod module path.
			if strings.Contains(low, "github.com/mhsanaei/3x-ui/v2") {
				continue
			}
			t.Errorf("%s:%d contains forbidden MHSanaei runtime/config reference: %s", slash, idx+1, strings.TrimSpace(line))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if checked == 0 {
		t.Fatal("expected to inspect repository files")
	}

	spec, ok := findCoreUpdateSpec("xray")
	if !ok {
		t.Fatal("xray update spec missing")
	}
	if spec.GithubRepo != "XTLS/Xray-core" || spec.UpstreamURL != "https://github.com/XTLS/Xray-core/releases" {
		t.Fatalf("unexpected xray upstream spec: %+v", spec)
	}
	for name, entry := range builtinGeofiles {
		if strings.Contains(strings.ToLower(entry.URL), "mhsanaei") {
			t.Fatalf("geofile %s points to mhsanaei: %s", name, entry.URL)
		}
	}
}

func TestXrayReleaseAssetGOARMAndStrictDgstAndRateLimit(t *testing.T) {
	assets := []githubReleaseAsset{
		{Name: "Xray-linux-64.zip", BrowserDownloadURL: "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip"},
		{Name: "Xray-linux-64.zip.dgst", BrowserDownloadURL: "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip.dgst"},
		{Name: "Xray-linux-arm64-v8a.zip", BrowserDownloadURL: "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-arm64-v8a.zip"},
		{Name: "Xray-linux-arm32-v7a.zip", BrowserDownloadURL: "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-arm32-v7a.zip"},
		{Name: "Xray-linux-arm32-v6.zip", BrowserDownloadURL: "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-arm32-v6.zip"},
		{Name: "Xray-linux-arm32-v5.zip", BrowserDownloadURL: "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-arm32-v5.zip"},
		{Name: "Xray-linux-32.zip", BrowserDownloadURL: "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-32.zip"},
	}

	if name, _, _, dgst := pickReleaseAsset("xray", assets, "amd64"); name != "Xray-linux-64.zip" || !strings.HasSuffix(dgst, ".dgst") {
		t.Fatalf("amd64 pick = (%q, %q), want Xray-linux-64.zip + .dgst", name, dgst)
	}
	if name, _, _, _ := pickReleaseAsset("xray", assets, "arm64"); name != "Xray-linux-arm64-v8a.zip" {
		t.Fatalf("arm64 pick = %q, want Xray-linux-arm64-v8a.zip", name)
	}
	if name, _, _, _ := pickReleaseAsset("xray", assets, "386"); name != "Xray-linux-32.zip" {
		t.Fatalf("386 pick = %q, want Xray-linux-32.zip", name)
	}

	t.Setenv("GOARM", "7")
	if name, _, _, _ := pickReleaseAsset("xray", assets, "arm"); name != "Xray-linux-arm32-v7a.zip" {
		t.Fatalf("arm GOARM=7 pick = %q, want Xray-linux-arm32-v7a.zip", name)
	}
	t.Setenv("GOARM", "6")
	if name, _, _, _ := pickReleaseAsset("xray", assets, "arm"); name != "Xray-linux-arm32-v6.zip" {
		t.Fatalf("arm GOARM=6 pick = %q, want Xray-linux-arm32-v6.zip", name)
	}
	t.Setenv("GOARM", "5")
	if name, _, _, _ := pickReleaseAsset("xray", assets, "arm"); name != "Xray-linux-arm32-v5.zip" {
		t.Fatalf("arm GOARM=5 pick = %q, want Xray-linux-arm32-v5.zip", name)
	}

	// Verify strict .dgst error propagation and rate-limit error reporting.
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)
	archTok := archTokenForTest(runtime.GOARCH)
	assetName := fmt.Sprintf("Xray-linux-%s.zip", archTok)

	var srv *httptest.Server
	mode := "bad-dgst"
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/XTLS/Xray-core/releases/latest" {
			if mode == "ratelimit" {
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", "1794960000")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v26.11.9",
				"assets": []map[string]any{
					{"name": assetName, "browser_download_url": srv.URL + "/dl/" + assetName},
					{"name": assetName + ".dgst", "browser_download_url": srv.URL + "/dl/" + assetName + ".dgst"},
				},
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, ".dgst") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prevGH := githubReleaseAPIBase
	githubReleaseAPIBase = srv.URL
	defer func() { githubReleaseAPIBase = prevGH }()

	svc := &CoreService{}
	restarted := false
	_, err := svc.UpdateCore(CoreUpdateOptions{
		Target:         "xray",
		AllowUnpatched: true,
		RestartFunc:    func(string) error { restarted = true; return nil },
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "sha-256 digest") {
		t.Fatalf("expected strict .dgst fetch failure, got err=%v", err)
	}
	if restarted {
		t.Fatal("RestartFunc must not run when .dgst checksum fetch fails")
	}

	mode = "ratelimit"
	_, _, rlErr := svc.ListUpstreamCoreVersions("xray", true)
	if rlErr == nil || !strings.Contains(rlErr.Error(), "rate limit") {
		t.Fatalf("expected explicit GitHub rate limit error, got %v", rlErr)
	}
}

func TestDetectXrayCapabilitiesScansEmbeddedMarkersAndMeta(t *testing.T) {
	invalidateXrayCapabilitiesCache()
	dir := t.TempDir()

	// 1. Real-sized unpatched binary (no vpn-ui markers).
	unpatched := filepath.Join(dir, "xray-official")
	payload := make([]byte, realXrayBinaryMinBytes+64)
	copy(payload, []byte{0x7f, 'E', 'L', 'F'})
	if err := os.WriteFile(unpatched, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	caps := DetectXrayCapabilities(unpatched)
	if caps.BinaryMode != BinaryModeOfficialXTLSUnpatched || caps.SupportsSpeedLimit || caps.SupportsNativeForkProtocols {
		t.Fatalf("expected unpatched official XTLS capabilities, got %+v", caps)
	}

	// 2. Binary embedding both vpn-ui speedlimit and fork protocol markers.
	patched := filepath.Join(dir, "xray-patched")
	patchedPayload := append([]byte(nil), payload...)
	copy(patchedPayload[1024:], []byte("env=XRAY_SPEEDLIMIT_FILE"))
	copy(patchedPayload[8192:], []byte("proto=xray.proxy.naive.Account"))
	if err := os.WriteFile(patched, patchedPayload, 0o755); err != nil {
		t.Fatal(err)
	}
	capsPatched := DetectXrayCapabilities(patched)
	if capsPatched.BinaryMode != BinaryModeCustomPatched || !capsPatched.SupportsSpeedLimit || !capsPatched.SupportsNativeForkProtocols {
		t.Fatalf("expected patched custom capabilities, got %+v", capsPatched)
	}
}

func TestSingboxForkDecouplingAndXrayConfigForOfficialBinary(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	prevBase := singboxForkConfigBase
	singboxForkConfigBase = t.TempDir()
	defer func() { singboxForkConfigBase = prevBase }()

	var ss SettingService
	if err := ss.SetForkProtocolEngine("sing-box"); err != nil {
		t.Fatalf("SetForkProtocolEngine: %v", err)
	}
	defer func() { _ = ss.SetForkProtocolEngine("auto") }()

	db := database.GetDB()
	inbounds := []*model.Inbound{
		{
			Id:             101,
			UserId:         1,
			Tag:            "inbound-anytls-101",
			Listen:         "0.0.0.0",
			Port:           8443,
			Protocol:       model.ANYTLS,
			Enable:         true,
			Settings:       `{"clients":[{"email":"a@test","password":"pw1","enable":true,"limitIp":2}],"paddingScheme":["stop=8","0=30-30"]}`,
			StreamSettings: `{"security":"reality","realitySettings":{"target":"www.cloudflare.com:443","serverNames":["www.cloudflare.com"],"privateKey":"privkey-test","shortIds":["abcd1234"]}}`,
		},
		{
			Id:             102,
			UserId:         1,
			Tag:            "inbound-tuic-102",
			Listen:         "::",
			Port:           9443,
			Protocol:       model.TUIC,
			Enable:         true,
			Settings:       `{"clients":[{"email":"t@test","id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","password":"pw2","enable":true}],"congestionControl":"bbr","authTimeout":4,"heartbeat":12,"zeroRttHandshake":true}`,
			StreamSettings: `{"security":"tls","tlsSettings":{"serverName":"tuic.example.com"}}`,
		},
		{
			Id:             103,
			UserId:         1,
			Tag:            "inbound-naive-103",
			Listen:         "0.0.0.0",
			Port:           10443,
			Protocol:       model.NAIVE,
			Enable:         true,
			Settings:       `{"clients":[{"email":"n@test","username":"naive_user","password":"pw3","enable":true}],"network":"tcp"}`,
			StreamSettings: `{"security":"tls","tlsSettings":{"serverName":"naive.example.com"}}`,
		},
	}
	for _, inb := range inbounds {
		if err := db.Create(inb).Error; err != nil {
			t.Fatalf("create inbound %d: %v", inb.Id, err)
		}
	}

	// Build Xray config pretending an unpatched official XTLS binary is active.
	var xs XrayService
	xrayCfg, err := xs.BuildXrayConfigWithCapabilities(XrayBinaryCapabilities{
		BinaryMode:                  BinaryModeOfficialXTLSUnpatched,
		SupportsSpeedLimit:          false,
		SupportsNativeForkProtocols: false,
	})
	if err != nil {
		t.Fatalf("BuildXrayConfigWithCapabilities: %v", err)
	}

	for _, ic := range xrayCfg.InboundConfigs {
		if ic.Protocol == string(model.ANYTLS) || ic.Protocol == string(model.TUIC) || ic.Protocol == string(model.NAIVE) {
			t.Fatalf("unpatched official Xray config leaked raw fork protocol %q", ic.Protocol)
		}
	}

	byTag := map[string]int{}
	for _, ic := range xrayCfg.InboundConfigs {
		if ic.Protocol == "socks" {
			byTag[ic.Tag] = ic.Port
		}
	}
	for _, inb := range inbounds {
		if gotPort := byTag[inb.Tag]; gotPort != singboxForkSocksPortBase+inb.Id {
			t.Fatalf("expected loopback SOCKS5 bridge for %s on port %d, got %d", inb.Tag, singboxForkSocksPortBase+inb.Id, gotPort)
		}
	}

	// Render sing-box configs and validate protocol schemas.
	var sf SingboxForkService
	for _, inb := range inbounds {
		raw, _, _, err := sf.buildServerConfig(inb, "sec-test")
		if err != nil {
			t.Fatalf("buildServerConfig(%s): %v", inb.Protocol, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("invalid sing-box JSON for %s: %v", inb.Protocol, err)
		}
		sInb := doc["inbounds"].([]any)[0].(map[string]any)
		if sInb["type"] != string(inb.Protocol) {
			t.Fatalf("sing-box inbound type = %v, want %s", sInb["type"], inb.Protocol)
		}
		switch inb.Protocol {
		case model.ANYTLS:
			tls := sInb["tls"].(map[string]any)
			reality := tls["reality"].(map[string]any)
			if reality["enabled"] != true || reality["private_key"] != "privkey-test" {
				t.Fatalf("unexpected anytls reality config: %v", reality)
			}
			ps := sInb["padding_scheme"].([]any)
			if len(ps) != 2 || ps[0] != "stop=8" {
				t.Fatalf("unexpected padding_scheme: %v", ps)
			}
		case model.TUIC:
			if sInb["congestion_control"] != "bbr" || sInb["auth_timeout"] != "4s" || sInb["heartbeat"] != "12s" || sInb["zero_rtt_handshake"] != true {
				t.Fatalf("unexpected tuic config: %v", sInb)
			}
		case model.NAIVE:
			if sInb["network"] != "tcp" {
				t.Fatalf("expected naive network=tcp, got %v", sInb["network"])
			}
			u0 := sInb["users"].([]any)[0].(map[string]any)
			if u0["username"] != "naive_user" || u0["password"] != "pw3" {
				t.Fatalf("unexpected naive user: %v", u0)
			}
		}
	}
}

func TestKernelTCSpeedLimitPlannerSafetyAndIPv4IPv6(t *testing.T) {
	if isAllowedVpnTCInterface("eth0") || isAllowedVpnTCInterface("ens3") || isAllowedVpnTCInterface("lo") {
		t.Fatal("physical WAN or loopback interface must never be accepted for tc shaping")
	}
	if !isAllowedVpnTCInterface("ppp0") || !isAllowedVpnTCInterface("tun0") || !isAllowedVpnTCInterface("awg-1") {
		t.Fatal("expected VPN tunnel interfaces to be allowed")
	}

	users := []speedLimitUser{
		{
			Email:   "vpn-a",
			DownBps: 1024 * 100,
			UpBps:   1024 * 50,
			IPs:     []string{"10.2.0.5/32", "fd00:1::5/128", "192.0.2.10/32"},
		},
	}
	plan := buildTCSpeedLimitPlan(users, func(cidr string) (string, bool) {
		switch cidr {
		case "10.2.0.5/32":
			return "ppp0", true
		case "fd00:1::5/128":
			return "tun0", true
		default:
			return "eth0", true // rejected by safety allowlist
		}
	}, []string{"ppp9"})

	joined := make([]string, 0, len(plan.Commands))
	for _, cmd := range plan.Commands {
		joined = append(joined, strings.Join(cmd, " "))
	}
	all := strings.Join(joined, "\n")

	if strings.Contains(all, "eth0") {
		t.Fatalf("eth0 must not appear in tc plan: %s", all)
	}
	if !strings.Contains(all, "qdisc del dev ppp9 root") || !strings.Contains(all, "qdisc del dev ppp9 ingress") {
		t.Fatalf("expected stale interface ppp9 cleanup in plan: %s", all)
	}
	if !strings.Contains(all, "dev ppp0 parent 1: classid 1:10 htb rate 819200bit ceil 819200bit") {
		t.Fatalf("missing IPv4 HTB download class for ppp0: %s", all)
	}
	if !strings.Contains(all, "match ipv6 dst") && !strings.Contains(all, "match ip6 dst fd00:1::5/128") {
		t.Fatalf("missing IPv6 ip6 filter for tun0: %s", all)
	}
	if !strings.Contains(all, "parent ffff: protocol ipv6 prio 10 u32 match ip6 src fd00:1::5/128 police rate 409600bit") {
		t.Fatalf("missing IPv6 ingress police filter for tun0: %s", all)
	}
}

func TestForkProtocolEngineSettingAndAutoDetection(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	var ss SettingService
	if got := ss.GetForkProtocolEngine(); got != "auto" {
		t.Fatalf("default forkProtocolEngine = %q, want auto", got)
	}
	if err := ss.SetForkProtocolEngine("invalid-engine"); err == nil {
		t.Fatal("expected error for invalid forkProtocolEngine")
	}
	if err := ss.SetForkProtocolEngine("sing-box"); err != nil {
		t.Fatalf("SetForkProtocolEngine(sing-box): %v", err)
	}
	if !ShouldUseSingboxForkEngineForCaps(XrayBinaryCapabilities{SupportsNativeForkProtocols: true}) {
		t.Fatal("explicit sing-box mode must use sing-box even with patched Xray")
	}
	if err := ss.SetForkProtocolEngine("xray"); err != nil {
		t.Fatalf("SetForkProtocolEngine(xray): %v", err)
	}
	if ShouldUseSingboxForkEngineForCaps(XrayBinaryCapabilities{SupportsNativeForkProtocols: false}) {
		t.Fatal("explicit xray mode must return false for sing-box engine")
	}
	if err := ss.SetForkProtocolEngine("auto"); err != nil {
		t.Fatalf("SetForkProtocolEngine(auto): %v", err)
	}
	if !ShouldUseSingboxForkEngineForCaps(XrayBinaryCapabilities{BinaryMode: BinaryModeOfficialXTLSUnpatched, SupportsNativeForkProtocols: false}) {
		t.Fatal("auto mode must select sing-box when active Xray lacks native fork protocols")
	}
	if ShouldUseSingboxForkEngineForCaps(XrayBinaryCapabilities{BinaryMode: BinaryModeBundledPatched, SupportsNativeForkProtocols: true}) {
		t.Fatal("auto mode must keep patched Xray when active binary supports native fork protocols")
	}
}
