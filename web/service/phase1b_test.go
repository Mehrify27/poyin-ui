package service

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/op/go-logging"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

var phase1bLoggerOnce sync.Once

func newPhase1bTestDB(t *testing.T) {
	t.Helper()
	phase1bLoggerOnce.Do(func() { logger.InitLogger(logging.ERROR) })
	if err := database.InitDB(filepath.Join(t.TempDir(), "phase1b-test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
}

func TestPhase1b_Item1_PerInboundTrafficBreakdown(t *testing.T) {
	newPhase1bTestDB(t)
	db := database.GetDB()

	const gb = int64(1024 * 1024 * 1024)
	inb1 := model.Inbound{
		UserId:         1,
		Remark:         "VLESS-Edge",
		Protocol:       model.VLESS,
		Port:           443,
		Enable:         true,
		Tag:            "inbound-443",
		Settings:       `{"clients":[{"id":"11111111-1111-1111-1111-111111111111","email":"multi@example.com","enable":true,"totalGB":10737418240}]}`,
		StreamSettings: `{"network":"tcp","security":"none"}`,
	}
	inb2 := model.Inbound{
		UserId:         1,
		Remark:         "Trojan-Core",
		Protocol:       model.Trojan,
		Port:           8443,
		Enable:         true,
		Tag:            "inbound-8443",
		Settings:       `{"clients":[{"password":"pw1","email":"multi@example.com","enable":true,"totalGB":10737418240}]}`,
		StreamSettings: `{"network":"tcp","security":"none"}`,
	}
	if err := db.Create(&inb1).Error; err != nil {
		t.Fatalf("create inb1: %v", err)
	}
	if err := db.Create(&inb2).Error; err != nil {
		t.Fatalf("create inb2: %v", err)
	}

	acc := model.Account{
		Email:   "multi@example.com",
		UUID:    "11111111-1111-1111-1111-111111111111",
		TotalGB: 10 * gb,
		Enable:  true,
	}
	if err := db.Create(&acc).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	enTrue := true
	m1 := model.AccountInbound{
		AccountId: acc.Id,
		InboundId: inb1.Id,
		Enable:    &enTrue,
		Up:        100,
		Down:      400,
		AllTime:   500,
	}
	m2 := model.AccountInbound{
		AccountId: acc.Id,
		InboundId: inb2.Id,
		Enable:    &enTrue,
		Up:        250,
		Down:      750,
		AllTime:   1000,
	}
	if err := db.Create(&m1).Error; err != nil {
		t.Fatalf("create m1: %v", err)
	}
	if err := db.Create(&m2).Error; err != nil {
		t.Fatalf("create m2: %v", err)
	}

	ct := xray.ClientTraffic{
		InboundId: inb1.Id,
		Email:     "multi@example.com",
		Enable:    true,
		Up:        350,
		Down:      1150,
		AllTime:   1500,
		Total:     10 * gb,
	}
	if err := db.Create(&ct).Error; err != nil {
		t.Fatalf("create client traffic: %v", err)
	}

	inboundSvc := &InboundService{}
	traffics := []*xray.ClientTraffic{&ct}
	inboundSvc.populateClientInboundTraffics(db, traffics)

	if len(ct.InboundTraffics) != 2 {
		t.Fatalf("InboundTraffics len = %d, want 2: %+v", len(ct.InboundTraffics), ct.InboundTraffics)
	}
	byId := map[int]xray.InboundTrafficBreakdown{}
	for _, b := range ct.InboundTraffics {
		byId[b.InboundId] = b
	}
	if b1 := byId[inb1.Id]; b1.Up != 100 || b1.Down != 400 || b1.Total != 500 || b1.Remark != "VLESS-Edge" || b1.Port != 443 {
		t.Fatalf("unexpected inbound1 breakdown: %+v", b1)
	}
	if b2 := byId[inb2.Id]; b2.Up != 250 || b2.Down != 750 || b2.Total != 1000 || b2.Remark != "Trojan-Core" || b2.Port != 8443 {
		t.Fatalf("unexpected inbound2 breakdown: %+v", b2)
	}

	accSvc := &AccountService{}
	admin := &model.User{Id: 1, IsSuperAdmin: true, Enable: true}
	res, err := accSvc.ListAccounts(admin, 1, 20, "multi@example.com", "")
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("ListAccounts rows = %d, want 1", len(res.Rows))
	}
	item := res.Rows[0]
	if item.Up != 350 || item.Down != 1150 || len(item.Memberships) != 2 {
		t.Fatalf("unexpected account totals/memberships: %+v", item)
	}
	memById := map[int]AccountMembershipView{}
	for _, m := range item.Memberships {
		memById[m.InboundId] = m
	}
	if memById[inb1.Id].Up != 100 || memById[inb1.Id].Down != 400 || memById[inb1.Id].Total != 500 {
		t.Fatalf("unexpected membership 1 breakdown: %+v", memById[inb1.Id])
	}
	if memById[inb2.Id].Up != 250 || memById[inb2.Id].Down != 750 || memById[inb2.Id].Total != 1000 {
		t.Fatalf("unexpected membership 2 breakdown: %+v", memById[inb2.Id])
	}
}

func TestPhase1b_Item2_ResellerBulkCreateAndCopyBatch(t *testing.T) {
	newPhase1bTestDB(t)
	db := database.GetDB()
	const gb = int64(1024 * 1024 * 1024)

	reseller := &model.User{Username: "reseller1", Password: "x", IsReseller: true, Enable: true}
	if err := db.Create(reseller).Error; err != nil {
		t.Fatalf("create reseller: %v", err)
	}
	profile := &model.ResellerProfile{
		UserId:         reseller.Id,
		AllowanceBytes: 10 * gb,
		SpentBytes:     0,
	}
	if err := db.Create(profile).Error; err != nil {
		t.Fatalf("create reseller profile: %v", err)
	}

	inbound := &model.Inbound{
		UserId:   reseller.Id,
		Remark:   "Reseller-VLESS",
		Protocol: model.VLESS,
		Port:     10443,
		Enable:   true,
		Tag:      "inbound-10443",
		Settings: `{"clients":[]}`,
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	rs := &ResellerService{}
	overBudgetPayload := &model.Inbound{
		Id: inbound.Id,
		Settings: `{"clients":[` +
			`{"email":"c1@example.com","totalGB":` + "5368709120" + `,"enable":true},` +
			`{"email":"c2@example.com","totalGB":` + "6442450944" + `,"enable":true}` +
			`]}`,
	}
	if _, err := rs.PrepareClientCreate(reseller, overBudgetPayload); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("over-budget bulk PrepareClientCreate err = %v, want ErrInsufficientBalance", err)
	}
	var refreshed model.ResellerProfile
	if err := db.Where("user_id = ?", reseller.Id).First(&refreshed).Error; err != nil {
		t.Fatalf("reload profile: %v", err)
	}
	if refreshed.SpentBytes != 0 {
		t.Fatalf("over-budget create mutated SpentBytes to %d", refreshed.SpentBytes)
	}

	validPayload := &model.Inbound{
		Id: inbound.Id,
		Settings: `{"clients":[` +
			`{"email":"Alice@example.com","totalGB":` + "3221225472" + `,"enable":true},` +
			`{"email":"Bob@example.com","totalGB":` + "4294967296" + `,"enable":true}` +
			`]}`,
	}
	ticket, err := rs.PrepareClientCreate(reseller, validPayload)
	if err != nil {
		t.Fatalf("PrepareClientCreate valid batch: %v", err)
	}
	if ticket.Quote.DeltaSpent != 7*gb || len(ticket.Emails) != 2 {
		t.Fatalf("unexpected batch ticket: %+v", ticket)
	}
	if err := db.Where("user_id = ?", reseller.Id).First(&refreshed).Error; err != nil {
		t.Fatalf("reload profile after create: %v", err)
	}
	if refreshed.SpentBytes != 7*gb {
		t.Fatalf("SpentBytes = %d, want %d", refreshed.SpentBytes, 7*gb)
	}

	var rcCount int64
	db.Model(&model.ResellerClient{}).Where("user_id = ?", reseller.Id).Count(&rcCount)
	if rcCount != 2 {
		t.Fatalf("ResellerClient count = %d, want 2", rcCount)
	}

	if err := rs.Rollback(ticket); err != nil {
		t.Fatalf("Rollback batch: %v", err)
	}
	if err := db.Where("user_id = ?", reseller.Id).First(&refreshed).Error; err != nil {
		t.Fatalf("reload profile after rollback: %v", err)
	}
	if refreshed.SpentBytes != 0 {
		t.Fatalf("SpentBytes after rollback = %d, want 0", refreshed.SpentBytes)
	}
	db.Model(&model.ResellerClient{}).Where("user_id = ?", reseller.Id).Count(&rcCount)
	if rcCount != 0 {
		t.Fatalf("ResellerClient count after rollback = %d, want 0", rcCount)
	}

	copies := []model.Client{
		{Email: "copy1@example.com", TotalGB: 2 * gb, Enable: true},
		{Email: "copy2@example.com", TotalGB: 3 * gb, Enable: true},
	}
	copyTicket, err := rs.PrepareClientCopyBatch(reseller, inbound.Id, copies)
	if err != nil {
		t.Fatalf("PrepareClientCopyBatch: %v", err)
	}
	if copyTicket.Quote.DeltaSpent != 5*gb || len(copyTicket.Emails) != 2 {
		t.Fatalf("unexpected copy ticket: %+v", copyTicket)
	}
	if err := rs.Rollback(copyTicket); err != nil {
		t.Fatalf("Rollback copy batch: %v", err)
	}
}

func TestPhase1b_Item3_LifecycleCaseInsensitiveAndOrphanCleanup(t *testing.T) {
	newPhase1bTestDB(t)
	db := database.GetDB()

	acc := model.Account{Email: "UserOne@Example.com", UUID: "u-1", Enable: true}
	if err := db.Create(&acc).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	ct := xray.ClientTraffic{InboundId: 1, Email: "UserOne@Example.com", Enable: true, Up: 10}
	if err := db.Create(&ct).Error; err != nil {
		t.Fatalf("create traffic: %v", err)
	}
	ips := model.InboundClientIps{ClientEmail: "UserOne@Example.com", Ips: `["1.2.3.4"]`}
	if err := db.Create(&ips).Error; err != nil {
		t.Fatalf("create client ips: %v", err)
	}
	rc := model.ResellerClient{UserId: 2, Email: "UserOne@Example.com", InboundId: 1, ChargedBytes: 1024}
	if err := db.Create(&rc).Error; err != nil {
		t.Fatalf("create reseller client: %v", err)
	}

	accSvc := &AccountService{}
	if _, err := accSvc.RenameAccount("userone@example.com", "Renamed@Example.com"); err != nil {
		t.Fatalf("RenameAccount case-insensitive: %v", err)
	}

	var gotCT xray.ClientTraffic
	if err := db.Where("email = ?", "Renamed@Example.com").First(&gotCT).Error; err != nil {
		t.Fatalf("ClientTraffic not renamed: %v", err)
	}
	var gotIPs model.InboundClientIps
	if err := db.Where("client_email = ?", "Renamed@Example.com").First(&gotIPs).Error; err != nil {
		t.Fatalf("InboundClientIps not renamed: %v", err)
	}
	var gotRC model.ResellerClient
	if err := db.Where("LOWER(TRIM(email)) = ?", "renamed@example.com").First(&gotRC).Error; err != nil {
		t.Fatalf("ResellerClient not renamed: %v", err)
	}

	purged, err := PurgeAccountIfOrphanedTx(db, "renamed@example.com")
	if err != nil || !purged {
		t.Fatalf("PurgeAccountIfOrphanedTx = (%v, %v), want (true, nil)", purged, err)
	}
	var count int64
	db.Model(&model.Account{}).Where("id = ?", acc.Id).Count(&count)
	if count != 0 {
		t.Fatalf("orphaned account was not purged; count=%d", count)
	}
}

func TestPhase1b_Item4_OpenVpnAndOcservCustomConfig(t *testing.T) {
	newPhase1bTestDB(t)
	db := database.GetDB()

	baseOvpn := "port 1194\nproto udp\ntun-mtu 1500\nverb 3\n"
	diskOvpn := baseOvpn + "# BEGIN_USER_CUSTOM\nsndbuf 393216\nrcvbuf 393216\n# END_USER_CUSTOM\n# manual extra\nkeepalive 5 30\n"
	mergedOvpn, recovered := mergeOpenVpnCustomConfig(baseOvpn, "", diskOvpn)
	if !strings.Contains(mergedOvpn, "sndbuf 393216") || !strings.Contains(mergedOvpn, "keepalive 5 30") {
		t.Fatalf("openVPN custom lines lost during merge:\n%s", mergedOvpn)
	}
	if !strings.Contains(recovered, "sndbuf 393216") || !strings.Contains(recovered, "keepalive 5 30") {
		t.Fatalf("openVPN recovered custom lines incomplete:\n%s", recovered)
	}

	rawCustom := "reneg-sec 0\n# CLIENT_CUSTOM\nauth-nocache\nsetenv opt block-outside-dns\n# END_CLIENT_CUSTOM\n"
	serverLines, _ := splitOpenVpnCustomSections(rawCustom)
	serverCustom := strings.Join(serverLines, "\n")
	clientCustom := strings.Join(extractOpenVpnClientCustom(rawCustom), "\n")
	if strings.Contains(serverCustom, "auth-nocache") || !strings.Contains(serverCustom, "reneg-sec 0") {
		t.Fatalf("unexpected server custom split: %q", serverCustom)
	}
	if !strings.Contains(clientCustom, "auth-nocache") || !strings.Contains(clientCustom, "block-outside-dns") {
		t.Fatalf("unexpected client custom split: %q", clientCustom)
	}

	baseOcserv := "tcp-port = 443\ntry-mtu-discovery = true\n"
	diskOcserv := baseOcserv + "# BEGIN_USER_CUSTOM\ndpd = 60\n# END_USER_CUSTOM\nmobile-dpd = 900\n"
	mergedOcserv, recOcserv := mergeOcservCustomConfig(baseOcserv, "", diskOcserv)
	if !strings.Contains(mergedOcserv, "dpd = 60") || !strings.Contains(mergedOcserv, "mobile-dpd = 900") {
		t.Fatalf("ocserv custom lines lost:\n%s", mergedOcserv)
	}
	if !strings.Contains(recOcserv, "dpd = 60") || !strings.Contains(recOcserv, "mobile-dpd = 900") {
		t.Fatalf("ocserv recovered custom incomplete:\n%s", recOcserv)
	}

	inb := model.Inbound{
		UserId:   1,
		Remark:   "OVPN",
		Protocol: model.OPENVPN,
		Port:     1194,
		Tag:      "inbound-1194",
		Settings: `{"clients":[]}`,
	}
	if err := db.Create(&inb).Error; err != nil {
		t.Fatalf("create ovpn inbound: %v", err)
	}
	syncInboundCustomConfig(inb.Id, "sndbuf 393216\n# CLIENT_CUSTOM\nauth-nocache\n# END_CLIENT_CUSTOM", true)
	var reloaded model.Inbound
	if err := db.First(&reloaded, inb.Id).Error; err != nil {
		t.Fatalf("reload inbound: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(reloaded.Settings), &parsed); err != nil {
		t.Fatalf("unmarshal updated settings: %v", err)
	}
	if got, _ := parsed["customConfig"].(string); !strings.Contains(got, "sndbuf 393216") {
		t.Fatalf("customConfig not synced into inbound settings: %q", got)
	}
}

func TestPhase1b_Item5A_GreOwnedNameAndXrayTemplateReconcile(t *testing.T) {
	if greOwnedName("cgre-myisp") {
		t.Fatal("greOwnedName claimed cgre-myisp client GRE interface")
	}
	if greOwnedName("cgre1234abcd") {
		t.Fatal("greOwnedName claimed cgre1234abcd client GRE hash interface")
	}
	if !greOwnedName("gre10_0_1") {
		t.Fatal("greOwnedName rejected valid server GRE interface gre10_0_1")
	}

	rawTemplate := `{
  "inbounds": [],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"}
  ]
}`
	vpnTunnels := []VpnOutboundConfig{
		{Tag: "gre-egress", Kind: VpnOutGre, Enable: true, Iface: "cgre-gre-egress", Via: "proxy-hop"},
	}
	sshTunnels := []SshOutboundConfig{
		{Tag: "ssh-egress", Address: "1.2.3.4", Port: 22, SocksPort: 10888},
	}

	reconciled := reconcileXrayTemplateOutboundsWith(rawTemplate, vpnTunnels, sshTunnels)
	var parsed struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(reconciled), &parsed); err != nil {
		t.Fatalf("unmarshal reconciled template: %v", err)
	}
	byTag := map[string]map[string]any{}
	for _, ob := range parsed.Outbounds {
		if tag, _ := ob["tag"].(string); tag != "" {
			byTag[tag] = ob
		}
	}
	greOb := byTag["gre-egress"]
	if greOb == nil || greOb["protocol"] != "freedom" {
		t.Fatalf("missing or malformed reconciled GRE outbound: %+v", greOb)
	}
	stream, _ := greOb["streamSettings"].(map[string]any)
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt["interface"] != "cgre-gre-egress" {
		t.Fatalf("GRE outbound sockopt.interface = %v, want cgre-gre-egress", sockopt["interface"])
	}
	sshOb := byTag["ssh-egress"]
	if sshOb == nil || sshOb["protocol"] != "socks" {
		t.Fatalf("missing or malformed reconciled SSH outbound: %+v", sshOb)
	}
}
