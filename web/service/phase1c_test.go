package service

import (
	"embed"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/locale"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

type phase1cLocaleStub struct{}

func (phase1cLocaleStub) GetTgLang() (string, error) {
	return "en-US", nil
}

func initPhase1cTestLocale(t *testing.T) {
	t.Helper()
	t.Setenv("VPNUI_DEBUG", "true")
	if err := locale.InitLocalizer(embed.FS{}, phase1cLocaleStub{}); err != nil {
		t.Fatalf("InitLocalizer(debug disk): %v", err)
	}
}

func TestAccountListAndAssignableFlowMetadata(t *testing.T) {
	svc := newAccountsDB(t)
	db := database.GetDB()

	superAdmin := &model.User{
		Username:     "phase1c-superadmin",
		Password:     "x",
		Enable:       true,
		IsSuperAdmin: true,
	}
	if err := db.Create(superAdmin).Error; err != nil {
		t.Fatalf("create superadmin: %v", err)
	}

	vlessTCPTLS := &model.Inbound{
		UserId:         superAdmin.Id,
		Tag:            "vless-tcp-tls",
		Remark:         "VLESS-TCP-TLS",
		Port:           48101,
		Protocol:       model.VLESS,
		Enable:         true,
		Settings:       `{"decryption":"none","flow":"xtls-rprx-vision","clients":[{"id":"11111111-1111-1111-1111-111111111111","email":"flow-user@example.com","flow":"xtls-rprx-vision","enable":false}]}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"sni.example.com"}}`,
	}
	vlessWSNone := &model.Inbound{
		UserId:         superAdmin.Id,
		Tag:            "vless-ws-none",
		Remark:         "VLESS-WS-NONE",
		Port:           48102,
		Protocol:       model.VLESS,
		Enable:         true,
		Settings:       `{"decryption":"none","flow":"xtls-rprx-vision","clients":[{"id":"22222222-2222-2222-2222-222222222222","email":"ws-user@example.com","flow":"","enable":false}]}`,
		StreamSettings: `{"network":"ws","security":"none"}`,
	}
	vmessTCPTLS := &model.Inbound{
		UserId:         superAdmin.Id,
		Tag:            "vmess-tcp-tls",
		Remark:         "VMESS-TCP-TLS",
		Port:           48103,
		Protocol:       model.VMESS,
		Enable:         true,
		Settings:       `{"clients":[{"id":"33333333-3333-3333-3333-333333333333","email":"vmess-user@example.com","enable":false}]}`,
		StreamSettings: `{"network":"tcp","security":"tls"}`,
	}
	for _, ib := range []*model.Inbound{vlessTCPTLS, vlessWSNone, vmessTCPTLS} {
		if err := db.Create(ib).Error; err != nil {
			t.Fatalf("create inbound %s: %v", ib.Tag, err)
		}
	}
	svc.MigrationAccounts()

	listRes, err := svc.ListAccounts(superAdmin, 1, 50, "", "")
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}

	byEmail := map[string]AccountRow{}
	for _, row := range listRes.Rows {
		byEmail[row.Email] = row
	}
	if row, ok := byEmail["flow-user@example.com"]; !ok || len(row.Memberships) != 1 {
		t.Fatalf("missing flow-user membership: %+v", row)
	} else {
		m := row.Memberships[0]
		if !m.CanEnableTlsFlow || m.Flow != "xtls-rprx-vision" {
			t.Fatalf("vless-tcp-tls membership flow metadata = (%v, %q), want (true, %q)", m.CanEnableTlsFlow, m.Flow, "xtls-rprx-vision")
		}
	}
	if row, ok := byEmail["ws-user@example.com"]; !ok || len(row.Memberships) != 1 {
		t.Fatalf("missing ws-user membership: %+v", row)
	} else if row.Memberships[0].CanEnableTlsFlow {
		t.Fatalf("vless-ws-none unexpectedly marked CanEnableTlsFlow=true: %+v", row.Memberships[0])
	}
	if row, ok := byEmail["vmess-user@example.com"]; !ok || len(row.Memberships) != 1 {
		t.Fatalf("missing vmess-user membership: %+v", row)
	} else if row.Memberships[0].CanEnableTlsFlow {
		t.Fatalf("vmess unexpectedly marked CanEnableTlsFlow=true: %+v", row.Memberships[0])
	}

	assignable, err := svc.AssignableInboundsFor(superAdmin)
	if err != nil {
		t.Fatalf("AssignableInboundsFor: %v", err)
	}
	byId := map[int]AccountMembershipView{}
	for _, a := range assignable {
		byId[a.InboundId] = a
	}
	if !byId[vlessTCPTLS.Id].CanEnableTlsFlow || byId[vlessTCPTLS.Id].Flow != "xtls-rprx-vision" {
		t.Fatalf("assignable vlessTCPTLS = %+v, want CanEnableTlsFlow=true and Flow=xtls-rprx-vision", byId[vlessTCPTLS.Id])
	}
	if byId[vlessWSNone.Id].CanEnableTlsFlow {
		t.Fatalf("assignable vlessWSNone unexpectedly CanEnableTlsFlow=true: %+v", byId[vlessWSNone.Id])
	}
	if byId[vmessTCPTLS.Id].CanEnableTlsFlow {
		t.Fatalf("assignable vmessTCPTLS unexpectedly CanEnableTlsFlow=true: %+v", byId[vmessTCPTLS.Id])
	}
}

func TestTgbotHelpersAndNilGuards(t *testing.T) {
	_ = newAccountsDB(t)
	initPhase1cTestLocale(t)
	db := database.GetDB()

	origBot := bot
	bot = nil
	t.Cleanup(func() { bot = origBot })

	origReceiver := receiver_inbound_ID
	origId := client_Id
	origFlow := client_Flow
	origEmail := client_Email
	origLimitIP := client_LimitIP
	origTotalGB := client_TotalGB
	origExpiry := client_ExpiryTime
	origEnable := client_Enable
	origTgID := client_TgID
	origSubID := client_SubID
	origComment := client_Comment
	origReset := client_Reset
	origSec := client_Security
	origShPw := client_ShPassword
	origTrPw := client_TrPassword
	origMethod := client_Method
	t.Cleanup(func() {
		receiver_inbound_ID = origReceiver
		client_Id = origId
		client_Flow = origFlow
		client_Email = origEmail
		client_LimitIP = origLimitIP
		client_TotalGB = origTotalGB
		client_ExpiryTime = origExpiry
		client_Enable = origEnable
		client_TgID = origTgID
		client_SubID = origSubID
		client_Comment = origComment
		client_Reset = origReset
		client_Security = origSec
		client_ShPassword = origShPw
		client_TrPassword = origTrPw
		client_Method = origMethod
	})

	tg := (&Tgbot{}).NewTgbot()

	// 1. HashStorage lazy init + >64-char round trip
	hs := tg.GetHashStorage()
	if hs == nil {
		t.Fatalf("GetHashStorage returned nil")
	}
	longQuery := "very_long_callback_action_" + strings.Repeat("x", 80)
	encoded := tg.encodeQuery(longQuery)
	if encoded == longQuery || len(encoded) > 64 {
		t.Fatalf("encodeQuery did not hash long query: %q", encoded)
	}
	decoded, err := tg.decodeQuery(encoded)
	if err != nil || decoded != longQuery {
		t.Fatalf("decodeQuery = (%q, %v), want %q", decoded, err, longQuery)
	}

	// 2. isSingleWord checks
	for _, bad := range []string{"", "   ", "two words", "alice\tbob"} {
		if tg.isSingleWord(bad) {
			t.Fatalf("isSingleWord(%q) = true, want false", bad)
		}
	}
	if !tg.isSingleWord("  alice@example.com ") {
		t.Fatalf("isSingleWord(%q) = false, want true", "  alice@example.com ")
	}

	// 3. Nil bot / nil callback / short status loads guards
	tg.answerCallback(nil, true)
	tg.SendMsgToTgbot(12345, "safe noop with nil bot")
	tg.setCachedStatus(&Status{Loads: []float64{0.25}})
	if usage := tg.prepareServerUsageInfo(); usage == "" {
		t.Fatalf("prepareServerUsageInfo returned empty string")
	}

	// 4. BuildInboundClientDataMessage future expiry formatting (must show positive remaining hours/date)
	client_Email = "bot-user@example.com"
	client_Id = "11111111-1111-1111-1111-111111111111"
	client_Flow = ""
	client_TotalGB = 5 << 30
	client_LimitIP = 2
	client_Enable = false
	client_ExpiryTime = time.Now().Add(24 * time.Hour).UnixMilli()
	client_TgID = "123456789"
	client_SubID = "sub-bot"
	client_Comment = "line1\n\"quoted\""
	client_Reset = 0

	previewMsg24h, err := tg.BuildInboundClientDataMessage("VLESS-INB", model.VLESS)
	if err != nil {
		t.Fatalf("BuildInboundClientDataMessage(24h): %v", err)
	}
	wantUnit := tg.I18nBot("tgbot.hours")
	if !strings.Contains(previewMsg24h, "23 "+wantUnit) && !strings.Contains(previewMsg24h, "24 "+wantUnit) {
		t.Fatalf("unexpected 24h expiry preview message: %s", previewMsg24h)
	}

	client_ExpiryTime = time.Now().Add(50 * time.Hour).UnixMilli()
	expectedDate := time.Unix(client_ExpiryTime/1000, 0).Format("2006-01-02")
	previewMsg, err := tg.BuildInboundClientDataMessage("VLESS-INB", model.VLESS)
	if err != nil {
		t.Fatalf("BuildInboundClientDataMessage(50h): %v", err)
	}
	if !strings.Contains(previewMsg, expectedDate) {
		t.Fatalf("unexpected 50h expiry preview message (want %s): %s", expectedDate, previewMsg)
	}

	// 5. BuildJSONForProtocol + SubmitAddClient (JSON escaping, numeric tgId, flow fallback, SyncInboundAccounts)
	vlessInb := &model.Inbound{
		UserId:         1,
		Tag:            "bot-vless",
		Remark:         "BOT-VLESS",
		Port:           48201,
		Protocol:       model.VLESS,
		Enable:         true,
		Settings:       `{"decryption":"none","flow":"xtls-rprx-vision","clients":[]}`,
		StreamSettings: `{"network":"tcp","security":"tls"}`,
	}
	if err := db.Create(vlessInb).Error; err != nil {
		t.Fatalf("create vlessInb: %v", err)
	}
	receiver_inbound_ID = vlessInb.Id

	rawSettings, err := tg.BuildJSONForProtocol(model.VLESS)
	if err != nil {
		t.Fatalf("BuildJSONForProtocol(VLESS): %v", err)
	}
	var parsedVless struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal([]byte(rawSettings), &parsedVless); err != nil || len(parsedVless.Clients) != 1 {
		t.Fatalf("invalid BuildJSONForProtocol JSON (%v): %s", err, rawSettings)
	}
	cli := parsedVless.Clients[0]
	if cli["email"] != "bot-user@example.com" || cli["comment"] != "line1\n\"quoted\"" {
		t.Fatalf("JSON escaping mismatch: %+v", cli)
	}
	if cli["flow"] != "xtls-rprx-vision" {
		t.Fatalf("VLESS flow fallback missing: %+v", cli)
	}
	if tgNum, ok := cli["tgId"].(float64); !ok || int64(tgNum) != 123456789 {
		t.Fatalf("expected numeric tgId 123456789, got %#v (%T)", cli["tgId"], cli["tgId"])
	}

	if _, err := tg.SubmitAddClient(); err != nil {
		t.Fatalf("SubmitAddClient: %v", err)
	}
	var syncedAcc model.Account
	if err := db.Where("email = ?", "bot-user@example.com").First(&syncedAcc).Error; err != nil {
		t.Fatalf("expected SubmitAddClient to sync model.Account: %v", err)
	}

	// 6. SS2022 derived key generation in BuildJSONForProtocol
	ssInb := &model.Inbound{
		UserId:   1,
		Tag:      "bot-ss2022",
		Remark:   "BOT-SS2022",
		Port:     48202,
		Protocol: model.Shadowsocks,
		Enable:   true,
		Settings: `{"method":"2022-blake3-aes-128-gcm","password":"aaaaaaaaaaaaaaaaaaaaaa==","clients":[]}`,
	}
	if err := db.Create(ssInb).Error; err != nil {
		t.Fatalf("create ssInb: %v", err)
	}
	receiver_inbound_ID = ssInb.Id
	client_ShPassword = "invalid-plain-password"
	ssJSON, err := tg.BuildJSONForProtocol(model.Shadowsocks)
	if err != nil {
		t.Fatalf("BuildJSONForProtocol(Shadowsocks): %v", err)
	}
	var parsedSS struct {
		Clients []struct {
			Password string `json:"password"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(ssJSON), &parsedSS); err != nil || len(parsedSS.Clients) != 1 {
		t.Fatalf("unmarshal SS JSON: %v %s", err, ssJSON)
	}
	if !validShadowsocksKey(parsedSS.Clients[0].Password, 16) {
		t.Fatalf("SS2022 client password %q is not a valid 16-byte PSK", parsedSS.Clients[0].Password)
	}

	// 7. clientInfoMsg with per-inbound breakdown + reseller owner + balance
	reseller := &model.User{Username: "seller-ali", Password: "x", Enable: true, IsReseller: true}
	if err := db.Create(reseller).Error; err != nil {
		t.Fatalf("create reseller: %v", err)
	}
	if err := db.Create(&model.ResellerProfile{UserId: reseller.Id, CreatedBy: 1, AllowanceBytes: 10 << 30}).Error; err != nil {
		t.Fatalf("create reseller profile: %v", err)
	}
	if err := db.Create(&model.ResellerClient{
		UserId: reseller.Id, Email: "bot-user@example.com", InboundId: vlessInb.Id, ChargedBytes: 2 << 30,
	}).Error; err != nil {
		t.Fatalf("create reseller client: %v", err)
	}
	infoOut := tg.clientInfoMsg(&xray.ClientTraffic{
		Email:  "bot-user@example.com",
		Enable: true,
		Up:     1 << 20,
		Down:   2 << 20,
		Total:  5 << 30,
		InboundTraffics: []xray.InboundTrafficBreakdown{
			{InboundId: vlessInb.Id, Protocol: "vless", Remark: "BOT-VLESS", Port: 48201, Up: 1 << 20, Down: 2 << 20, Enable: true},
		},
	}, true, false, false, false, true, false)
	if !strings.Contains(infoOut, "BOT-VLESS") || !strings.Contains(infoOut, "seller-ali") {
		t.Fatalf("expected clientInfoMsg to include inbound breakdown and reseller info, got:\n%s", infoOut)
	}
}

func TestInboundServiceBotMultiInboundAndParkedHelpers(t *testing.T) {
	acctSvc := newAccountsDB(t)
	inbSvc := &InboundService{}
	db := database.GetDB()

	ib1 := seedInboundWithClients(t, model.VLESS, 48301, []map[string]any{
		{"id": "44444444-4444-4444-4444-444444444444", "email": "alice@example.com", "enable": false, "totalGB": float64(5 << 30)},
	})
	ib2 := seedInboundWithClients(t, model.VMESS, 48302, []map[string]any{})
	parkSource := seedTaggedInbound(t, model.VLESS, 48303, []map[string]any{
		{"id": "55555555-5555-5555-5555-555555555555", "email": "parked@example.com", "enable": false, "totalGB": float64(2 << 30), "subId": "park-sub"},
	})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: ib1.Id, Enable: false, Email: "alice@example.com", Total: 5 << 30})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: parkSource.Id, Enable: false, Email: "parked@example.com", Total: 2 << 30})
	acctSvc.MigrationAccounts()

	// Spread alice across ib1 + ib2, then point client_traffics.inbound_id to a stale non-existent inbound ID.
	if _, err := acctSvc.ApplyMemberships("alice@example.com", []int{ib1.Id, ib2.Id}, nil, true); err != nil {
		t.Fatalf("ApplyMemberships(alice): %v", err)
	}
	if err := db.Model(&xray.ClientTraffic{}).Where("email = ?", "alice@example.com").Update("inbound_id", 999999).Error; err != nil {
		t.Fatalf("stale inbound_id update: %v", err)
	}

	// Park parked@example.com cleanly on zero inbounds.
	if _, err := acctSvc.ApplyMemberships("parked@example.com", []int{}, []int{parkSource.Id}, true); err != nil {
		t.Fatalf("park parked@example.com: %v", err)
	}

	// Case-insensitive lookup recovers real serving inbound even with stale client_traffics.inbound_id.
	traffic, resolvedInb, err := inbSvc.GetClientInboundByEmail("ALICE@EXAMPLE.COM")
	if err != nil || traffic == nil || resolvedInb == nil {
		t.Fatalf("GetClientInboundByEmail failed: (%v, %v, %v)", traffic, resolvedInb, err)
	}
	if resolvedInb.Id != ib1.Id && resolvedInb.Id != ib2.Id {
		t.Fatalf("resolved inbound %d not among [%d, %d]", resolvedInb.Id, ib1.Id, ib2.Id)
	}

	// Parked account synthesizes a valid *model.Client.
	parkedTraffic, parkedClient, err := inbSvc.GetClientByEmail("parked@example.com")
	if err != nil || parkedTraffic == nil || parkedClient == nil {
		t.Fatalf("GetClientByEmail(parked) failed: (%v, %v, %v)", parkedTraffic, parkedClient, err)
	}
	if parkedClient.SubID != "park-sub" || parkedClient.ID != "55555555-5555-5555-5555-555555555555" {
		t.Fatalf("unexpected synthesized parked client: %+v", parkedClient)
	}

	// SetClientTelegramUserID updates account AND projects numeric tgId onto both ib1 and ib2.
	if _, err := inbSvc.SetClientTelegramUserID(traffic.Id, 987654321); err != nil {
		t.Fatalf("SetClientTelegramUserID: %v", err)
	}
	if _, err := inbSvc.ResetClientIpLimitByEmail("alice@example.com", 4); err != nil {
		t.Fatalf("ResetClientIpLimitByEmail: %v", err)
	}
	newExp := time.Now().Add(72 * time.Hour).UnixMilli()
	if _, err := inbSvc.ResetClientExpiryTimeByEmail("alice@example.com", newExp); err != nil {
		t.Fatalf("ResetClientExpiryTimeByEmail: %v", err)
	}
	if _, err := inbSvc.ResetClientTrafficLimitByEmail("alice@example.com", 12); err != nil {
		t.Fatalf("ResetClientTrafficLimitByEmail: %v", err)
	}

	for _, id := range []int{ib1.Id, ib2.Id} {
		clients := readClients(t, id)
		if len(clients) != 1 {
			t.Fatalf("inbound %d clients len = %d, want 1", id, len(clients))
		}
		c := clients[0]
		if got, _ := c["limitIp"].(float64); int(got) != 4 {
			t.Fatalf("inbound %d limitIp = %v, want 4", id, c["limitIp"])
		}
		if got, _ := c["expiryTime"].(float64); int64(got) != newExp {
			t.Fatalf("inbound %d expiryTime = %v, want %d", id, c["expiryTime"], newExp)
		}
		if got, _ := c["totalGB"].(float64); int64(got) != int64(12)<<30 {
			t.Fatalf("inbound %d totalGB = %v, want %d", id, c["totalGB"], int64(12)<<30)
		}
		if got, _ := c["tgId"].(float64); int64(got) != 987654321 {
			t.Fatalf("inbound %d tgId = %v, want 987654321", id, c["tgId"])
		}
	}

	// ToggleClientEnableByEmail flips false -> true and projects to both inbounds.
	newEnable, _, err := inbSvc.ToggleClientEnableByEmail("alice@example.com")
	if err != nil || !newEnable {
		t.Fatalf("ToggleClientEnableByEmail = (%v, %v), want (true, nil)", newEnable, err)
	}
	var aliceAcc model.Account
	if err := db.Where("email = ?", "alice@example.com").First(&aliceAcc).Error; err != nil {
		t.Fatalf("query alice account: %v", err)
	}
	if !aliceAcc.Enable || aliceAcc.TgID != 987654321 || aliceAcc.LimitIP != 4 {
		t.Fatalf("alice account mismatch after bot edits: %+v", aliceAcc)
	}

	// tgId == 0 never returns unlinked accounts.
	zeroRows, err := inbSvc.GetClientTrafficTgBot(0)
	if err != nil {
		t.Fatalf("GetClientTrafficTgBot(0): %v", err)
	}
	if len(zeroRows) != 0 {
		t.Fatalf("GetClientTrafficTgBot(0) returned %d rows, want 0", len(zeroRows))
	}

	// Linked tgId returns deduplicated multi-inbound account with InboundTraffics breakdown.
	linkedRows, err := inbSvc.GetClientTrafficTgBot(987654321)
	if err != nil {
		t.Fatalf("GetClientTrafficTgBot(987654321): %v", err)
	}
	if len(linkedRows) != 1 {
		t.Fatalf("GetClientTrafficTgBot(987654321) len = %d, want 1: %+v", len(linkedRows), linkedRows)
	}
	if len(linkedRows[0].InboundTraffics) != 2 {
		t.Fatalf("expected 2 InboundTraffics breakdown rows for multi-inbound client, got %d: %+v", len(linkedRows[0].InboundTraffics), linkedRows[0].InboundTraffics)
	}
}
