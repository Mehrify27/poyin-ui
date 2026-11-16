package service

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/xray"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

type fakeRadiusRW struct {
	resp *radius.Packet
}

func (f *fakeRadiusRW) Write(p *radius.Packet) error {
	f.resp = p
	return nil
}

type fakeAcctCounters struct {
	up     int64
	down   int64
	active bool
}

type fakeNftAcctBackend struct {
	mu      sync.Mutex
	entries map[string]*fakeAcctCounters
	adds    int
	removes int
}

func newFakeNftAcctBackend() *fakeNftAcctBackend {
	return &fakeNftAcctBackend{
		entries: make(map[string]*fakeAcctCounters),
	}
}

func fakeAcctKey(protocol, ip string) string {
	return protocol + ":" + ip
}

func (b *fakeNftAcctBackend) setBytes(protocol, ip string, up, down int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := fakeAcctKey(protocol, ip)
	e := b.entries[key]
	if e == nil {
		e = &fakeAcctCounters{active: true}
		b.entries[key] = e
	}
	e.up += up
	e.down += down
	e.active = true
}

func (b *fakeNftAcctBackend) isActive(protocol, ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[fakeAcctKey(protocol, ip)]
	return e != nil && e.active
}

func (b *fakeNftAcctBackend) addClientAccounting(protocol, ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.adds++
	key := fakeAcctKey(protocol, ip)
	e := b.entries[key]
	if e == nil {
		e = &fakeAcctCounters{active: true}
		b.entries[key] = e
	} else {
		e.active = true
	}
	return nil
}

func (b *fakeNftAcctBackend) removeClientAccounting(protocol, ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removes++
	key := fakeAcctKey(protocol, ip)
	if e := b.entries[key]; e != nil {
		e.active = false
		e.up = 0
		e.down = 0
	}
	return nil
}

func (b *fakeNftAcctBackend) readAndResetClientCounters(protocol, ip string) (int64, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[fakeAcctKey(protocol, ip)]
	if e == nil || !e.active {
		return 0, 0
	}
	up, down := e.up, e.down
	e.up, e.down = 0, 0
	return up, down
}

func (b *fakeNftAcctBackend) collectAndResetTraffic(byProto map[string]map[string]string, byProtoInbound map[string]map[string]int) []*xray.ClientTraffic {
	b.mu.Lock()
	defer b.mu.Unlock()
	type acc struct {
		up, down int64
	}
	var out []*xray.ClientTraffic
	for proto, ipToEmail := range byProto {
		for ip, email := range ipToEmail {
			e := b.entries[fakeAcctKey(proto, ip)]
			if e == nil || !e.active || (e.up == 0 && e.down == 0) {
				continue
			}
			inbId := 0
			if byProtoInbound != nil {
				inbId = byProtoInbound[proto][ip]
			}
			out = append(out, &xray.ClientTraffic{
				Email:     email,
				InboundId: inbId,
				Up:        e.up,
				Down:      e.down,
			})
			e.up, e.down = 0, 0
		}
	}
	return out
}

func TestRadiusAccountingFoldOnAcceptEvictionAndLateStop(t *testing.T) {
	backend := newFakeNftAcctBackend()
	var foldedUp, foldedDown int64
	var foldedEmail string

	s := &RadiusService{
		sessions: map[string]*radiusSession{
			"pptp-sess-1": {
				email:     "user1@t",
				ip:        "10.1.0.2",
				protocol:  "pptp",
				inboundId: 7,
				started:   time.Now().Add(-time.Minute),
			},
		},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		nftService:  NftService{acctBackend: backend},
		secret:      []byte("testsecret"),
		foldTrafficFn: func(email, protocol string, inboundId int, up, down int64) {
			foldedEmail = email
			foldedUp += up
			foldedDown += down
		},
	}

	// Simulate traffic before eviction under rapid CHAP/pppd redial churn.
	backend.setBytes("pptp", "10.1.0.2", 12345, 67890)

	// New device (or churned NAS-Port) evicts oldest session on User-Limit=1 "accept".
	assignedIP, rejected := s.allocateBlockIP(7, 0, []string{"10.1.0.2"}, "pptp", "accept", "198.51.100.10", 12, "user1@t")

	if rejected || assignedIP == nil || assignedIP.String() != "10.1.0.2" {
		t.Fatalf("allocateBlockIP = (%v, %v), want (10.1.0.2, false)", assignedIP, rejected)
	}
	if foldedEmail != "user1@t" || foldedUp != 12345 || foldedDown != 67890 {
		t.Fatalf("eviction fold = (%q, %d, %d), want (user1@t, 12345, 67890)", foldedEmail, foldedUp, foldedDown)
	}
	if !backend.isActive("pptp", "10.1.0.2") {
		t.Fatal("eviction+reassignment left nft accounting inactive for newcomer")
	}

	// Simulate newcomer accumulating traffic before late Acct-Stop for evicted session arrives.
	backend.setBytes("pptp", "10.1.0.2", 500, 900)

	// Late Acct-Stop arrives for pptp-sess-1 BEFORE newcomer's Acct-Start arrives (pendingActive = true).
	pktStop := radius.New(radius.CodeAccountingRequest, []byte("testsecret"))
	rfc2866.AcctStatusType_Set(pktStop, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctSessionID_SetString(pktStop, "pptp-sess-1")
	rfc2865.UserName_SetString(pktStop, "user1")
	rfc2865.NASIdentifier_SetString(pktStop, "pptp-7")
	rfc2865.FramedIPAddress_Set(pktStop, net.ParseIP("10.1.0.2").To4())
	s.handleAcct(&fakeRadiusRW{}, &radius.Request{Packet: pktStop})

	// Must not remove rule while pending lease is active, and must not lose or double-fold.
	if !backend.isActive("pptp", "10.1.0.2") {
		t.Fatal("late Acct-Stop removed nft accounting while pending lease was active")
	}

	// Now newcomer's Acct-Start arrives on pptp-sess-2 and sends normal Acct-Stop later.
	pktStart := radius.New(radius.CodeAccountingRequest, []byte("testsecret"))
	rfc2866.AcctStatusType_Set(pktStart, rfc2866.AcctStatusType_Value_Start)
	rfc2866.AcctSessionID_SetString(pktStart, "pptp-sess-2")
	rfc2865.UserName_SetString(pktStart, "user1")
	rfc2865.NASIdentifier_SetString(pktStart, "pptp-7")
	rfc2865.FramedIPAddress_Set(pktStart, net.ParseIP("10.1.0.2").To4())

	// Populate sess directly as handleAcct Start requires DB email lookup when DB exists;
	// simulate same atomic Acct-Start registration then stop.
	nftAcctMu.Lock()
	s.mu.Lock()
	s.sessions["pptp-sess-2"] = &radiusSession{email: "user1@t", ip: "10.1.0.2", protocol: "pptp", inboundId: 7, started: time.Now()}
	delete(s.pending, "10.1.0.2")
	s.mu.Unlock()
	nftAcctMu.Unlock()

	// Late stale stop for yet another old session id after newcomer is live must also spare newcomer's rule+bytes.
	pktLate := radius.New(radius.CodeAccountingRequest, []byte("testsecret"))
	rfc2866.AcctStatusType_Set(pktLate, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctSessionID_SetString(pktLate, "pptp-sess-0")
	rfc2865.UserName_SetString(pktLate, "user1")
	rfc2865.NASIdentifier_SetString(pktLate, "pptp-7")
	rfc2865.FramedIPAddress_Set(pktLate, net.ParseIP("10.1.0.2").To4())
	s.handleAcct(&fakeRadiusRW{}, &radius.Request{Packet: pktLate})

	if !backend.isActive("pptp", "10.1.0.2") {
		t.Fatal("stale orphan Acct-Stop removed active newcomer nft accounting rule")
	}
	if up, down := backend.readAndResetClientCounters("pptp", "10.1.0.2"); up != 500 || down != 900 {
		t.Fatalf("newcomer bytes corrupted: got (%d, %d), want (500, 900)", up, down)
	}
}

func TestRadiusAccountingIdempotentRedialKeepsRuleAcrossStop(t *testing.T) {
	backend := newFakeNftAcctBackend()
	var foldedUp, foldedDown int64
	s := &RadiusService{
		sessions: map[string]*radiusSession{
			"pptp-old": {
				email:     "redial@t",
				ip:        "10.1.0.5",
				protocol:  "pptp",
				inboundId: 2,
				started:   time.Now().Add(-time.Minute),
			},
		},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		nftService:  NftService{acctBackend: backend},
		secret:      []byte("testsecret"),
		foldTrafficFn: func(email, protocol string, inboundId int, up, down int64) {
			foldedUp += up
			foldedDown += down
		},
	}
	backend.setBytes("pptp", "10.1.0.5", 4000, 8000)

	// Same station + same NAS-Port re-authenticates (CHAP flap / idempotent redial).
	ip1, _ := s.allocateBlockIP(2, 0, []string{"10.1.0.5"}, "pptp", "reject", "203.0.113.9", 5, "redial@t")
	// Refresh redial claim once already recorded:
	ip2, rej2 := s.allocateBlockIP(2, 0, []string{"10.1.0.5"}, "pptp", "reject", "203.0.113.9", 5, "redial@t")
	if ip1 == nil || ip2 == nil || rej2 || ip2.String() != "10.1.0.5" {
		t.Fatalf("redial failed: (%v, %v, %v)", ip1, ip2, rej2)
	}

	// Old session sends Acct-Stop while s.pending["10.1.0.5"] is active.
	pktStop := radius.New(radius.CodeAccountingRequest, []byte("testsecret"))
	rfc2866.AcctStatusType_Set(pktStop, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctSessionID_SetString(pktStop, "pptp-old")
	rfc2865.UserName_SetString(pktStop, "redial")
	rfc2865.NASIdentifier_SetString(pktStop, "pptp-2")
	rfc2865.FramedIPAddress_Set(pktStop, net.ParseIP("10.1.0.5").To4())
	s.handleAcct(&fakeRadiusRW{}, &radius.Request{Packet: pktStop})

	if foldedUp != 4000 || foldedDown != 8000 {
		t.Fatalf("redial Acct-Stop lost old bytes: got (%d, %d), want (4000, 8000)", foldedUp, foldedDown)
	}
	if !backend.isActive("pptp", "10.1.0.5") {
		t.Fatal("redial Acct-Stop tore down nft accounting rule needed by pending redial")
	}
}

func TestRadiusAccountingReclaimStaleOpenConnectFoldsBytes(t *testing.T) {
	backend := newFakeNftAcctBackend()
	var foldedUp, foldedDown int64
	s := &RadiusService{
		sessions: map[string]*radiusSession{
			ocSessionKey("10.4.1.2"): {
				email:     "oc@t",
				ip:        "10.4.1.2",
				protocol:  "openconnect",
				inboundId: 9,
				started:   time.Now().Add(-time.Hour),
				heard:     time.Now().Add(-time.Hour),
				acctID:    "oc-old-sid",
			},
		},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		ocActiveFn:  func(string) bool { return false },
		nftService:  NftService{acctBackend: backend},
		foldTrafficFn: func(email, protocol string, inboundId int, up, down int64) {
			foldedUp += up
			foldedDown += down
		},
	}
	backend.setBytes("openconnect", "10.4.1.2", 1111, 2222)

	ip, rejected := s.allocateBlockIP(9, 0, []string{"10.4.1.2"}, "openconnect", "reject", "198.51.100.7", 0, "oc@t")
	s.mu.Lock()
	sess := s.sessions[ocSessionKey("10.4.1.2")]
	s.mu.Unlock()

	if rejected || ip == nil || ip.String() != "10.4.1.2" {
		t.Fatalf("stale reclaim returned (%v, %v)", ip, rejected)
	}
	if foldedUp != 1111 || foldedDown != 2222 {
		t.Fatalf("reclaim did not fold bytes: got (%d, %d), want (1111, 2222)", foldedUp, foldedDown)
	}
	if sess == nil || !sess.reassigned || sess.prevAcctID != "oc-old-sid" {
		t.Fatalf("reclaimed OpenConnect session missing predecessor guard metadata: %+v", sess)
	}
}

func TestOcservAcctStartWithoutFramedIPBindsAndAllowsEarlyStop(t *testing.T) {
	backend := newFakeNftAcctBackend()
	var foldedUp, foldedDown int64
	const secret = "testsecret"
	s := &RadiusService{
		sessions: map[string]*radiusSession{
			ocSessionKey("10.4.2.2"): {
				email:      "fresh@t",
				ip:         "10.4.2.2",
				protocol:   "openconnect",
				inboundId:  5,
				started:    time.Now(),
				reassigned: true,
				prevAcctID: "oc-evicted",
			},
			ocSessionKey("10.4.2.3"): {
				email:     "direct@t",
				ip:        "10.4.2.3",
				protocol:  "openconnect",
				inboundId: 5,
				started:   time.Now(),
			},
		},
		pending:    map[string]time.Time{},
		nftService: NftService{acctBackend: backend},
		secret:     []byte(secret),
		foldTrafficFn: func(email, protocol string, inboundId int, up, down int64) {
			foldedUp += up
			foldedDown += down
		},
	}
	backend.setBytes("openconnect", "10.4.2.2", 300, 700)
	backend.setBytes("openconnect", "10.4.2.3", 100, 200)

	// 1. ocserv sends Acct-Start WITHOUT Framed-IP-Address for the new reassigned session.
	pktStart := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(pktStart, rfc2866.AcctStatusType_Value_Start)
	rfc2866.AcctSessionID_SetString(pktStart, "oc-new-sid")
	rfc2865.UserName_SetString(pktStart, "fresh@t")
	rfc2865.NASIdentifier_SetString(pktStart, "openconnect-5")
	s.handleAcct(&fakeRadiusRW{}, &radius.Request{Packet: pktStart})

	if got := s.sessions[ocSessionKey("10.4.2.2")].acctID; got != "oc-new-sid" {
		t.Fatalf("Acct-Start without Framed-IP did not bind acctID: got %q", got)
	}

	// 2. Evicted predecessor's late Stop is still rejected.
	pktOldStop := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(pktOldStop, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctSessionID_SetString(pktOldStop, "oc-evicted")
	rfc2865.UserName_SetString(pktOldStop, "fresh@t")
	rfc2865.NASIdentifier_SetString(pktOldStop, "openconnect-5")
	rfc2865.FramedIPAddress_Set(pktOldStop, net.ParseIP("10.4.2.2").To4())
	s.handleAcct(&fakeRadiusRW{}, &radius.Request{Packet: pktOldStop})
	if s.sessions[ocSessionKey("10.4.2.2")] == nil {
		t.Fatal("predecessor Acct-Stop deleted newcomer session")
	}

	// 3. Newcomer's genuine quick Stop closes immediately despite being within grace!
	pktNewStop := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(pktNewStop, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctSessionID_SetString(pktNewStop, "oc-new-sid")
	rfc2865.UserName_SetString(pktNewStop, "fresh@t")
	rfc2865.NASIdentifier_SetString(pktNewStop, "openconnect-5")
	rfc2865.FramedIPAddress_Set(pktNewStop, net.ParseIP("10.4.2.2").To4())
	s.handleAcct(&fakeRadiusRW{}, &radius.Request{Packet: pktNewStop})
	if s.sessions[ocSessionKey("10.4.2.2")] != nil {
		t.Fatal("genuine quick Acct-Stop failed to close session matching bound acctID")
	}

	// 4. Non-reassigned fresh session closes immediately on Acct-Stop even without Acct-Start.
	pktDirectStop := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(pktDirectStop, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctSessionID_SetString(pktDirectStop, "oc-direct-sid")
	rfc2865.UserName_SetString(pktDirectStop, "direct@t")
	rfc2865.NASIdentifier_SetString(pktDirectStop, "openconnect-5")
	rfc2865.FramedIPAddress_Set(pktDirectStop, net.ParseIP("10.4.2.3").To4())
	s.handleAcct(&fakeRadiusRW{}, &radius.Request{Packet: pktDirectStop})
	if s.sessions[ocSessionKey("10.4.2.3")] != nil {
		t.Fatal("non-reassigned quick Acct-Stop remained stuck under stale reclaim grace")
	}
	if foldedUp != 400 || foldedDown != 900 {
		t.Fatalf("folded = (%d, %d), want (400, 900)", foldedUp, foldedDown)
	}
}

func TestPppLineHasIPExactMatch(t *testing.T) {
	cases := []struct {
		line string
		ip   string
		want bool
	}{
		{"42: ppp0    inet 10.0.5.0 peer 10.0.5.1/32 scope global ppp0", "10.0.5.1", true},
		{"42: ppp0    inet 10.0.5.0 peer 10.0.5.10/32 scope global ppp0", "10.0.5.1", false},
		{"43: ppp1    inet 10.0.5.1/32 scope global ppp1", "10.0.5.1", true},
		{"44: ppp2    inet 10.0.5.100/24 scope global ppp2", "10.0.5.1", false},
		{"45: ppp3    inet 10.0.5.0 peer 10.0.5.1 scope global ppp3", "10.0.5.1", true},
	}
	for _, tc := range cases {
		if got := pppLineHasIP(tc.line, tc.ip); got != tc.want {
			t.Errorf("pppLineHasIP(%q, %q) = %v, want %v", tc.line, tc.ip, got, tc.want)
		}
	}
}

func TestCleanStaleSessionsFoldAndReplacementGuard(t *testing.T) {
	backend := newFakeNftAcctBackend()
	var foldedUp, foldedDown int64

	deadSess := &radiusSession{
		email:     "dead@t",
		ip:        "10.4.9.2",
		protocol:  "openconnect",
		inboundId: 1,
		started:   time.Now().Add(-time.Hour),
		heard:     time.Now().Add(-time.Hour),
	}
	replacedOld := &radiusSession{
		email:     "old@t",
		ip:        "10.4.9.3",
		protocol:  "openconnect",
		inboundId: 1,
		started:   time.Now().Add(-time.Hour),
		heard:     time.Now().Add(-time.Hour),
	}
	replacedNew := &radiusSession{
		email:     "new@t",
		ip:        "10.4.9.3",
		protocol:  "openconnect",
		inboundId: 1,
		started:   time.Now(),
	}

	s := &RadiusService{
		sessions: map[string]*radiusSession{
			"oc:dead":    deadSess,
			"oc:replace": replacedOld,
		},
		pending:    map[string]time.Time{},
		nftService: NftService{acctBackend: backend},
		foldTrafficFn: func(email, protocol string, inboundId int, up, down int64) {
			foldedUp += up
			foldedDown += down
		},
	}
	s.ocActiveFn = func(ip string) bool {
		if ip == "10.4.9.3" {
			// Concurrent replacement occurs while CleanStaleSessions probes off-lock.
			s.mu.Lock()
			s.sessions["oc:replace"] = replacedNew
			s.mu.Unlock()
		}
		return false
	}

	backend.setBytes("openconnect", "10.4.9.2", 800, 1200)
	backend.setBytes("openconnect", "10.4.9.3", 50, 60)

	s.CleanStaleSessions()

	if s.sessions["oc:dead"] != nil {
		t.Fatal("stale dead session was not cleaned")
	}
	if s.sessions["oc:replace"] != replacedNew {
		t.Fatal("CleanStaleSessions evicted replacement session pointer during off-lock probe")
	}
	if foldedUp != 800 || foldedDown != 1200 {
		t.Fatalf("CleanStaleSessions fold = (%d, %d), want (800, 1200)", foldedUp, foldedDown)
	}
	if !backend.isActive("openconnect", "10.4.9.3") {
		t.Fatal("CleanStaleSessions removed nft accounting rule for replaced session")
	}
}

func TestWithVpnAccountingLockConcurrency(t *testing.T) {
	backend := newFakeNftAcctBackend()
	nft := &NftService{acctBackend: backend}

	var totalProduced int64
	var totalCollected atomic.Int64

	var wg sync.WaitGroup
	// Concurrent producers + collectors exercising CollectAndResetTrafficLocked vs Remove/ReadAndReset.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "10.1.0.10"
			for iter := 0; iter < 50; iter++ {
				WithVpnAccountingLock(func() {
					_ = nft.addClientAccountingLocked("pptp", ip)
					backend.setBytes("pptp", ip, 10, 20)
					totalCollected.Add(0)
					up, down := nft.readAndResetClientCountersLocked("pptp", ip)
					totalCollected.Add(up + down)
				})
				atomic.AddInt64(&totalProduced, 30)
			}
		}(i)
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			byProto := map[string]map[string]string{"pptp": {"10.1.0.10": "u@t"}}
			byInb := map[string]map[string]int{"pptp": {"10.1.0.10": 1}}
			for iter := 0; iter < 50; iter++ {
				WithVpnAccountingLock(func() {
					for _, tr := range nft.CollectAndResetTrafficLocked(byProto, byInb) {
						totalCollected.Add(tr.Up + tr.Down)
					}
				})
			}
		}()
	}
	wg.Wait()

	WithVpnAccountingLock(func() {
		up, down := nft.readAndResetClientCountersLocked("pptp", "10.1.0.10")
		totalCollected.Add(up + down)
	})
	if got := totalCollected.Load(); got != totalProduced {
		t.Fatalf("byte conservation violated under concurrency: collected=%d produced=%d", got, totalProduced)
	}
}
