package service

import (
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestFilterOnlineTargets(t *testing.T) {
	online := map[string]bool{
		"alice": true,
		"carol": true,
	}
	candidates := []string{"bob", "alice", "dave", "alice", "carol", " "}
	got := filterOnlineTargets(candidates, online)
	want := []string{"alice", "carol"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterOnlineTargets = %v, want %v", got, want)
	}
	if empty := filterOnlineTargets([]string{"offline1", "offline2"}, online); len(empty) != 0 {
		t.Fatalf("expected empty slice when all disabled users are offline, got %v", empty)
	}
}

func TestParseOcservOnlineUsers(t *testing.T) {
	if online, err := parseOcservOnlineUsers([]byte("[]")); err != nil || len(online) != 0 {
		t.Fatalf("empty occtl JSON = (%v, %v), want empty nil", online, err)
	}
	sample := []byte(`[
		{"ID": 101, "Username": "alice", "IPv4": "10.4.1.2"},
		{"ID": 102, "Username": "bob", "IPv4": "10.4.1.3"}
	]`)
	online, err := parseOcservOnlineUsers(sample)
	if err != nil {
		t.Fatalf("parseOcservOnlineUsers error: %v", err)
	}
	if !online["alice"] || !online["bob"] || online["offline_user"] {
		t.Fatalf("unexpected ocserv online map: %v", online)
	}
}

func TestParseOpenVpnMgmtOnlineUsers(t *testing.T) {
	status2 := strings.Join([]string{
		"OpenVPN CLIENT LIST",
		"Updated,2026-11-14 12:00:00",
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address",
		"CLIENT_LIST,ovpn_online,203.0.113.5:1194,10.8.0.2,,100,200",
		"CLIENT_LIST,UNDEF,203.0.113.6:1194,,,,",
		"ROUTING TABLE",
		"END",
	}, "\r\n")
	online2 := parseOpenVpnMgmtOnlineUsers(status2)
	if !online2["ovpn_online"] || online2["UNDEF"] || online2["ovpn_offline"] {
		t.Fatalf("unexpected status2 online map: %v", online2)
	}

	status1 := strings.Join([]string{
		"OpenVPN CLIENT LIST",
		"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
		"legacy_user,198.51.100.1:443,10,20,2026-11-14",
		"ROUTING TABLE",
		"Virtual Address,Common Name,Real Address,Last Ref",
		"10.8.0.2,legacy_user,198.51.100.1:443,2026-11-14",
		"END",
	}, "\n")
	online1 := parseOpenVpnMgmtOnlineUsers(status1)
	if !online1["legacy_user"] || len(online1) != 1 {
		t.Fatalf("unexpected status1 online map: %v", online1)
	}
}

func TestOpenVpnMgmtKillUsersOnlyKillsOnline(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "mgmt.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var cmds []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(">INFO:OpenVPN Management Interface Version 5\r\n"))

		buf := make([]byte, 4096)
		var acc strings.Builder
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				acc.Write(buf[:n])
				for {
					s := acc.String()
					idx := strings.IndexByte(s, '\n')
					if idx < 0 {
						break
					}
					line := strings.TrimSpace(s[:idx])
					acc.Reset()
					acc.WriteString(s[idx+1:])
					mu.Lock()
					cmds = append(cmds, line)
					mu.Unlock()
					switch {
					case line == "status 2":
						_, _ = conn.Write([]byte("HEADER,CLIENT_LIST,Common Name,Real Address\r\nCLIENT_LIST,disabled_online,1.2.3.4:1111,10.8.0.2\r\nEND\r\n"))
					case strings.HasPrefix(line, "kill "):
						_, _ = conn.Write([]byte("SUCCESS: killed\r\n"))
					case line == "quit":
						return
					}
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	var svc OpenVpnService
	svc.killUsersViaMgmt(sockPath, []string{"disabled_offline_1", "disabled_online", "disabled_offline_2"})
	<-done

	mu.Lock()
	defer mu.Unlock()
	killCount := 0
	for _, c := range cmds {
		if strings.HasPrefix(c, "kill ") {
			killCount++
			if c != "kill disabled_online" {
				t.Fatalf("issued unexpected kill command for offline user: %q", c)
			}
		}
	}
	if killCount != 1 {
		t.Fatalf("killCount = %d (cmds=%v), want 1", killCount, cmds)
	}
}

func TestParseAccelOnlineUsers(t *testing.T) {
	emptyOut := []byte(" username \n----------\n")
	if got := parseAccelOnlineUsers(emptyOut); len(got) != 0 {
		t.Fatalf("expected no active SSTP sessions, got %v", got)
	}
	activeOut := []byte(" username \r\n----------\r\n sstp_alice \r\n sstp_bob \r\n")
	got := parseAccelOnlineUsers(activeOut)
	if !got["sstp_alice"] || !got["sstp_bob"] || got["sstp_offline"] || len(got) != 2 {
		t.Fatalf("unexpected SSTP online users: %v", got)
	}
	tableOut := []byte(" ifname | username | ip \n--------+----------+---------\n ppp0 | table_user | 10.5.0.2 \n")
	gotTable := parseAccelOnlineUsers(tableOut)
	if !gotTable["table_user"] || len(gotTable) != 1 {
		t.Fatalf("unexpected SSTP table online users: %v", gotTable)
	}
}

func TestParseIkev2SAIDs(t *testing.T) {
	listing := strings.Join([]string{
		"ikev2-6: #12, ESTABLISHED, IKEv2, abc:def",
		"  local  'vpn.example.com' @ 203.0.113.10[4500]",
		"  remote '198.51.100.20' @ 198.51.100.20[4500] EAP: 'ike_online'",
		"ikev2-6: #15, CONNECTING, IKEv2, 111:222",
		"  local  'vpn.example.com' @ 203.0.113.10[500]",
	}, "\n")
	saByUser := parseIkev2SAIDs([]byte(listing))
	if got := saByUser["ike_online"]; !reflect.DeepEqual(got, []string{"12"}) {
		t.Fatalf("saByUser[ike_online] = %v, want [12]", got)
	}
	if got := saByUser["ike_offline"]; len(got) != 0 {
		t.Fatalf("expected no SAs for offline user, got %v", got)
	}
}
