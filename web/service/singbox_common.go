package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"

	statsService "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type singboxSocksAccount struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type clashConnectionsResp struct {
	Connections []clashConnection `json:"connections"`
}

type clashConnection struct {
	ID       string   `json:"id"`
	Chains   []string `json:"chains"`
	Start    any      `json:"start"`
	Metadata struct {
		SourceIP string `json:"sourceIP"`
		User     string `json:"user"`
	} `json:"metadata"`
}

func (c clashConnection) startUnixNano() int64 {
	switch v := c.Start.(type) {
	case float64:
		return int64(v) * int64(time.Millisecond)
	case string:
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.UnixNano()
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UnixNano()
		}
	}
	return 0
}

var singboxChainIdxRe = regexp.MustCompile(`^xray-u-(\d+)$`)

var (
	singboxUserStatRe    = regexp.MustCompile(`^user>>>([^>]+)>>>traffic>>>(uplink|downlink)$`)
	singboxInboundStatRe = regexp.MustCompile(`^inbound>>>([^>]+)>>>traffic>>>(uplink|downlink)$`)
)

func getDisabledAccountEmails() map[string]bool {
	disabled := map[string]bool{}
	db := database.GetDB()
	if db == nil {
		return disabled
	}
	var traffics []*xray.ClientTraffic
	if err := db.Model(xray.ClientTraffic{}).Where("enable = ?", false).Find(&traffics).Error; err != nil {
		return disabled
	}
	for _, t := range traffics {
		disabled[t.Email] = true
	}
	return disabled
}

func loadOrCreateClashSecret(cfgPath string) string {
	if raw, err := os.ReadFile(cfgPath); err == nil {
		var parsed struct {
			Experimental struct {
				ClashAPI struct {
					Secret string `json:"secret"`
				} `json:"clash_api"`
			} `json:"experimental"`
		}
		if json.Unmarshal(raw, &parsed) == nil && parsed.Experimental.ClashAPI.Secret != "" {
			return parsed.Experimental.ClashAPI.Secret
		}
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func buildLoopbackSocksInbound(inbound *model.Inbound, socksPort int, accounts []singboxSocksAccount) *xray.InboundConfig {
	var socksSettings []byte
	var err error
	if len(accounts) > 0 {
		socksSettings, err = json.Marshal(struct {
			Auth     string                `json:"auth"`
			Accounts []singboxSocksAccount `json:"accounts"`
			UDP      bool                  `json:"udp"`
		}{Auth: "password", Accounts: accounts, UDP: true})
	} else {
		socksSettings, err = json.Marshal(struct {
			Auth string `json:"auth"`
			UDP  bool   `json:"udp"`
		}{Auth: "noauth", UDP: true})
	}
	if err != nil {
		logger.Warning("sing-box bridge: socks settings marshal failed:", err)
		return nil
	}
	sniffing := `{"enabled":true,"destOverride":["tls","http","quic"]}`
	return &xray.InboundConfig{
		Listen:   json_util.RawMessage(`"127.0.0.1"`),
		Port:     socksPort,
		Protocol: "socks",
		Settings: json_util.RawMessage(socksSettings),
		Tag:      inbound.Tag,
		Sniffing: json_util.RawMessage(sniffing),
	}
}

func buildSingboxRouteOutboundsForXray(inboundTag string, socksPort int, accounts []singboxSocksAccount) (outbounds []map[string]any, routeRules []map[string]any, finalOutbound string) {
	for i, u := range accounts {
		outTag := fmt.Sprintf("xray-u-%d", i)
		outbounds = append(outbounds, map[string]any{
			"type":        "socks",
			"tag":         outTag,
			"server":      "127.0.0.1",
			"server_port": socksPort,
			"version":     "5",
			"username":    u.User,
			"password":    u.Pass,
		})
		routeRules = append(routeRules, map[string]any{
			"inbound":   []string{inboundTag},
			"auth_user": []string{u.User},
			"outbound":  outTag,
		})
	}
	fallbackOut := map[string]any{
		"type":        "socks",
		"tag":         "xray-fallback",
		"server":      "127.0.0.1",
		"server_port": socksPort,
		"version":     "5",
	}
	if len(accounts) > 0 {
		fallbackOut["username"] = accounts[0].User
		fallbackOut["password"] = accounts[0].Pass
	}
	outbounds = append(outbounds, fallbackOut)
	return outbounds, routeRules, "xray-fallback"
}

func fetchClashConnections(port int, secret string) ([]clashConnection, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/connections", port)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clash api /connections status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var parsed clashConnectionsResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	return parsed.Connections, nil
}

func closeClashConnection(port int, secret, connID string) {
	if connID == "" {
		return
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/connections/%s", port, connID)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func enforceClashIPLimits(
	port int,
	secret string,
	strategy string,
	resolveUser func(clashConnection) string,
	limitForUser func(string) int,
) {
	if resolveUser == nil || limitForUser == nil {
		return
	}
	conns, err := fetchClashConnections(port, secret)
	if err != nil || len(conns) == 0 {
		return
	}

	type ipBucket struct {
		ip       string
		earliest int64
		connIDs  []string
	}
	byUser := map[string]map[string]*ipBucket{}
	for _, conn := range conns {
		user := resolveUser(conn)
		ip := strings.TrimSpace(conn.Metadata.SourceIP)
		if user == "" || ip == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		userMap := byUser[user]
		if userMap == nil {
			userMap = map[string]*ipBucket{}
			byUser[user] = userMap
		}
		b := userMap[ip]
		if b == nil {
			b = &ipBucket{ip: ip, earliest: conn.startUnixNano()}
			userMap[ip] = b
		} else if st := conn.startUnixNano(); st > 0 && (b.earliest == 0 || st < b.earliest) {
			b.earliest = st
		}
		b.connIDs = append(b.connIDs, conn.ID)
	}

	for user, userMap := range byUser {
		limit := limitForUser(user)
		if limit <= 0 || len(userMap) <= limit {
			continue
		}
		buckets := make([]*ipBucket, 0, len(userMap))
		for _, b := range userMap {
			buckets = append(buckets, b)
		}
		sort.Slice(buckets, func(i, j int) bool {
			if buckets[i].earliest == buckets[j].earliest {
				return buckets[i].ip < buckets[j].ip
			}
			return buckets[i].earliest < buckets[j].earliest
		})

		var evict []*ipBucket
		if strings.EqualFold(strings.TrimSpace(strategy), "reject") {
			evict = buckets[limit:]
		} else {
			evict = buckets[:len(buckets)-limit]
		}
		for _, b := range evict {
			for _, id := range b.connIDs {
				closeClashConnection(port, secret, id)
			}
		}
	}
}

func resolveChainIndex(chains []string) (int, bool) {
	for _, ch := range chains {
		if m := singboxChainIdxRe.FindStringSubmatch(ch); len(m) == 2 {
			if idx, err := strconv.Atoi(m[1]); err == nil && idx >= 0 {
				return idx, true
			}
		}
	}
	return 0, false
}

func querySingboxV2rayStats(
	port int,
	inboundID int,
	inboundTag string,
	includeInbound bool,
	mapUserEmail func(rawUser string) string,
) ([]*xray.Traffic, []*xray.ClientTraffic) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	client := statsService.NewStatsServiceClient(conn)
	resp, err := client.QueryStats(ctx, &statsService.QueryStatsRequest{Reset_: true})
	if err != nil {
		logger.Debug("sing-box: QueryStats failed on inbound", inboundID, ":", err)
		return nil, nil
	}

	type trafficPair struct {
		up   int64
		down int64
	}
	var inbPair trafficPair
	userPairs := map[string]*trafficPair{}

	for _, st := range resp.GetStat() {
		if m := singboxUserStatRe.FindStringSubmatch(st.Name); len(m) == 3 {
			email := m[1]
			if mapUserEmail != nil {
				if mapped := strings.TrimSpace(mapUserEmail(email)); mapped != "" {
					email = mapped
				}
			}
			p := userPairs[email]
			if p == nil {
				p = &trafficPair{}
				userPairs[email] = p
			}
			if m[2] == "uplink" {
				p.up += st.Value
			} else {
				p.down += st.Value
			}
			continue
		}
		if includeInbound {
			if m := singboxInboundStatRe.FindStringSubmatch(st.Name); len(m) == 3 && m[1] == inboundTag {
				if m[2] == "uplink" {
					inbPair.up += st.Value
				} else {
					inbPair.down += st.Value
				}
			}
		}
	}

	var outInbounds []*xray.Traffic
	if includeInbound && (inbPair.up > 0 || inbPair.down > 0) {
		outInbounds = append(outInbounds, &xray.Traffic{
			IsInbound:  true,
			IsOutbound: false,
			Tag:        inboundTag,
			Up:         inbPair.up,
			Down:       inbPair.down,
		})
	}

	var outClients []*xray.ClientTraffic
	for email, p := range userPairs {
		if p.up <= 0 && p.down <= 0 {
			continue
		}
		outClients = append(outClients, &xray.ClientTraffic{
			InboundId: inboundID,
			Email:     email,
			Up:        p.up,
			Down:      p.down,
		})
	}
	return outInbounds, outClients
}

type sidecarTLSInput struct {
	ServerName      string
	Listen          string
	CertificateFile string
	KeyFile         string
	Certificate     string
	Key             string
	StreamSettings  string
}

func resolveSidecarTLSCerts(dir string, in sidecarTLSInput, settingService *SettingService) (certPath, keyPath, fingerprint string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", "", err
	}

	certFile := strings.TrimSpace(in.CertificateFile)
	keyFile := strings.TrimSpace(in.KeyFile)
	certPEM := strings.TrimSpace(in.Certificate)
	keyPEM := strings.TrimSpace(in.Key)
	sni := strings.TrimSpace(in.ServerName)

	if strings.TrimSpace(in.StreamSettings) != "" {
		var stream struct {
			TlsSettings struct {
				ServerName   string `json:"serverName"`
				Certificates []struct {
					CertificateFile string `json:"certificateFile"`
					KeyFile         string `json:"keyFile"`
					Certificate     string `json:"certificate"`
					Key             string `json:"key"`
				} `json:"certificates"`
			} `json:"tlsSettings"`
		}
		if json.Unmarshal([]byte(in.StreamSettings), &stream) == nil {
			if sni == "" {
				sni = strings.TrimSpace(stream.TlsSettings.ServerName)
			}
			if certFile == "" && keyFile == "" && certPEM == "" && keyPEM == "" && len(stream.TlsSettings.Certificates) > 0 {
				c := stream.TlsSettings.Certificates[0]
				if strings.TrimSpace(c.CertificateFile) != "" && strings.TrimSpace(c.KeyFile) != "" {
					certFile = strings.TrimSpace(c.CertificateFile)
					keyFile = strings.TrimSpace(c.KeyFile)
				} else if strings.TrimSpace(c.Certificate) != "" && strings.TrimSpace(c.Key) != "" {
					certPEM = strings.TrimSpace(c.Certificate)
					keyPEM = strings.TrimSpace(c.Key)
				}
			}
		}
	}

	if certFile != "" && keyFile != "" {
		return certFile, keyFile, fileHashPair(certFile, keyFile), nil
	}
	if certPEM != "" && keyPEM != "" {
		cp := filepath.Join(dir, "server.crt")
		kp := filepath.Join(dir, "server.key")
		if err := writeFileIfChanged(cp, []byte(certPEM+"\n"), 0o644); err != nil {
			return "", "", "", err
		}
		if err := writeFileIfChanged(kp, []byte(keyPEM+"\n"), 0o600); err != nil {
			return "", "", "", err
		}
		sum := sha256.Sum256([]byte(certPEM + "|" + keyPEM))
		return cp, kp, hex.EncodeToString(sum[:]), nil
	}

	if settingService != nil {
		if cf, err := settingService.GetCertFile(); err == nil && strings.TrimSpace(cf) != "" {
			if kf, err := settingService.GetKeyFile(); err == nil && strings.TrimSpace(kf) != "" {
				if regularFileExists(cf) && regularFileExists(kf) {
					return cf, kf, fileHashPair(cf, kf), nil
				}
			}
		}
		if cf, err := settingService.GetSubCertFile(); err == nil && strings.TrimSpace(cf) != "" {
			if kf, err := settingService.GetSubKeyFile(); err == nil && strings.TrimSpace(kf) != "" {
				if regularFileExists(cf) && regularFileExists(kf) {
					return cf, kf, fileHashPair(cf, kf), nil
				}
			}
		}
	}

	cp := filepath.Join(dir, "selfsigned.crt")
	kp := filepath.Join(dir, "selfsigned.key")
	if !regularFileExists(cp) || !regularFileExists(kp) {
		host := sni
		if host == "" {
			host = strings.TrimSpace(in.Listen)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "localhost"
		}
		genDir := filepath.Join(dir, ".gen")
		pCert, pKey, gerr := GeneratePanelSelfSignedCert(genDir, host)
		if gerr != nil {
			return "", "", "", fmt.Errorf("sing-box self-signed cert: %w", gerr)
		}
		if err := os.Rename(pCert, cp); err != nil {
			if raw, rerr := os.ReadFile(pCert); rerr == nil {
				_ = os.WriteFile(cp, raw, 0o644)
			} else {
				_ = os.RemoveAll(genDir)
				return "", "", "", err
			}
		}
		if err := os.Rename(pKey, kp); err != nil {
			if raw, rerr := os.ReadFile(pKey); rerr == nil {
				_ = os.WriteFile(kp, raw, 0o600)
			} else {
				_ = os.RemoveAll(genDir)
				return "", "", "", err
			}
		}
		_ = os.RemoveAll(genDir)
	}
	return cp, kp, fileHashPair(cp, kp), nil
}
