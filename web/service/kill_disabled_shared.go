package service

import (
	"encoding/json"
	"regexp"
	"strings"
)

var singleQuotedTokenRe = regexp.MustCompile(`'([^']+)'`)

// filterOnlineTargets returns the deduplicated subset of candidates currently present in
// online, preserving order. Offline disabled users are excluded so periodic sweeps do not
// spam daemon control interfaces or syslogs with disconnect commands for offline users.
func filterOnlineTargets(candidates []string, online map[string]bool) []string {
	if len(candidates) == 0 || len(online) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(candidates))
	var out []string
	for _, u := range candidates {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] || !online[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// parseOcservOnlineUsers extracts connected usernames from `occtl -j show users` JSON output.
func parseOcservOnlineUsers(raw []byte) (map[string]bool, error) {
	trimmed := strings.TrimSpace(string(raw))
	online := make(map[string]bool)
	if trimmed == "" || trimmed == "null" {
		return online, nil
	}
	var users []struct {
		Username string `json:"Username"`
	}
	if err := json.Unmarshal([]byte(trimmed), &users); err != nil {
		return nil, err
	}
	for _, u := range users {
		if name := strings.TrimSpace(u.Username); name != "" {
			online[name] = true
		}
	}
	return online, nil
}

// parseOpenVpnMgmtOnlineUsers extracts connected common names (usernames) from an
// OpenVPN management interface `status`, `status 2`, or `status 3` response.
func parseOpenVpnMgmtOnlineUsers(raw string) map[string]bool {
	online := make(map[string]bool)
	inV1Clients := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "END" {
			break
		}
		if strings.HasPrefix(line, "CLIENT_LIST,") {
			fields := strings.Split(line, ",")
			if len(fields) > 1 {
				if cn := strings.TrimSpace(fields[1]); cn != "" && cn != "UNDEF" {
					online[cn] = true
				}
			}
			continue
		}
		if strings.HasPrefix(line, "CLIENT_LIST\t") {
			fields := strings.Split(line, "\t")
			if len(fields) > 1 {
				if cn := strings.TrimSpace(fields[1]); cn != "" && cn != "UNDEF" {
					online[cn] = true
				}
			}
			continue
		}
		if strings.HasPrefix(line, "Common Name,") {
			inV1Clients = true
			continue
		}
		if strings.HasPrefix(line, "ROUTING TABLE") || strings.HasPrefix(line, "GLOBAL STATS") || strings.HasPrefix(line, "HEADER,") {
			inV1Clients = false
			continue
		}
		if inV1Clients {
			fields := strings.Split(line, ",")
			if len(fields) >= 2 {
				if cn := strings.TrimSpace(fields[0]); cn != "" && cn != "UNDEF" {
					online[cn] = true
				}
			}
		}
	}
	return online
}

// parseAccelOnlineUsers extracts connected usernames from `accel-cmd show sessions username`.
func parseAccelOnlineUsers(raw []byte) map[string]bool {
	online := make(map[string]bool)
	userCol := 0
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip dashed/box separator lines such as "----------" or "------+------"
		if strings.Trim(trimmed, "-+=| ") == "" {
			continue
		}
		if strings.Contains(trimmed, "|") {
			cols := strings.Split(trimmed, "|")
			isHeader := false
			for idx, col := range cols {
				if strings.EqualFold(strings.TrimSpace(col), "username") {
					userCol = idx
					isHeader = true
					break
				}
			}
			if isHeader {
				continue
			}
			if userCol >= 0 && userCol < len(cols) {
				if u := strings.TrimSpace(cols[userCol]); u != "" {
					online[u] = true
				}
			}
			continue
		}
		if strings.EqualFold(trimmed, "username") {
			continue
		}
		online[trimmed] = true
	}
	return online
}

// parseIkev2SAIDs maps each active remote/EAP identity from `swanctl --list-sas` to
// the list of established IKE SA numeric IDs (#<id>) holding that identity.
func parseIkev2SAIDs(raw []byte) map[string][]string {
	saByUser := make(map[string][]string)
	curID := ""
	seenSAForUser := make(map[string]bool)
	for _, ln := range strings.Split(string(raw), "\n") {
		if m := ikeSAHeaderRe.FindStringSubmatch(ln); m != nil {
			curID = m[1]
			continue
		}
		if curID != "" && strings.Contains(ln, "remote") {
			for _, m := range singleQuotedTokenRe.FindAllStringSubmatch(ln, -1) {
				ident := m[1]
				if ident == "" {
					continue
				}
				dedupKey := ident + "\x00" + curID
				if seenSAForUser[dedupKey] {
					continue
				}
				seenSAForUser[dedupKey] = true
				saByUser[ident] = append(saByUser[ident], curID)
			}
		}
	}
	return saByUser
}
