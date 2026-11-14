// Package vpnsec provides security validation and sanitization helpers shared across
// panel configuration, WireGuard/AWG handling, reverse proxy trust checks, and systemd CLI guards.
package vpnsec

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultTrustedProxies restricts forwarded IP/host header trust to local reverse proxies by default.
const DefaultTrustedProxies = "127.0.0.1,::1"

var (
	wgKeyNameRe        = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	wgDirectiveAssignR = regexp.MustCompile(`(?i)(?:^|[\r\n])\s*(?:post[-_]?up|pre[-_]?up|post[-_]?down|pre[-_]?down|save[-_]?config)\s*=`)
	systemdNameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
)

// dangerousWgDirectives holds canonicalized (lowercased, '-' and '_' stripped) wg-quick keys
// capable of executing arbitrary shell commands or mutating host state on interface lifecycle events.
var dangerousWgDirectives = map[string]struct{}{
	"postup":     {},
	"preup":      {},
	"postdown":   {},
	"predown":    {},
	"saveconfig": {},
}

func canonicalWgKey(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	k = strings.ReplaceAll(k, "_", "")
	k = strings.ReplaceAll(k, "-", "")
	return k
}

// ValidateWireGuardScalar ensures a single value interpolated into WireGuard/AWG config
// files or settings cannot break INI structure, inject new lines, or sneak hook directives.
func ValidateWireGuardScalar(field, value string) error {
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b == '\r' || b == '\n' || b == 0 || b < 0x20 || b == 0x7f {
			return fmt.Errorf("%s contains forbidden control or newline character", field)
		}
	}
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "]") {
		return fmt.Errorf("%s cannot contain INI section header syntax", field)
	}
	if wgDirectiveAssignR.MatchString(value) {
		return fmt.Errorf("%s cannot contain forbidden WireGuard hook directives", field)
	}
	return nil
}

// ValidateWireGuardScalars validates alternating (field, value) pairs with ValidateWireGuardScalar.
func ValidateWireGuardScalars(pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if err := ValidateWireGuardScalar(pairs[i], pairs[i+1]); err != nil {
			return err
		}
	}
	return nil
}

// ValidateWireGuardKey validates that key is a canonical 32-byte Curve25519 WireGuard key
// encoded in standard base64 without control characters or internal whitespace.
func ValidateWireGuardKey(field, key string) error {
	if err := ValidateWireGuardScalar(field, key); err != nil {
		return err
	}
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("%s cannot be empty", field)
	}
	if strings.ContainsAny(trimmed, " \t") || len(trimmed) != 44 {
		return fmt.Errorf("%s must be a 44-character base64 WireGuard key", field)
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s must decode to a 32-byte WireGuard key", field)
	}
	return nil
}

// ValidateWireGuardConfText performs strict line-by-line validation on wg-quick / amneziawg
// INI configuration files, rejecting malformed lines, control characters, and command-execution
// directives (PreUp, PostUp, PreDown, PostDown, SaveConfig).
func ValidateWireGuardConfText(conf string) error {
	if strings.TrimSpace(conf) == "" {
		return errors.New("WireGuard config is empty")
	}
	for i := 0; i < len(conf); i++ {
		b := conf[i]
		if b == 0 || (b < 0x20 && b != '\t' && b != '\r' && b != '\n') || b == 0x7f {
			return errors.New("WireGuard config contains invalid control characters")
		}
	}

	section := ""
	hasKeypairHint := false
	lines := strings.Split(conf, "\n")
	for idx, rawLine := range lines {
		lineNum := idx + 1
		line := strings.TrimSuffix(rawLine, "\r")
		if pos := commentStart(line); pos >= 0 {
			line = line[:pos]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
				return fmt.Errorf("line %d: malformed section header", lineNum)
			}
			sec := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if sec != "interface" && sec != "peer" {
				return fmt.Errorf("line %d: unsupported WireGuard section [%s]", lineNum, line[1:len(line)-1])
			}
			section = sec
			continue
		}
		if section == "" {
			return fmt.Errorf("line %d: setting appears outside [Interface] or [Peer]", lineNum)
		}
		eq := strings.IndexByte(line, '=')
		if eq < 1 {
			return fmt.Errorf("line %d: malformed WireGuard setting", lineNum)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if !wgKeyNameRe.MatchString(key) {
			return fmt.Errorf("line %d: invalid key name %q", lineNum, key)
		}
		if _, forbidden := dangerousWgDirectives[canonicalWgKey(key)]; forbidden {
			return fmt.Errorf("line %d: forbidden WireGuard directive %q is not allowed", lineNum, key)
		}
		if err := ValidateWireGuardScalar(fmt.Sprintf("line %d (%s)", lineNum, key), val); err != nil {
			return err
		}
		ck := canonicalWgKey(key)
		if (section == "interface" && ck == "privatekey") || (section == "peer" && ck == "publickey") {
			if err := ValidateWireGuardKey(key, val); err != nil {
				return fmt.Errorf("line %d: %w", lineNum, err)
			}
			hasKeypairHint = true
		}
		if ck == "presharedkey" && val != "" {
			if err := ValidateWireGuardKey(key, val); err != nil {
				return fmt.Errorf("line %d: %w", lineNum, err)
			}
		}
	}
	if !hasKeypairHint {
		return errors.New("WireGuard config must contain a valid [Interface] PrivateKey or [Peer] PublicKey")
	}
	return nil
}

func commentStart(line string) int {
	for i := 0; i < len(line); i++ {
		if (line[i] == '#' || line[i] == ';') && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return i
		}
	}
	return -1
}

// ParseTrustedProxies parses a comma/whitespace-separated list of trusted reverse proxy
// IPs or CIDRs and normalizes them into canonical CIDR strings for Gin's SetTrustedProxies.
// An empty value returns DefaultTrustedProxies ("127.0.0.1/32", "::1/128").
// Explicit "none"/"off"/"disabled" returns an empty non-nil slice (trust no proxy headers).
func ParseTrustedProxies(raw string) ([]string, error) {
	prefixes, err := ParseTrustedProxyPrefixes(raw)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out, nil
}

// ParseTrustedProxyPrefixes parses trusted proxy IPs/CIDRs into netip.Prefix slices.
func ParseTrustedProxyPrefixes(raw string) ([]netip.Prefix, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		trimmed = DefaultTrustedProxies
	}
	switch strings.ToLower(trimmed) {
	case "none", "off", "disabled", "false":
		return []netip.Prefix{}, nil
	}

	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(parts) == 0 {
		return ParseTrustedProxyPrefixes(DefaultTrustedProxies)
	}

	out := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]bool, len(parts))
	for _, tok := range parts {
		if p, err := netip.ParsePrefix(tok); err == nil {
			norm := p.Masked()
			if !seen[norm] {
				seen[norm] = true
				out = append(out, norm)
			}
			continue
		}
		if addr, err := netip.ParseAddr(tok); err == nil {
			addr = addr.Unmap()
			p := netip.PrefixFrom(addr, addr.BitLen())
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
			continue
		}
		return nil, fmt.Errorf("invalid trusted proxy IP or CIDR: %q", tok)
	}
	return out, nil
}

// IsTrustedProxyPeer reports whether the remote socket address matches any configured trusted prefix.
func IsTrustedProxyPeer(remoteAddr string, trusted []netip.Prefix) bool {
	if len(trusted) == 0 || strings.TrimSpace(remoteAddr) == "" {
		return false
	}
	host := ExtractPeerHost(remoteAddr)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ExtractPeerHost extracts and normalizes the IP or hostname from a RemoteAddr string.
func ExtractPeerHost(remoteAddr string) string {
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

// ResolveClientIP returns the client IP from X-Forwarded-For / X-Real-IP ONLY when
// remoteAddr matches a trusted proxy CIDR; otherwise forwarded headers are ignored
// and the direct normalized peer IP from remoteAddr is returned.
func ResolveClientIP(remoteAddr, xRealIP, xForwardedFor string, trusted []netip.Prefix) string {
	peerIP := ExtractPeerHost(remoteAddr)
	if !IsTrustedProxyPeer(remoteAddr, trusted) {
		return peerIP
	}
	if strings.TrimSpace(xForwardedFor) != "" {
		// Walk right-to-left skipping known trusted proxy hops so a spoofed
		// left-hand X-Forwarded-For value supplied by a client cannot win.
		parts := strings.Split(xForwardedFor, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(parts[i])
			if addr, err := netip.ParseAddr(hop); err == nil {
				addr = addr.Unmap()
				hopStr := addr.String()
				if !IsTrustedProxyPeer(hopStr, trusted) || i == 0 {
					return hopStr
				}
			}
		}
	}
	if candidate := strings.TrimSpace(xRealIP); candidate != "" {
		if addr, err := netip.ParseAddr(candidate); err == nil {
			return addr.Unmap().String()
		}
	}
	return peerIP
}

// ValidateSystemdServiceName enforces a safe strict unit name without path traversal.
func ValidateSystemdServiceName(name string) (string, error) {
	n := strings.TrimSpace(name)
	n = strings.TrimSuffix(n, ".service")
	if n == "" || strings.Contains(n, "..") || strings.ContainsAny(n, `/\`) || !systemdNameRe.MatchString(n) {
		return "", fmt.Errorf("invalid systemd service name %q", name)
	}
	return n, nil
}

// ValidateSystemdUnitText validates a generated/CLI systemd unit so arbitrary
// lifecycle command hooks or unexpected executables cannot be written into systemd units.
func ValidateSystemdUnitText(unitText string, allowedExecPath string) error {
	if strings.TrimSpace(unitText) == "" {
		return errors.New("systemd unit content cannot be empty")
	}
	for i := 0; i < len(unitText); i++ {
		b := unitText[i]
		if b == 0 || (b < 0x20 && b != '\t' && b != '\r' && b != '\n') || b == 0x7f {
			return errors.New("systemd unit contains forbidden control characters")
		}
	}

	seenSections := map[string]bool{}
	var section string
	var execStartCount int
	allowedClean := ""
	if trimmedAllowed := strings.TrimSpace(allowedExecPath); trimmedAllowed != "" {
		allowedClean = cleanExecPath(trimmedAllowed)
	}

	forbiddenServiceKeys := map[string]struct{}{
		"execstartpre":  {},
		"execstartpost": {},
		"execreload":    {},
		"execstop":      {},
		"execstoppost":  {},
		"execcondition": {},
	}

	for idx, raw := range strings.Split(unitText, "\n") {
		lineNum := idx + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
				return fmt.Errorf("line %d: malformed systemd section header", lineNum)
			}
			sec := line[1 : len(line)-1]
			switch sec {
			case "Unit", "Service", "Install":
				section = sec
				seenSections[sec] = true
			default:
				return fmt.Errorf("line %d: unsupported systemd section [%s]", lineNum, sec)
			}
			continue
		}
		if section == "" {
			return fmt.Errorf("line %d: directive outside section", lineNum)
		}
		eq := strings.IndexByte(line, '=')
		if eq < 1 {
			return fmt.Errorf("line %d: malformed systemd directive", lineNum)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if !wgKeyNameRe.MatchString(key) {
			return fmt.Errorf("line %d: invalid directive key %q", lineNum, key)
		}
		lowerKey := strings.ToLower(key)
		if section == "Service" {
			if _, forbidden := forbiddenServiceKeys[lowerKey]; forbidden {
				return fmt.Errorf("line %d: forbidden systemd execution hook %q", lineNum, key)
			}
			if lowerKey == "execstart" {
				execStartCount++
				if strings.ContainsAny(val, "`|&;><") || strings.Contains(val, "$(") {
					return fmt.Errorf("line %d: ExecStart contains forbidden shell metacharacters", lineNum)
				}
				fields := strings.Fields(val)
				if len(fields) == 0 {
					return fmt.Errorf("line %d: ExecStart cannot be empty", lineNum)
				}
				bin := strings.TrimLeft(fields[0], "@-:+!")
				if !strings.HasPrefix(bin, "/") && !filepath.IsAbs(bin) {
					return fmt.Errorf("line %d: ExecStart binary %q must be an absolute path", lineNum, bin)
				}
				if allowedClean != "" && cleanExecPath(bin) != allowedClean {
					return fmt.Errorf("line %d: ExecStart binary %q does not match allowed binary %q", lineNum, bin, allowedClean)
				}
			}
		}
	}

	for _, reqSec := range []string{"Unit", "Service", "Install"} {
		if !seenSections[reqSec] {
			return fmt.Errorf("systemd unit missing [%s] section", reqSec)
		}
	}
	if execStartCount != 1 {
		return fmt.Errorf("systemd unit must contain exactly one ExecStart directive (got %d)", execStartCount)
	}
	return nil
}

func cleanExecPath(p string) string {
	if strings.HasPrefix(p, "/") {
		return path.Clean(p)
	}
	return filepath.Clean(p)
}
