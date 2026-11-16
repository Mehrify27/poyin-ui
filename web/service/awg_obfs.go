package service

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Jipok/wgctrl-go/wgtypes"
	"golang.org/x/crypto/blake2s"
)

const (
	AwgBackendAuto      = "auto"
	AwgBackendKernel    = "kernel"
	AwgBackendUserspace = "userspace"

	awgWGLabelMAC1 = "mac1----"

	awgMsgInitiationSize  = 148
	awgMsgResponseSize    = 92
	awgMsgCookieReplySize = 64
	awgMsgTransportMin    = 32
	awgMaxMessageSize     = 65535
)

// awgObfs captures all AWG 1.0 + 1.5 + 2.0 obfuscation settings for an interface.
type awgObfs struct {
	Backend            string
	Jc, Jmin, Jmax     int
	S1, S2, S3, S4     int
	H1, H2, H3, H4     string
	I1, I2, I3, I4, I5 string
}

// NormalizeAWGBackend maps UI/config backend values to one of "", "auto",
// "kernel", or "userspace" while preserving unknown strings for validation.
func NormalizeAWGBackend(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", AwgBackendAuto:
		return AwgBackendAuto
	case AwgBackendKernel:
		return AwgBackendKernel
	case AwgBackendUserspace, "amneziawg-go", "go":
		return AwgBackendUserspace
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func (b awgObfs) Normalized() awgObfs {
	b.Backend = NormalizeAWGBackend(b.Backend)
	b.H1 = strings.TrimSpace(b.H1)
	b.H2 = strings.TrimSpace(b.H2)
	b.H3 = strings.TrimSpace(b.H3)
	b.H4 = strings.TrimSpace(b.H4)
	b.I1 = strings.TrimSpace(b.I1)
	b.I2 = strings.TrimSpace(b.I2)
	b.I3 = strings.TrimSpace(b.I3)
	b.I4 = strings.TrimSpace(b.I4)
	b.I5 = strings.TrimSpace(b.I5)
	return b
}

// HasRanges reports whether any magic header uses the AWG 2.0 "min-max" range syntax.
func (b awgObfs) HasRanges() bool {
	for _, h := range []string{b.H1, b.H2, b.H3, b.H4} {
		if strings.Contains(strings.TrimSpace(h), "-") {
			return true
		}
	}
	return false
}

// HasCPS reports whether any Custom Protocol Signature (I1-I5) packet is configured.
func (b awgObfs) HasCPS() bool {
	for _, spec := range []string{b.I1, b.I2, b.I3, b.I4, b.I5} {
		if strings.TrimSpace(spec) != "" {
			return true
		}
	}
	return false
}

// RequiresAWG2 reports whether any AWG 1.5 / 2.0 feature is active.
func (b awgObfs) RequiresAWG2() bool {
	return b.S3 > 0 || b.S4 > 0 || b.HasRanges() || b.HasCPS()
}

func (b awgObfs) sig() string {
	n := b.Normalized()
	return fmt.Sprintf("%s|%d|%d|%d|%d|%d|%d|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		n.Backend, n.Jc, n.Jmin, n.Jmax, n.S1, n.S2, n.S3, n.S4,
		n.H1, n.H2, n.H3, n.H4, n.I1, n.I2, n.I3, n.I4, n.I5)
}

func (b awgObfs) apply(cfg *wgtypes.Config) {
	b.applyInternal(cfg, false)
}

func (b awgObfs) applyFull(cfg *wgtypes.Config) {
	b.applyInternal(cfg, true)
}

func (b awgObfs) applyInternal(cfg *wgtypes.Config, includeZeroV2 bool) {
	jc, jmin, jmax, s1, s2 := b.Jc, b.Jmin, b.Jmax, b.S1, b.S2
	cfg.Jc, cfg.Jmin, cfg.Jmax = &jc, &jmin, &jmax
	cfg.S1, cfg.S2 = &s1, &s2

	if includeZeroV2 || b.S3 > 0 {
		s3 := b.S3
		cfg.S3 = &s3
	}
	if includeZeroV2 || b.S4 > 0 {
		s4 := b.S4
		cfg.S4 = &s4
	}

	if h1 := strings.TrimSpace(b.H1); h1 != "" {
		cfg.H1 = &h1
	}
	if h2 := strings.TrimSpace(b.H2); h2 != "" {
		cfg.H2 = &h2
	}
	if h3 := strings.TrimSpace(b.H3); h3 != "" {
		cfg.H3 = &h3
	}
	if h4 := strings.TrimSpace(b.H4); h4 != "" {
		cfg.H4 = &h4
	}

	i1 := strings.TrimSpace(b.I1)
	if includeZeroV2 || i1 != "" {
		cfg.I1 = &i1
	}
	i2 := strings.TrimSpace(b.I2)
	if includeZeroV2 || i2 != "" {
		cfg.I2 = &i2
	}
	i3 := strings.TrimSpace(b.I3)
	if includeZeroV2 || i3 != "" {
		cfg.I3 = &i3
	}
	i4 := strings.TrimSpace(b.I4)
	if includeZeroV2 || i4 != "" {
		cfg.I4 = &i4
	}
	i5 := strings.TrimSpace(b.I5)
	if includeZeroV2 || i5 != "" {
		cfg.I5 = &i5
	}
}

type awgCapabilities struct {
	KernelAvailable    bool
	KernelSupportsV2   bool
	UserspaceAvailable bool
}

func currentAwgCapabilities() awgCapabilities {
	kAvail := awgKernelModuleLoaded()
	return awgCapabilities{
		KernelAvailable:    kAvail,
		KernelSupportsV2:   kAvail && !awgKernelModuleIsLegacyV1(),
		UserspaceAvailable: awgUserspaceAvailable(),
	}
}

// DetectAWGBackend picks "kernel" or "userspace" for an interface based on requested
// preference, active AWG 1.5/2.0 features, and live host capabilities.
func DetectAWGBackend(requested string, obfs awgObfs) (string, string) {
	return DetectAWGBackendWithCaps(requested, obfs, currentAwgCapabilities())
}

// DetectAWGBackendWithCaps is the pure decision function behind DetectAWGBackend.
func DetectAWGBackendWithCaps(requested string, obfs awgObfs, caps awgCapabilities) (string, string) {
	req := NormalizeAWGBackend(requested)
	if req == "" || req == AwgBackendAuto {
		req = NormalizeAWGBackend(obfs.Backend)
	}

	switch req {
	case AwgBackendUserspace:
		if caps.UserspaceAvailable {
			return AwgBackendUserspace, "selected userspace amneziawg-go backend"
		}
		if caps.KernelAvailable && (!obfs.RequiresAWG2() || caps.KernelSupportsV2) {
			return AwgBackendKernel, "userspace backend unavailable; using kernel module"
		}
		return AwgBackendUserspace, "userspace backend requested (unavailable)"

	case AwgBackendKernel:
		if caps.KernelAvailable {
			if obfs.RequiresAWG2() && !caps.KernelSupportsV2 && caps.UserspaceAvailable {
				return AwgBackendUserspace, "loaded kernel module lacks AWG 1.5/2.0 support; falling back to userspace amneziawg-go"
			}
			return AwgBackendKernel, "selected kernel amneziawg backend"
		}
		if caps.UserspaceAvailable {
			return AwgBackendUserspace, "kernel module not loaded; falling back to userspace amneziawg-go"
		}
		return AwgBackendKernel, "kernel module unavailable"

	default: // AwgBackendAuto or any unrecognized value treated as auto
		if caps.KernelAvailable {
			if obfs.RequiresAWG2() && !caps.KernelSupportsV2 && caps.UserspaceAvailable {
				return AwgBackendUserspace, "AWG 1.5/2.0 features require userspace amneziawg-go (legacy kernel module loaded)"
			}
			return AwgBackendKernel, "kernel amneziawg module available"
		}
		if caps.UserspaceAvailable {
			return AwgBackendUserspace, "kernel module not available; using userspace amneziawg-go"
		}
		return AwgBackendKernel, "no AmneziaWG backend available"
	}
}

// awgHeaderRange represents either a single scalar magic header or an inclusive
// "min-max" range per AWG 2.0.
type awgHeaderRange struct {
	Min uint32
	Max uint32
	Set bool
}

// ParseAwgHeaderRange parses either "<uint32>" or "<min>-<max>".
func ParseAwgHeaderRange(spec string) (awgHeaderRange, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return awgHeaderRange{}, nil
	}
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return awgHeaderRange{}, fmt.Errorf("expected <min>-<max>, got %q", spec)
		}
		lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		if err != nil {
			return awgHeaderRange{}, fmt.Errorf("invalid range start in %q: %w", spec, err)
		}
		hi, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return awgHeaderRange{}, fmt.Errorf("invalid range end in %q: %w", spec, err)
		}
		if lo > hi {
			return awgHeaderRange{}, fmt.Errorf("range start (%d) exceeds end (%d) in %q", lo, hi, spec)
		}
		if lo == 0 {
			return awgHeaderRange{}, fmt.Errorf("magic header value must be non-zero in %q", spec)
		}
		return awgHeaderRange{Min: uint32(lo), Max: uint32(hi), Set: true}, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return awgHeaderRange{}, fmt.Errorf("invalid integer %q: %w", spec, err)
	}
	if v == 0 {
		return awgHeaderRange{}, fmt.Errorf("magic header value must be non-zero")
	}
	return awgHeaderRange{Min: uint32(v), Max: uint32(v), Set: true}, nil
}

// Pick returns a cryptographically random value within [Min, Max].
func (r awgHeaderRange) Pick() uint32 {
	if r.Min >= r.Max {
		return r.Min
	}
	span := uint64(r.Max-r.Min) + 1
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(span))
	if err != nil {
		return r.Min
	}
	return r.Min + uint32(n.Uint64())
}

// Match reports whether v lies within [Min, Max].
func (r awgHeaderRange) Match(v uint32) bool {
	return v >= r.Min && v <= r.Max
}

func (r awgHeaderRange) overlaps(o awgHeaderRange) bool {
	return r.Set && o.Set && !(o.Max < r.Min || r.Max < o.Min)
}

// ValidateAwgHeaders checks syntax and non-overlap for non-empty H1..H4 values.
func ValidateAwgHeaders(h1, h2, h3, h4 string) error {
	names := []string{"h1", "h2", "h3", "h4"}
	raw := []string{h1, h2, h3, h4}
	parsed := make([]awgHeaderRange, 4)
	setCount := 0
	for i, spec := range raw {
		r, err := ParseAwgHeaderRange(spec)
		if err != nil {
			return fmt.Errorf("%s: %w", names[i], err)
		}
		parsed[i] = r
		if r.Set {
			setCount++
		}
	}
	if setCount == 0 {
		return nil
	}
	for i := 0; i < 4; i++ {
		if !parsed[i].Set {
			continue
		}
		for j := i + 1; j < 4; j++ {
			if parsed[i].overlaps(parsed[j]) {
				return fmt.Errorf("%s (%q) and %s (%q) must not overlap", names[i], strings.TrimSpace(raw[i]), names[j], strings.TrimSpace(raw[j]))
			}
		}
	}
	return nil
}

type awgCPSTagKind int

const (
	cpsTagBytes awgCPSTagKind = iota
	cpsTagCounter
	cpsTagTimestamp
	cpsTagRandomBytes
	cpsTagRandomASCII
	cpsTagRandomDigits
)

type awgCPSTag struct {
	kind   awgCPSTagKind
	data   []byte
	length int
}

type awgCPSPacket struct {
	raw       string
	totalSize int
	tags      []awgCPSTag
}

// ValidateAwgCPSSpec validates an AmneziaWG 1.5/2.0 CPS packet string (I1-I5).
func ValidateAwgCPSSpec(field, spec string) error {
	_, err := parseAwgCPSPacket(spec)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func parseAwgCPSPacket(spec string) (*awgCPSPacket, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, nil
	}
	var tags []awgCPSTag
	total := 0
	s := trimmed
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t\r\n")
		if len(s) == 0 {
			break
		}
		if s[0] != '<' {
			return nil, fmt.Errorf("unexpected text outside <...> tag near %q", s)
		}
		end := strings.IndexByte(s, '>')
		if end <= 1 {
			return nil, fmt.Errorf("unterminated or empty <...> tag in %q", trimmed)
		}
		inner := strings.TrimSpace(s[1:end])
		s = s[end+1:]

		key, val, hasVal := strings.Cut(inner, " ")
		val = strings.TrimSpace(val)

		switch key {
		case "b":
			if !hasVal || (!strings.HasPrefix(val, "0x") && !strings.HasPrefix(val, "0X")) {
				return nil, fmt.Errorf("<b ...> requires 0x-prefixed hex data")
			}
			hexPart := val[2:]
			if len(hexPart) == 0 || len(hexPart)%2 != 0 {
				return nil, fmt.Errorf("<b %s> must contain an even, non-empty number of hex digits", val)
			}
			raw, err := hex.DecodeString(hexPart)
			if err != nil {
				return nil, fmt.Errorf("<b %s>: invalid hex: %w", val, err)
			}
			total += len(raw)
			tags = append(tags, awgCPSTag{kind: cpsTagBytes, data: raw, length: len(raw)})

		case "c":
			if val != "" {
				return nil, fmt.Errorf("<c> takes no arguments")
			}
			total += 4
			tags = append(tags, awgCPSTag{kind: cpsTagCounter, length: 4})

		case "t":
			if val != "" {
				return nil, fmt.Errorf("<t> takes no arguments")
			}
			total += 4
			tags = append(tags, awgCPSTag{kind: cpsTagTimestamp, length: 4})

		case "r", "rc", "rd":
			if !hasVal || val == "" {
				return nil, fmt.Errorf("<%s N> requires a positive length", key)
			}
			n, err := strconv.Atoi(val)
			if err != nil || n <= 0 || n > awgMaxMessageSize {
				return nil, fmt.Errorf("<%s %s>: length must be between 1 and %d", key, val, awgMaxMessageSize)
			}
			kind := cpsTagRandomBytes
			if key == "rc" {
				kind = cpsTagRandomASCII
			} else if key == "rd" {
				kind = cpsTagRandomDigits
			}
			total += n
			tags = append(tags, awgCPSTag{kind: kind, length: n})

		default:
			return nil, fmt.Errorf("unknown CPS tag <%s>", key)
		}

		if total > awgMaxMessageSize {
			return nil, fmt.Errorf("total packet size %d exceeds %d", total, awgMaxMessageSize)
		}
	}
	if len(tags) == 0 {
		return nil, errors.New("empty CPS packet specification")
	}
	return &awgCPSPacket{raw: trimmed, totalSize: total, tags: tags}, nil
}

const (
	cpsASCIIChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	cpsDigitChars = "0123456789"
)

func (p *awgCPSPacket) Render(counter uint32, now time.Time) []byte {
	if p == nil || p.totalSize == 0 {
		return nil
	}
	out := make([]byte, p.totalSize)
	pos := 0
	for _, tag := range p.tags {
		dst := out[pos : pos+tag.length]
		switch tag.kind {
		case cpsTagBytes:
			copy(dst, tag.data)
		case cpsTagCounter:
			binary.BigEndian.PutUint32(dst, counter)
		case cpsTagTimestamp:
			binary.BigEndian.PutUint32(dst, uint32(now.Unix()))
		case cpsTagRandomBytes:
			_, _ = rand.Read(dst)
		case cpsTagRandomASCII:
			fillRandomAlphabet(dst, cpsASCIIChars)
		case cpsTagRandomDigits:
			fillRandomAlphabet(dst, cpsDigitChars)
		}
		pos += tag.length
	}
	return out
}

func fillRandomAlphabet(dst []byte, alphabet string) {
	if len(dst) == 0 {
		return
	}
	_, _ = rand.Read(dst)
	n := len(alphabet)
	for i, b := range dst {
		dst[i] = alphabet[int(b)%n]
	}
}

// ComputeWireGuardMAC1Key derives BLAKE2s-256("mac1----" || pubkey) used by
// WireGuard and AmneziaWG handshake mac1 tags.
func ComputeWireGuardMAC1Key(pub wgtypes.Key) [32]byte {
	var key [32]byte
	h, _ := blake2s.New256(nil)
	h.Write([]byte(awgWGLabelMAC1))
	h.Write(pub[:])
	h.Sum(key[:0])
	return key
}

func computeWireGuardMAC1(key [32]byte, msgWithoutMacs []byte) [16]byte {
	var mac [16]byte
	h, _ := blake2s.New128(key[:])
	h.Write(msgWithoutMacs)
	h.Sum(mac[:0])
	return mac
}

// awgWireCodec transforms WireGuard packets to/from AmneziaWG 1.0/1.5/2.0 wire
// framing (junk/CPS preambles, S1-S4 random prefixes, H1-H4 headers, and MAC1
// updates).
type awgWireCodec struct {
	obfs   awgObfs
	h1     awgHeaderRange
	h2     awgHeaderRange
	h3     awgHeaderRange
	h4     awgHeaderRange
	cps    []*awgCPSPacket
	ctr    atomic.Uint32
}

func newAwgWireCodec(obfs awgObfs) (*awgWireCodec, error) {
	obfs = obfs.Normalized()
	h1 := awgHeaderRange{Min: 1, Max: 1, Set: true}
	h2 := awgHeaderRange{Min: 2, Max: 2, Set: true}
	h3 := awgHeaderRange{Min: 3, Max: 3, Set: true}
	h4 := awgHeaderRange{Min: 4, Max: 4, Set: true}

	if obfs.H1 != "" || obfs.H2 != "" || obfs.H3 != "" || obfs.H4 != "" {
		if err := ValidateAwgHeaders(obfs.H1, obfs.H2, obfs.H3, obfs.H4); err != nil {
			return nil, err
		}
		if obfs.H1 != "" {
			r, err := ParseAwgHeaderRange(obfs.H1)
			if err != nil {
				return nil, err
			}
			h1 = r
		}
		if obfs.H2 != "" {
			r, err := ParseAwgHeaderRange(obfs.H2)
			if err != nil {
				return nil, err
			}
			h2 = r
		}
		if obfs.H3 != "" {
			r, err := ParseAwgHeaderRange(obfs.H3)
			if err != nil {
				return nil, err
			}
			h3 = r
		}
		if obfs.H4 != "" {
			r, err := ParseAwgHeaderRange(obfs.H4)
			if err != nil {
				return nil, err
			}
			h4 = r
		}
	}

	var cpsList []*awgCPSPacket
	for _, spec := range []string{obfs.I1, obfs.I2, obfs.I3, obfs.I4, obfs.I5} {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		pkt, err := parseAwgCPSPacket(spec)
		if err != nil {
			return nil, err
		}
		if pkt != nil {
			cpsList = append(cpsList, pkt)
		}
	}

	return &awgWireCodec{
		obfs: obfs,
		h1:   h1,
		h2:   h2,
		h3:   h3,
		h4:   h4,
		cps:  cpsList,
	}, nil
}

// BuildHandshakePreamble generates CPS signature packets (I1-I5) followed by Jc
// random junk packets of sizes drawn from [Jmin, Jmax].
func (c *awgWireCodec) BuildHandshakePreamble(now time.Time) [][]byte {
	var out [][]byte
	for _, spec := range c.cps {
		ctr := c.ctr.Add(1)
		if raw := spec.Render(ctr, now); len(raw) > 0 {
			out = append(out, raw)
		}
	}
	for i := 0; i < c.obfs.Jc; i++ {
		sz := c.pickJunkSize()
		if sz <= 0 {
			continue
		}
		buf := make([]byte, sz)
		_, _ = rand.Read(buf)
		out = append(out, buf)
	}
	return out
}

func (c *awgWireCodec) pickJunkSize() int {
	lo, hi := c.obfs.Jmin, c.obfs.Jmax
	if hi <= 0 {
		return 0
	}
	if lo < 0 {
		lo = 0
	}
	if hi <= lo {
		return lo
	}
	span := uint64(hi - lo + 1)
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(span))
	if err != nil {
		return lo
	}
	return lo + int(n.Uint64())
}

// EncodeOutgoing transforms a standard WireGuard packet into an obfuscated AWG
// wire packet. lookupMAC1Key receives the un-obfuscated packet so callers can
// identify the recipient peer even across endpoint NAT/roaming.
func (c *awgWireCodec) EncodeOutgoing(
	pkt []byte,
	lookupMAC1Key func(inner []byte) ([32]byte, bool),
) []byte {
	if len(pkt) < 4 {
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		return cp
	}
	msgType := binary.LittleEndian.Uint32(pkt[:4])
	var prefixLen int
	var hdr uint32
	mac1Offset := -1

	switch msgType {
	case 1:
		prefixLen = c.obfs.S1
		hdr = c.h1.Pick()
		if len(pkt) == awgMsgInitiationSize {
			mac1Offset = 116
		}
	case 2:
		prefixLen = c.obfs.S2
		hdr = c.h2.Pick()
		if len(pkt) == awgMsgResponseSize {
			mac1Offset = 60
		}
	case 3:
		prefixLen = c.obfs.S3
		hdr = c.h3.Pick()
	case 4:
		prefixLen = c.obfs.S4
		hdr = c.h4.Pick()
	default:
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		return cp
	}

	if prefixLen < 0 {
		prefixLen = 0
	}
	out := make([]byte, prefixLen+len(pkt))
	if prefixLen > 0 {
		_, _ = rand.Read(out[:prefixLen])
	}
	body := out[prefixLen:]
	copy(body, pkt)
	binary.LittleEndian.PutUint32(body[:4], hdr)

	if mac1Offset > 0 && lookupMAC1Key != nil {
		if key, ok := lookupMAC1Key(pkt); ok {
			mac := computeWireGuardMAC1(key, body[:mac1Offset])
			copy(body[mac1Offset:mac1Offset+16], mac[:])
		}
	}
	return out
}

// DecodeIncoming unwraps an incoming AmneziaWG wire datagram back into a standard
// WireGuard packet. Returns (nil, false) for junk or unrecognized datagrams.
func (c *awgWireCodec) DecodeIncoming(pkt []byte, localMAC1Key [32]byte, haveLocalKey bool) ([]byte, bool) {
	if c.obfs.S1 >= 0 && len(pkt) == c.obfs.S1+awgMsgInitiationSize {
		hdr := binary.LittleEndian.Uint32(pkt[c.obfs.S1 : c.obfs.S1+4])
		if c.h1.Match(hdr) {
			return unwrapHandshakeMsg(pkt[c.obfs.S1:], 1, 116, localMAC1Key, haveLocalKey), true
		}
	}
	if c.obfs.S2 >= 0 && len(pkt) == c.obfs.S2+awgMsgResponseSize {
		hdr := binary.LittleEndian.Uint32(pkt[c.obfs.S2 : c.obfs.S2+4])
		if c.h2.Match(hdr) {
			return unwrapHandshakeMsg(pkt[c.obfs.S2:], 2, 60, localMAC1Key, haveLocalKey), true
		}
	}
	if c.obfs.S3 >= 0 && len(pkt) == c.obfs.S3+awgMsgCookieReplySize {
		hdr := binary.LittleEndian.Uint32(pkt[c.obfs.S3 : c.obfs.S3+4])
		if c.h3.Match(hdr) {
			out := make([]byte, len(pkt)-c.obfs.S3)
			copy(out, pkt[c.obfs.S3:])
			binary.LittleEndian.PutUint32(out[:4], 3)
			return out, true
		}
	}
	if c.obfs.S4 >= 0 && len(pkt) >= c.obfs.S4+awgMsgTransportMin {
		hdr := binary.LittleEndian.Uint32(pkt[c.obfs.S4 : c.obfs.S4+4])
		if c.h4.Match(hdr) {
			out := make([]byte, len(pkt)-c.obfs.S4)
			copy(out, pkt[c.obfs.S4:])
			binary.LittleEndian.PutUint32(out[:4], 4)
			return out, true
		}
	}
	return nil, false
}

func unwrapHandshakeMsg(raw []byte, wgType uint32, mac1Offset int, localMAC1Key [32]byte, haveLocalKey bool) []byte {
	out := make([]byte, len(raw))
	copy(out, raw)
	// Verify MAC1 against the wire header before rewriting the header type back
	// to the canonical WireGuard value. Only if MAC1 validates under the wire
	// framing do we recompute MAC1 for wireguard-go's CookieChecker; otherwise
	// leave MAC1 un-repaired so wireguard-go drops unauthenticated packets.
	wireMacOK := false
	if haveLocalKey {
		expected := computeWireGuardMAC1(localMAC1Key, raw[:mac1Offset])
		wireMacOK = hmac.Equal(expected[:], raw[mac1Offset:mac1Offset+16])
	}
	binary.LittleEndian.PutUint32(out[:4], wgType)
	if wireMacOK {
		repaired := computeWireGuardMAC1(localMAC1Key, out[:mac1Offset])
		copy(out[mac1Offset:mac1Offset+16], repaired[:])
	}
	return out
}
