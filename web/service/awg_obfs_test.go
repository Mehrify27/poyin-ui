package service

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/Jipok/wgctrl-go/wgtypes"
)

func TestDetectAWGBackendWithCaps(t *testing.T) {
	awg1 := awgObfs{Jc: 4, Jmin: 8, Jmax: 80, S1: 77, S2: 90, H1: "1001", H2: "1002", H3: "1003", H4: "1004"}
	awg2S3 := awgObfs{Jc: 4, Jmin: 8, Jmax: 80, S1: 77, S2: 90, S3: 16, H1: "1001", H2: "1002", H3: "1003", H4: "1004"}
	awg2S4 := awgObfs{Jc: 4, Jmin: 8, Jmax: 80, S1: 77, S2: 90, S4: 8, H1: "1001", H2: "1002", H3: "1003", H4: "1004"}
	awg2Range := awgObfs{Jc: 4, Jmin: 8, Jmax: 80, S1: 77, S2: 90, H1: "100000-100999", H2: "200000-200999", H3: "300000-300999", H4: "400000-400999"}
	awg2CPS := awgObfs{Jc: 4, Jmin: 8, Jmax: 80, S1: 77, S2: 90, I1: "<b 0x16030100><r 16>"}

	tests := []struct {
		name      string
		requested string
		obfs      awgObfs
		caps      awgCapabilities
		want      string
	}{
		{
			name:      "auto prefers kernel when loaded for AWG 1.0",
			requested: "auto",
			obfs:      awg1,
			caps:      awgCapabilities{KernelAvailable: true, KernelSupportsV2: false, UserspaceAvailable: true},
			want:      AwgBackendKernel,
		},
		{
			name:      "empty uppercase auto falls back to userspace when kernel missing",
			requested: " ",
			obfs:      awgObfs{Backend: "AUTO"},
			caps:      awgCapabilities{KernelAvailable: false, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "auto falls back to userspace on legacy kernel when S3 set",
			requested: "auto",
			obfs:      awg2S3,
			caps:      awgCapabilities{KernelAvailable: true, KernelSupportsV2: false, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "auto falls back to userspace on legacy kernel when S4 set",
			requested: "auto",
			obfs:      awg2S4,
			caps:      awgCapabilities{KernelAvailable: true, KernelSupportsV2: false, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "auto falls back to userspace on legacy kernel when range H1 set",
			requested: "auto",
			obfs:      awg2Range,
			caps:      awgCapabilities{KernelAvailable: true, KernelSupportsV2: false, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "auto falls back to userspace on legacy kernel when I1 CPS set",
			requested: "auto",
			obfs:      awg2CPS,
			caps:      awgCapabilities{KernelAvailable: true, KernelSupportsV2: false, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "auto uses kernel for AWG 2.0 when KernelSupportsV2 is true",
			requested: "auto",
			obfs:      awg2Range,
			caps:      awgCapabilities{KernelAvailable: true, KernelSupportsV2: true, UserspaceAvailable: true},
			want:      AwgBackendKernel,
		},
		{
			name:      "explicit kernel falls back to userspace when kernel absent",
			requested: "kernel",
			obfs:      awg1,
			caps:      awgCapabilities{KernelAvailable: false, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "explicit kernel falls back to userspace on legacy kernel with AWG 2.0",
			requested: "kernel",
			obfs:      awg2CPS,
			caps:      awgCapabilities{KernelAvailable: true, KernelSupportsV2: false, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "explicit userspace aliases select userspace when available",
			requested: "amneziawg-go",
			obfs:      awg1,
			caps:      awgCapabilities{KernelAvailable: true, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "explicit go alias selects userspace when available",
			requested: "go",
			obfs:      awg1,
			caps:      awgCapabilities{KernelAvailable: true, UserspaceAvailable: true},
			want:      AwgBackendUserspace,
		},
		{
			name:      "explicit userspace falls back to kernel if userspace unavailable",
			requested: "userspace",
			obfs:      awg1,
			caps:      awgCapabilities{KernelAvailable: true, UserspaceAvailable: false},
			want:      AwgBackendKernel,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := DetectAWGBackendWithCaps(tc.requested, tc.obfs, tc.caps)
			if got != tc.want {
				t.Fatalf("DetectAWGBackendWithCaps(%q) = %q (%s), want %q", tc.requested, got, reason, tc.want)
			}
			if reason == "" {
				t.Fatalf("expected non-empty selection reason")
			}
		})
	}
}

func TestParseAwgHeaderRangeAndValidateHeaders(t *testing.T) {
	r, err := ParseAwgHeaderRange("123456")
	if err != nil || !r.Set || r.Min != 123456 || r.Max != 123456 {
		t.Fatalf("scalar ParseAwgHeaderRange failed: %+v, err=%v", r, err)
	}
	if !r.Match(123456) || r.Match(123455) || r.Pick() != 123456 {
		t.Fatalf("scalar Match/Pick failed for %+v", r)
	}

	rng, err := ParseAwgHeaderRange("100000 - 200000")
	if err != nil || !rng.Set || rng.Min != 100000 || rng.Max != 200000 {
		t.Fatalf("range ParseAwgHeaderRange failed: %+v, err=%v", rng, err)
	}
	for i := 0; i < 32; i++ {
		v := rng.Pick()
		if !rng.Match(v) {
			t.Fatalf("Pick() returned out-of-range value %d for [%d,%d]", v, rng.Min, rng.Max)
		}
	}
	if rng.Match(99999) || rng.Match(200001) {
		t.Fatalf("Match() accepted out-of-bounds values")
	}

	singleRng, err := ParseAwgHeaderRange("42-42")
	if err != nil || singleRng.Pick() != 42 || !singleRng.Match(42) {
		t.Fatalf("single-value range failed: %+v, err=%v", singleRng, err)
	}

	if err := ValidateAwgHeaders("", "", "", ""); err != nil {
		t.Fatalf("empty headers should be valid, got: %v", err)
	}
	if err := ValidateAwgHeaders("100-199", "200", "300-399", "400-500"); err != nil {
		t.Fatalf("non-overlapping headers should be valid, got: %v", err)
	}

	invalidHeaders := []struct {
		name           string
		h1, h2, h3, h4 string
	}{
		{"overlapping ranges at boundary", "100-200", "200-300", "301-400", "401-500"},
		{"scalar inside range", "100-200", "150", "300", "400"},
		{"duplicate scalars", "555", "666", "555", "888"},
		{"zero scalar", "0", "2", "3", "4"},
		{"zero range start", "0-10", "20-30", "40-50", "60-70"},
		{"inverted range", "200-100", "300", "400", "500"},
		{"extra dash", "1-2-3", "4", "5", "6"},
		{"non-numeric", "abc", "2", "3", "4"},
	}
	for _, tc := range invalidHeaders {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateAwgHeaders(tc.h1, tc.h2, tc.h3, tc.h4); err == nil {
				t.Fatalf("expected error for (%q,%q,%q,%q), got nil", tc.h1, tc.h2, tc.h3, tc.h4)
			}
		})
	}
}

func TestValidateAndRenderAwgCPSSpec(t *testing.T) {
	spec := "<b 0x16030100> <c> <t> <r 8> <rc 10> <rd 6>"
	if err := ValidateAwgCPSSpec("i1", spec); err != nil {
		t.Fatalf("ValidateAwgCPSSpec(%q) failed: %v", spec, err)
	}

	pkt, err := parseAwgCPSPacket(spec)
	if err != nil {
		t.Fatalf("parseAwgCPSPacket failed: %v", err)
	}
	now := time.Unix(1700000123, 0)
	rendered := pkt.Render(0x01020304, now)
	wantLen := 4 + 4 + 4 + 8 + 10 + 6
	if len(rendered) != wantLen {
		t.Fatalf("rendered length = %d, want %d", len(rendered), wantLen)
	}
	if !bytes.Equal(rendered[0:4], []byte{0x16, 0x03, 0x01, 0x00}) {
		t.Fatalf("unexpected static prefix bytes: %x", rendered[0:4])
	}
	if got := binary.BigEndian.Uint32(rendered[4:8]); got != 0x01020304 {
		t.Fatalf("counter = 0x%08x, want 0x01020304", got)
	}
	if got := binary.BigEndian.Uint32(rendered[8:12]); got != uint32(now.Unix()) {
		t.Fatalf("timestamp = %d, want %d", got, uint32(now.Unix()))
	}
	rcSlice := rendered[20:30]
	for i, c := range rcSlice {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			t.Fatalf("<rc 10> byte %d = %q is not ASCII alphanumeric", i, c)
		}
	}
	rdSlice := rendered[30:36]
	for i, c := range rdSlice {
		if c < '0' || c > '9' {
			t.Fatalf("<rd 6> byte %d = %q is not an ASCII digit", i, c)
		}
	}

	badSpecs := []struct {
		name string
		spec string
	}{
		{"text outside tags", "hello<c>"},
		{"odd hex digits", "<b 0xabc>"},
		{"non hex chars", "<b 0xzzzz>"},
		{"missing 0x prefix", "<b 1234>"},
		{"zero length random", "<r 0>"},
		{"negative length random", "<rc -1>"},
		{"unknown tag", "<foo 4>"},
		{"unterminated tag", "<b 0x00"},
	}
	for _, tc := range badSpecs {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateAwgCPSSpec("i1", tc.spec); err == nil {
				t.Fatalf("expected error for %q, got nil", tc.spec)
			}
		})
	}
}

func TestAwgWireCodecRoundTrip(t *testing.T) {
	obfs := awgObfs{
		Backend: AwgBackendUserspace,
		Jc:      3,
		Jmin:    16,
		Jmax:    32,
		S1:      7,
		S2:      11,
		S3:      5,
		S4:      9,
		H1:      "100000-100099",
		H2:      "200000-200099",
		H3:      "300000-300099",
		H4:      "400000-400099",
		I1:      "<b 0xdeadbeef><c>",
	}
	codec, err := newAwgWireCodec(obfs)
	if err != nil {
		t.Fatalf("newAwgWireCodec failed: %v", err)
	}

	preamble := codec.BuildHandshakePreamble(time.Unix(1700000000, 0))
	if len(preamble) != 4 {
		t.Fatalf("BuildHandshakePreamble returned %d packets, want 4 (1 CPS + 3 junk)", len(preamble))
	}
	if !bytes.HasPrefix(preamble[0], []byte{0xde, 0xad, 0xbe, 0xef}) || len(preamble[0]) != 8 {
		t.Fatalf("unexpected CPS preamble packet: %x", preamble[0])
	}
	for i := 1; i < len(preamble); i++ {
		if len(preamble[i]) < obfs.Jmin || len(preamble[i]) > obfs.Jmax {
			t.Fatalf("junk packet %d len=%d outside [%d,%d]", i, len(preamble[i]), obfs.Jmin, obfs.Jmax)
		}
	}

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	mac1Key := ComputeWireGuardMAC1Key(priv.PublicKey())
	lookup := func([]byte) ([32]byte, bool) { return mac1Key, true }

	makeInner := func(msgType uint32, size int, macOffset int) []byte {
		pkt := make([]byte, size)
		binary.LittleEndian.PutUint32(pkt[:4], msgType)
		for i := 4; i < len(pkt); i++ {
			pkt[i] = byte(i ^ int(msgType))
		}
		if macOffset > 0 {
			mac := computeWireGuardMAC1(mac1Key, pkt[:macOffset])
			copy(pkt[macOffset:macOffset+16], mac[:])
		}
		return pkt
	}

	cases := []struct {
		name      string
		inner     []byte
		prefixLen int
		hRange    awgHeaderRange
		macOffset int
	}{
		{"type1 initiation", makeInner(1, awgMsgInitiationSize, 116), obfs.S1, codec.h1, 116},
		{"type2 response", makeInner(2, awgMsgResponseSize, 60), obfs.S2, codec.h2, 60},
		{"type3 cookie", makeInner(3, awgMsgCookieReplySize, -1), obfs.S3, codec.h3, -1},
		{"type4 transport", makeInner(4, 80, -1), obfs.S4, codec.h4, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := codec.EncodeOutgoing(tc.inner, lookup)
			if len(wire) != tc.prefixLen+len(tc.inner) {
				t.Fatalf("wire length = %d, want %d", len(wire), tc.prefixLen+len(tc.inner))
			}
			wireHdr := binary.LittleEndian.Uint32(wire[tc.prefixLen : tc.prefixLen+4])
			if !tc.hRange.Match(wireHdr) {
				t.Fatalf("wire header %d outside range [%d,%d]", wireHdr, tc.hRange.Min, tc.hRange.Max)
			}
			if tc.macOffset > 0 {
				wantWireMAC := computeWireGuardMAC1(mac1Key, wire[tc.prefixLen:tc.prefixLen+tc.macOffset])
				gotWireMAC := wire[tc.prefixLen+tc.macOffset : tc.prefixLen+tc.macOffset+16]
				if !bytes.Equal(gotWireMAC, wantWireMAC[:]) {
					t.Fatalf("encoded wire MAC1 mismatch")
				}
			}
			decoded, ok := codec.DecodeIncoming(wire, mac1Key, true)
			if !ok {
				t.Fatalf("DecodeIncoming rejected valid packet")
			}
			if !bytes.Equal(decoded, tc.inner) {
				t.Fatalf("decoded packet mismatch against original canonical WireGuard packet")
			}
		})
	}

	// Junk and tampered headers must be discarded cleanly.
	if _, ok := codec.DecodeIncoming([]byte{1, 2, 3, 4}, mac1Key, true); ok {
		t.Fatalf("DecodeIncoming accepted short junk packet")
	}
	badHdr := make([]byte, obfs.S1+awgMsgInitiationSize)
	binary.LittleEndian.PutUint32(badHdr[obfs.S1:obfs.S1+4], 999999)
	if _, ok := codec.DecodeIncoming(badHdr, mac1Key, true); ok {
		t.Fatalf("DecodeIncoming accepted packet with out-of-range header")
	}
}
