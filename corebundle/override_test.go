package corebundle

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/binutil"
)

func makeTestELFForArch(t *testing.T, goarch string) []byte {
	t.Helper()
	var (
		class   byte = 2 // ELFCLASS64
		machine uint16
	)
	switch goarch {
	case "amd64":
		machine = 62
	case "arm64":
		machine = 183
	case "386":
		class = 1
		machine = 3
	case "arm":
		class = 1
		machine = 40
	default:
		t.Skipf("unsupported test GOARCH %q", goarch)
	}

	buf := make([]byte, 64)
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = class
	buf[5] = 1
	buf[6] = 1
	binary.LittleEndian.PutUint16(buf[16:18], 2)
	binary.LittleEndian.PutUint16(buf[18:20], machine)
	binary.LittleEndian.PutUint32(buf[20:24], 1)
	if class == 2 {
		binary.LittleEndian.PutUint16(buf[52:54], 64)
	} else {
		binary.LittleEndian.PutUint16(buf[40:42], 52)
	}
	return buf
}

func TestResolveXrayBinaryPathOverrideAndFallback(t *testing.T) {
	bundledDir := t.TempDir()
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)

	bundledBin := filepath.Join(bundledDir, XrayBinaryName())
	if err := os.WriteFile(bundledBin, makeTestELFForArch(t, runtime.GOARCH), 0o755); err != nil {
		t.Fatalf("seed bundled xray: %v", err)
	}

	// No override yet -> resolves to bundled path.
	if got := ResolveXrayBinaryPath(bundledDir); got != bundledBin {
		t.Fatalf("without override: got %q, want bundled %q", got, bundledBin)
	}

	// Valid custom override takes precedence over bundled binary.
	customBin := filepath.Join(customDir, XrayBinaryName())
	if err := os.WriteFile(customBin, makeTestELFForArch(t, runtime.GOARCH), 0o755); err != nil {
		t.Fatalf("seed custom xray: %v", err)
	}
	if got := ResolveXrayBinaryPath(bundledDir); got != customBin {
		t.Fatalf("with valid override: got %q, want custom %q", got, customBin)
	}

	// Corrupt custom override falls back safely to bundled binary.
	if err := os.WriteFile(customBin, []byte("corrupt-payload"), 0o755); err != nil {
		t.Fatalf("corrupt custom xray: %v", err)
	}
	if got := ResolveXrayBinaryPath(bundledDir); got != bundledBin {
		t.Fatalf("with corrupt override: got %q, want fallback bundled %q", got, bundledBin)
	}

	// Wrong architecture custom override falls back safely to bundled binary.
	wrongArch := "arm64"
	if runtime.GOARCH == "arm64" {
		wrongArch = "amd64"
	}
	if err := os.WriteFile(customBin, makeTestELFForArch(t, wrongArch), 0o755); err != nil {
		t.Fatalf("write wrong-arch custom xray: %v", err)
	}
	if got := ResolveXrayBinaryPath(bundledDir); got != bundledBin {
		t.Fatalf("with wrong-arch override: got %q, want fallback bundled %q", got, bundledBin)
	}
}
