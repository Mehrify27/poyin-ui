package backend

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
		machine = 62 // EM_X86_64
	case "arm64":
		machine = 183 // EM_AARCH64
	case "386":
		class = 1 // ELFCLASS32
		machine = 3
	case "arm":
		class = 1 // ELFCLASS32
		machine = 40
	default:
		t.Skipf("unsupported test GOARCH %q", goarch)
	}

	buf := make([]byte, 64)
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = class
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(buf[16:18], 2) // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:20], machine)
	binary.LittleEndian.PutUint32(buf[20:24], 1) // EV_CURRENT
	if class == 2 {
		binary.LittleEndian.PutUint16(buf[52:54], 64)
	} else {
		binary.LittleEndian.PutUint16(buf[40:42], 52)
	}
	return buf
}

func TestDaemonPathCustomOverridePrecedence(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)

	if got := CustomBinDir(); got != customDir {
		t.Fatalf("CustomBinDir() = %q, want %q", got, customDir)
	}

	overridePath := filepath.Join(customDir, "sing-box")
	if err := os.WriteFile(overridePath, makeTestELFForArch(t, runtime.GOARCH), 0o755); err != nil {
		t.Fatalf("write override ELF: %v", err)
	}

	got := DaemonPath("sing-box")
	if got != overridePath {
		t.Fatalf("DaemonPath(sing-box) = %q, want override %q", got, overridePath)
	}
}

func TestDaemonPathRejectsCorruptOrWrongArchOverride(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)

	overridePath := filepath.Join(customDir, "telemt")
	if err := os.WriteFile(overridePath, []byte("not-an-elf-binary"), 0o755); err != nil {
		t.Fatalf("write corrupt override: %v", err)
	}
	if got := DaemonPath("telemt"); got != BundledDaemonPath("telemt") {
		t.Fatalf("corrupt override should fall back to bundled path %q, got %q", BundledDaemonPath("telemt"), got)
	}

	wrongArch := "arm64"
	if runtime.GOARCH == "arm64" {
		wrongArch = "amd64"
	}
	if err := os.WriteFile(overridePath, makeTestELFForArch(t, wrongArch), 0o755); err != nil {
		t.Fatalf("write wrong-arch override: %v", err)
	}
	if got := DaemonPath("telemt"); got != BundledDaemonPath("telemt") {
		t.Fatalf("wrong-arch override should fall back to bundled path %q, got %q", BundledDaemonPath("telemt"), got)
	}
}
