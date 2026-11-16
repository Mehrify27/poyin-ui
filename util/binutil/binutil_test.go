package binutil

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// makeTestELF64 constructs a minimal valid ELF64 ET_EXEC header for machine.
func makeTestELF64(machine elf.Machine, payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT), 0})
	buf.Write(make([]byte, 8)) // e_ident padding
	_ = binary.Write(&buf, binary.LittleEndian, uint16(elf.ET_EXEC))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(machine))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))  // e_version
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0))  // e_entry
	_ = binary.Write(&buf, binary.LittleEndian, uint64(64)) // e_phoff
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0))  // e_shoff
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))  // e_flags
	_ = binary.Write(&buf, binary.LittleEndian, uint16(64)) // e_ehsize
	_ = binary.Write(&buf, binary.LittleEndian, uint16(56)) // e_phentsize
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))  // e_phnum
	_ = binary.Write(&buf, binary.LittleEndian, uint16(64)) // e_shentsize
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))  // e_shnum
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))  // e_shstrndx
	buf.Write(payload)
	return buf.Bytes()
}

func currentArchMachine() elf.Machine {
	if runtime.GOARCH == "arm64" {
		return elf.EM_AARCH64
	}
	return elf.EM_X86_64
}

func oppositeArchMachine() elf.Machine {
	if runtime.GOARCH == "arm64" {
		return elf.EM_X86_64
	}
	return elf.EM_AARCH64
}

func TestValidateELFBinaryAndArchMismatch(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, makeTestELF64(currentArchMachine(), []byte("ok")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateELFBinary(good, runtime.GOARCH); err != nil {
		t.Fatalf("expected valid ELF64 binary to pass: %v", err)
	}

	wrongArch := filepath.Join(dir, "wrong-arch")
	if err := os.WriteFile(wrongArch, makeTestELF64(oppositeArchMachine(), []byte("bad")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateELFBinary(wrongArch, runtime.GOARCH); err == nil {
		t.Fatal("expected architecture mismatch to fail validation")
	}

	notELF := filepath.Join(dir, "html-404")
	if err := os.WriteFile(notELF, []byte("<html>404 Not Found</html>"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateELFBinary(notELF, runtime.GOARCH); err == nil {
		t.Fatal("expected non-ELF file to fail validation")
	}
}

func TestResolveCustomBinaryFallbackAndOrder(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv(CustomBinDirEnv, customDir)

	badPath := filepath.Join(customDir, "xray-linux-"+runtime.GOARCH)
	if err := os.WriteFile(badPath, []byte("corrupt"), 0o755); err != nil {
		t.Fatal(err)
	}
	goodPath := filepath.Join(customDir, "xray")
	if err := os.WriteFile(goodPath, makeTestELF64(currentArchMachine(), []byte("v2")), 0o755); err != nil {
		t.Fatal(err)
	}

	resolved, warnErr := ResolveCustomBinary("xray-linux-"+runtime.GOARCH, "xray")
	if warnErr == nil {
		t.Fatal("expected warning error for invalid first candidate")
	}
	if resolved != goodPath {
		t.Fatalf("resolved = %q, want %q", resolved, goodPath)
	}
}

func TestAtomicInstallBinaryAndRestore(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "sing-box")
	src1 := filepath.Join(dir, "src1")
	src2 := filepath.Join(dir, "src2")

	data1 := makeTestELF64(currentArchMachine(), []byte("version-1"))
	data2 := makeTestELF64(currentArchMachine(), []byte("version-2"))
	if err := os.WriteFile(src1, data1, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src2, data2, 0o644); err != nil {
		t.Fatal(err)
	}

	sum2 := sha256.Sum256(data2)
	if err := VerifySHA256(src2, "sha256:"+hex.EncodeToString(sum2[:])); err != nil {
		t.Fatalf("VerifySHA256 failed: %v", err)
	}
	if err := VerifySHA256(src2, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected VerifySHA256 mismatch to fail")
	}

	bak1, hadPrev1, err := AtomicInstallBinary(dest, src1)
	if err != nil || hadPrev1 || bak1 == "" {
		t.Fatalf("first install unexpected result: bak=%q hadPrev=%v err=%v", bak1, hadPrev1, err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, data1) {
		t.Fatal("dest content after first install mismatch")
	}

	bak2, hadPrev2, err := AtomicInstallBinary(dest, src2)
	if err != nil || !hadPrev2 {
		t.Fatalf("second install unexpected result: bak=%q hadPrev=%v err=%v", bak2, hadPrev2, err)
	}
	got, _ = os.ReadFile(dest)
	if !bytes.Equal(got, data2) {
		t.Fatal("dest content after second install mismatch")
	}

	if err := RestoreBinary(dest, bak2, true); err != nil {
		t.Fatalf("RestoreBinary failed: %v", err)
	}
	got, _ = os.ReadFile(dest)
	if !bytes.Equal(got, data1) {
		t.Fatal("dest content after rollback did not restore data1")
	}
}
