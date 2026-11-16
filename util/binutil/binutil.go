package binutil

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// DefaultCustomBinDir holds operator-provided or independently updated
	// core/sidecar binaries so panel upgrades and bundled daemon extractions
	// never overwrite them.
	DefaultCustomBinDir = "/opt/vpn-ui/custom-bin"

	// CustomBinDirEnv overrides DefaultCustomBinDir when set.
	CustomBinDirEnv = "VPN_UI_CUSTOM_BIN_DIR"
)

// CustomBinDir returns the directory checked for custom/independently updated
// sidecar binary overrides.
func CustomBinDir() string {
	if env := strings.TrimSpace(os.Getenv(CustomBinDirEnv)); env != "" {
		return filepath.Clean(env)
	}
	return DefaultCustomBinDir
}

// ValidateELFBinary verifies that path is a regular executable ELF binary
// targeting goarch (e.g. "amd64", "arm64", "386", "arm").
func ValidateELFBinary(path, goarch string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() || !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() < 16 {
		return fmt.Errorf("%s is too small (%d bytes) to be a valid executable", path, st.Size())
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not executable (mode %04o)", path, st.Mode().Perm())
	}

	ef, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("%s is not a valid ELF binary: %w", path, err)
	}
	defer ef.Close()

	if ef.Type != elf.ET_EXEC && ef.Type != elf.ET_DYN {
		return fmt.Errorf("%s is not an ELF executable or PIE binary (type %s)", path, ef.Type)
	}

	wantClass, wantMachine, err := expectedELFTarget(goarch)
	if err != nil {
		return err
	}
	if ef.Class != wantClass {
		return fmt.Errorf("%s ELF class mismatch: got %s, want %s", path, ef.Class, wantClass)
	}
	if ef.Machine != wantMachine {
		return fmt.Errorf("%s ELF architecture mismatch: got %s, want %s", path, ef.Machine, wantMachine)
	}
	return nil
}

func expectedELFTarget(goarch string) (elf.Class, elf.Machine, error) {
	switch goarch {
	case "amd64":
		return elf.ELFCLASS64, elf.EM_X86_64, nil
	case "arm64":
		return elf.ELFCLASS64, elf.EM_AARCH64, nil
	case "386":
		return elf.ELFCLASS32, elf.EM_386, nil
	case "arm":
		return elf.ELFCLASS32, elf.EM_ARM, nil
	default:
		return elf.ELFCLASSNONE, elf.EM_NONE, fmt.Errorf("unsupported target architecture %q", goarch)
	}
}

// ValidateOverrideExecutable validates a custom override file before returning
// it for execution. Script names ("vpnc-script" or *.sh) allow a valid shebang
// ("#!"); all other overrides must pass ValidateELFBinary for runtime.GOARCH.
func ValidateOverrideExecutable(path, name string) error {
	if isScriptName(name) {
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		if st.IsDir() || !st.Mode().IsRegular() || st.Size() == 0 {
			return fmt.Errorf("%s is not a non-empty regular file", path)
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("%s is not executable (mode %04o)", path, st.Mode().Perm())
		}
		var hdr [2]byte
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		n, _ := f.Read(hdr[:])
		_ = f.Close()
		if n < 2 || !bytes.Equal(hdr[:], []byte("#!")) {
			return fmt.Errorf("%s missing script shebang", path)
		}
		return nil
	}
	return ValidateELFBinary(path, runtime.GOARCH)
}

func isScriptName(name string) bool {
	return name == "vpnc-script" || strings.HasSuffix(name, ".sh")
}

// ResolveCustomBinary checks CustomBinDir() in order for the candidate names
// and returns the first valid executable path along with any validation failure
// observed on an existing invalid file so callers can log and fall back safely.
func ResolveCustomBinary(candidates ...string) (string, error) {
	dir := CustomBinDir()
	var firstErr error
	for _, name := range candidates {
		if name == "" || strings.ContainsAny(name, `/\`) {
			continue
		}
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := ValidateOverrideExecutable(p, name); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("ignoring invalid custom binary %s: %w", p, err)
			}
			continue
		}
		return p, firstErr
	}
	return "", firstErr
}

// FileSHA256 computes the lowercase hex SHA-256 digest of a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifySHA256 validates a file against an expected hex SHA-256 digest
// (accepting an optional "sha256:" prefix). An empty expected digest is a no-op.
func VerifySHA256(path, expectedHex string) error {
	want := strings.TrimSpace(expectedHex)
	if want == "" {
		return nil
	}
	want = strings.TrimPrefix(strings.ToLower(want), "sha256:")
	want = strings.TrimSpace(want)
	if len(want) != 64 {
		return fmt.Errorf("invalid sha256 digest length %d", len(want))
	}
	if _, err := hex.DecodeString(want); err != nil {
		return fmt.Errorf("invalid sha256 hex digest: %w", err)
	}
	got, err := FileSHA256(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", filepath.Base(path), got, want)
	}
	return nil
}

// AtomicInstallBinary stages srcPath alongside dest, preserves any pre-existing
// dest at dest+".bak", and atomically renames the new executable into place.
func AtomicInstallBinary(dest, srcPath string) (backupPath string, hadPrev bool, err error) {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", false, err
	}
	tmpPath := dest + ".new"
	_ = os.Remove(tmpPath)

	src, err := os.Open(srcPath)
	if err != nil {
		return "", false, err
	}
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		_ = src.Close()
		return "", false, err
	}
	_, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	_ = src.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", false, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", false, closeErr
	}
	_ = os.Chmod(tmpPath, 0o755)

	backupPath = dest + ".bak"
	if st, statErr := os.Stat(dest); statErr == nil && !st.IsDir() {
		hadPrev = true
		_ = os.Remove(backupPath)
		if err := os.Rename(dest, backupPath); err != nil {
			_ = os.Remove(tmpPath)
			return "", false, fmt.Errorf("backup existing binary %s: %w", dest, err)
		}
	}

	if err := os.Rename(tmpPath, dest); err != nil {
		_ = os.Remove(tmpPath)
		if hadPrev {
			_ = os.Rename(backupPath, dest)
		}
		return "", false, fmt.Errorf("activate new binary %s: %w", dest, err)
	}
	return backupPath, hadPrev, nil
}

// RestoreBinary reverts a binary installed by AtomicInstallBinary. When
// hadPrev is true it restores backupPath; otherwise it removes dest so callers
// fall back to the bundled binary.
func RestoreBinary(dest, backupPath string, hadPrev bool) error {
	if !hadPrev {
		if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if backupPath == "" {
		backupPath = dest + ".bak"
	}
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup missing at %s: %w", backupPath, err)
	}
	tmpPath := dest + ".restore"
	_ = os.Remove(tmpPath)
	if err := os.Rename(backupPath, tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		_ = os.Rename(tmpPath, backupPath)
		return err
	}
	return nil
}
