package service

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/binutil"
)

func makeUpdaterTestELF(t *testing.T, goarch string, marker byte) []byte {
	t.Helper()
	var (
		class   byte = 2
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

	buf := make([]byte, 128)
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
	buf[100] = marker
	return buf
}

func makeTestZipArchive(t *testing.T, innerName string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(innerName)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func makeTestTarGzArchive(t *testing.T, innerName string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name: innerName,
		Mode: 0o755,
		Size: int64(len(payload)),
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func archTokenForTest(goarch string) string {
	switch goarch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "386"
	case "arm":
		return "arm"
	default:
		return goarch
	}
}

func TestUpdateCoreZipAndTargetedRestart(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)

	elfPayload := makeUpdaterTestELF(t, runtime.GOARCH, 0xA1)
	archive := makeTestZipArchive(t, "nested/xray", elfPayload)
	archiveSum := sha256HexBytes(archive)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/XTLS/Xray-core/releases/latest":
			assetName := fmt.Sprintf("Xray-linux-%s.zip", archTokenForTest(runtime.GOARCH))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v26.99.0",
				"assets": []map[string]any{
					{
						"name":                 assetName,
						"browser_download_url": srv.URL + "/download/" + assetName,
					},
					{
						"name":                 assetName + ".dgst",
						"browser_download_url": srv.URL + "/download/" + assetName + ".dgst",
					},
				},
			})
		case fmt.Sprintf("/download/Xray-linux-%s.zip", archTokenForTest(runtime.GOARCH)):
			_, _ = w.Write(archive)
		case fmt.Sprintf("/download/Xray-linux-%s.zip.dgst", archTokenForTest(runtime.GOARCH)):
			_, _ = fmt.Fprintf(w, "SHA2-256= %s\n", archiveSum)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prevBase := githubReleaseAPIBase
	githubReleaseAPIBase = srv.URL
	defer func() { githubReleaseAPIBase = prevBase }()

	var restarted []string
	svc := &CoreService{}
	results, err := svc.UpdateCore(CoreUpdateOptions{
		Target: "xray",
		RestartFunc: func(core string) error {
			restarted = append(restarted, core)
			return nil
		},
		VerifyHealthFunc: func(spec CoreUpdateSpec, destPath string) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("UpdateCore: %v", err)
	}
	if len(results) != 1 || results[0].Status != "updated" {
		t.Fatalf("unexpected update result: %+v", results)
	}
	if len(restarted) != 1 || restarted[0] != "xray" {
		t.Fatalf("expected ONLY xray to restart, got %v", restarted)
	}
	installed, err := os.ReadFile(results[0].DestPath)
	if err != nil {
		t.Fatalf("read installed binary: %v", err)
	}
	if !bytes.Equal(installed, elfPayload) {
		t.Fatalf("installed binary content mismatch")
	}

	inv := svc.GetCoreBinaryInventory()
	var found bool
	for _, item := range inv {
		if item.Core == "xray" {
			found = true
			if item.Source != "custom-override" || item.ActivePath != results[0].DestPath {
				t.Fatalf("expected xray inventory custom-override at %s, got %+v", results[0].DestPath, item)
			}
		}
	}
	if !found {
		t.Fatal("xray missing from GetCoreBinaryInventory")
	}
}

func TestUpdateCoreTarGzRejectsBadSHAAndWrongArch(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)

	elfPayload := makeUpdaterTestELF(t, runtime.GOARCH, 0xB2)
	tarGz := makeTestTarGzArchive(t, "sing-box-1.14.4-linux/sing-box", elfPayload)
	archivePath := filepath.Join(t.TempDir(), "sing-box.tar.gz")
	if err := os.WriteFile(archivePath, tarGz, 0o600); err != nil {
		t.Fatal(err)
	}

	svc := &CoreService{}
	// 1) Wrong SHA-256 must fail BEFORE installing or restarting.
	var restartCount int
	_, err := svc.UpdateCore(CoreUpdateOptions{
		Target: "sing-box",
		File:   archivePath,
		SHA256: strings.Repeat("0", 64),
		RestartFunc: func(core string) error {
			restartCount++
			return nil
		},
		VerifyHealthFunc: func(CoreUpdateSpec, string) error { return nil },
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "sha256") {
		t.Fatalf("expected sha256 mismatch error, got %v", err)
	}
	if restartCount != 0 {
		t.Fatalf("restart must not run on bad sha256")
	}

	// 2) Wrong architecture ELF inside tar.gz must fail before install.
	wrongArch := "arm64"
	if runtime.GOARCH == "arm64" {
		wrongArch = "amd64"
	}
	badTar := makeTestTarGzArchive(t, "sing-box", makeUpdaterTestELF(t, wrongArch, 0xC3))
	badPath := filepath.Join(t.TempDir(), "sing-box-wrong.tar.gz")
	if err := os.WriteFile(badPath, badTar, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpdateCore(CoreUpdateOptions{
		Target: "sing-box",
		File:   badPath,
		RestartFunc: func(core string) error {
			restartCount++
			return nil
		},
		VerifyHealthFunc: func(CoreUpdateSpec, string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected architecture mismatch error")
	}
	if restartCount != 0 {
		t.Fatalf("restart must not run on wrong ELF arch")
	}

	// 3) Valid SHA-256 and matching arch succeeds and targets ONLY hysteria2 core.
	var restartedCore string
	results, err := svc.UpdateCore(CoreUpdateOptions{
		Target: "sing-box",
		File:   archivePath,
		SHA256: sha256HexBytes(tarGz),
		RestartFunc: func(core string) error {
			restartedCore = core
			return nil
		},
		VerifyHealthFunc: func(CoreUpdateSpec, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("valid sing-box tar.gz update failed: %v", err)
	}
	if restartedCore != "hysteria2" {
		t.Fatalf("expected sing-box update to restart 'hysteria2' core only, got %q", restartedCore)
	}
	if len(results) != 1 || results[0].ServiceCore != "hysteria2" {
		t.Fatalf("unexpected result: %+v", results)
	}
}

func TestUpdateCoreAutoRollbackOnHealthFailureAndManualRollback(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)

	spec, ok := findCoreUpdateSpec("telemt")
	if !ok {
		t.Fatal("telemt spec missing")
	}
	dest := filepath.Join(customDir, spec.CustomFileFunc())

	oldELF := makeUpdaterTestELF(t, runtime.GOARCH, 0x11)
	if err := os.WriteFile(dest, oldELF, 0o755); err != nil {
		t.Fatalf("seed previous telemt: %v", err)
	}

	newELF := makeUpdaterTestELF(t, runtime.GOARCH, 0x22)
	newFile := filepath.Join(t.TempDir(), "telemt-new")
	if err := os.WriteFile(newFile, newELF, 0o755); err != nil {
		t.Fatal(err)
	}

	var restarts []string
	svc := &CoreService{}
	results, err := svc.UpdateCore(CoreUpdateOptions{
		Target: "telemt",
		File:   newFile,
		RestartFunc: func(core string) error {
			restarts = append(restarts, core)
			return nil
		},
		VerifyHealthFunc: func(CoreUpdateSpec, string) error {
			return errors.New("simulated startup crash")
		},
	})
	if err == nil {
		t.Fatal("expected error when health verification fails")
	}
	if len(results) != 1 || !results[0].RolledBack || results[0].Status != "rolled_back" {
		t.Fatalf("expected automatic rollback result, got %+v", results)
	}
	if len(restarts) != 2 || restarts[0] != "mtproto" || restarts[1] != "mtproto" {
		t.Fatalf("expected restart on update + restart after rollback (mtproto only), got %v", restarts)
	}
	cur, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cur, oldELF) {
		t.Fatal("automatic rollback did not restore previous binary bytes")
	}

	// Verify explicit rollback also restores from .bak and removes override when no .bak remains.
	if err := os.WriteFile(dest+".bak", oldELF, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, newELF, 0o755); err != nil {
		t.Fatal(err)
	}
	var rbCore string
	rbRes, err := svc.RollbackCore("telemt", func(core string) error {
		rbCore = core
		return nil
	})
	if err != nil {
		t.Fatalf("RollbackCore: %v", err)
	}
	if rbCore != "mtproto" || rbRes.Status != "rolled_back" || rbRes.Source != "backup" {
		t.Fatalf("unexpected RollbackCore result: %+v (restarted %q)", rbRes, rbCore)
	}
	cur, _ = os.ReadFile(dest)
	if !bytes.Equal(cur, oldELF) {
		t.Fatal("manual RollbackCore did not restore .bak")
	}

	// Second rollback without .bak removes custom override so bundled fallback wins.
	rbRes2, err := svc.RollbackCore("telemt", func(core string) error {
		rbCore = core
		return nil
	})
	if err != nil {
		t.Fatalf("RollbackCore bundled fallback: %v", err)
	}
	if rbRes2.Source != "bundled-fallback" {
		t.Fatalf("expected bundled-fallback source, got %+v", rbRes2)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("expected custom override to be removed, stat err = %v", statErr)
	}
}
