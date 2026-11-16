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

func TestScoreReleaseAssetPrefersMuslAndAvoidsV3(t *testing.T) {
	telemtAssets := []githubReleaseAsset{
		{Name: "telemt", BrowserDownloadURL: "https://example.com/telemt"},
		{Name: "telemt-x86_64-linux-gnu.tar.gz", BrowserDownloadURL: "https://example.com/gnu"},
		{Name: "telemt-x86_64-v3-linux-musl.tar.gz", BrowserDownloadURL: "https://example.com/v3-musl"},
		{Name: "telemt-x86_64-linux-musl.tar.gz", BrowserDownloadURL: "https://example.com/musl"},
	}
	name, _, _, _ := pickReleaseAsset("telemt", telemtAssets, "amd64")
	if name != "telemt-x86_64-linux-musl.tar.gz" {
		t.Fatalf("telemt amd64 picked %q, want telemt-x86_64-linux-musl.tar.gz", name)
	}

	singboxAssets := []githubReleaseAsset{
		{Name: "sing-box-1.14.4-linux-amd64-glibc.tar.gz", BrowserDownloadURL: "https://example.com/glibc"},
		{Name: "sing-box-1.14.4-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.com/plain"},
		{Name: "sing-box-1.14.4-linux-amd64-musl.tar.gz", BrowserDownloadURL: "https://example.com/musl"},
	}
	name, _, _, _ = pickReleaseAsset("sing-box", singboxAssets, "amd64")
	if name != "sing-box-1.14.4-linux-amd64-musl.tar.gz" {
		t.Fatalf("sing-box amd64 picked %q, want sing-box-1.14.4-linux-amd64-musl.tar.gz", name)
	}

	singboxNoMusl := []githubReleaseAsset{
		{Name: "sing-box-1.14.4-linux-amd64-glibc.tar.gz", BrowserDownloadURL: "https://example.com/glibc"},
		{Name: "sing-box-1.14.4-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.com/plain"},
	}
	name, _, _, _ = pickReleaseAsset("sing-box", singboxNoMusl, "amd64")
	if name != "sing-box-1.14.4-linux-amd64.tar.gz" {
		t.Fatalf("sing-box amd64 fallback picked %q, want static plain tar.gz over glibc", name)
	}

	armAssets := []githubReleaseAsset{
		{Name: "sing-box-1.14.4-linux-arm64.tar.gz", BrowserDownloadURL: "https://example.com/arm64"},
		{Name: "sing-box-1.14.4-linux-armv7.tar.gz", BrowserDownloadURL: "https://example.com/armv7"},
	}
	name, _, _, _ = pickReleaseAsset("sing-box", armAssets, "arm")
	if name != "sing-box-1.14.4-linux-armv7.tar.gz" {
		t.Fatalf("sing-box arm picked %q, want armv7 (must not match arm64)", name)
	}
}

func TestListUpstreamCoreVersionsAndInstallSelectedTag(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)

	archTok := archTokenForTest(runtime.GOARCH)
	oldELF := makeUpdaterTestELF(t, runtime.GOARCH, 0x33)
	oldZip := makeTestZipArchive(t, "xray", oldELF)
	oldSum := sha256HexBytes(oldZip)

	var srv *httptest.Server
	var xrayListCalls int
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/XTLS/Xray-core/releases":
			xrayListCalls++
			assetOld := fmt.Sprintf("Xray-linux-%s.zip", archTok)
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"tag_name":     "v26.12.0-rc.1",
					"prerelease":   true,
					"published_at": "2026-11-16T00:00:00Z",
					"assets": []map[string]any{
						{"name": assetOld, "browser_download_url": srv.URL + "/dl/rc/" + assetOld},
					},
				},
				{
					"tag_name":     "v26.11.9",
					"prerelease":   false,
					"published_at": "2026-11-09T00:00:00Z",
					"assets": []map[string]any{
						{"name": assetOld, "browser_download_url": srv.URL + "/dl/latest/" + assetOld},
					},
				},
				{
					"tag_name":     "v26.10.1",
					"prerelease":   false,
					"published_at": "2026-10-01T00:00:00Z",
					"assets": []map[string]any{
						{"name": assetOld, "browser_download_url": srv.URL + "/dl/old/" + assetOld},
						{"name": assetOld + ".dgst", "browser_download_url": srv.URL + "/dl/old/" + assetOld + ".dgst"},
					},
				},
			})
		case "/repos/XTLS/Xray-core/releases/tags/v26.10.1":
			assetOld := fmt.Sprintf("Xray-linux-%s.zip", archTok)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v26.10.1",
				"assets": []map[string]any{
					{"name": assetOld, "browser_download_url": srv.URL + "/dl/old/" + assetOld},
					{"name": assetOld + ".dgst", "browser_download_url": srv.URL + "/dl/old/" + assetOld + ".dgst"},
				},
			})
		case "/dl/old/Xray-linux-" + archTok + ".zip":
			_, _ = w.Write(oldZip)
		case "/dl/old/Xray-linux-" + archTok + ".zip.dgst":
			_, _ = fmt.Fprintf(w, "SHA2-256= %s\n", oldSum)
		case "/repos/amnezia-vpn/amneziawg-go/releases":
			_, _ = w.Write([]byte("[]"))
		case "/repos/amnezia-vpn/amneziawg-go/tags":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"name": "v3.1.20261116", "tarball_url": srv.URL + "/awg.tgz"},
				{"name": "v3.0.3", "tarball_url": srv.URL + "/awg303.tgz"},
			})
		case "/api/v4/projects/openconnect%2Focserv/releases":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"tag_name": "1.3.0", "name": "ocserv 1.3.0", "released_at": "2024-06-01T00:00:00Z"},
				{"tag_name": "1.2.4", "name": "ocserv 1.2.4", "released_at": "2024-02-01T00:00:00Z"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prevGH, prevGL := githubReleaseAPIBase, gitlabReleaseAPIBase
	githubReleaseAPIBase, gitlabReleaseAPIBase = srv.URL, srv.URL
	defer func() {
		githubReleaseAPIBase, gitlabReleaseAPIBase = prevGH, prevGL
	}()

	svc := &CoreService{}
	spec, list, err := svc.ListUpstreamCoreVersions("xray", true)
	if err != nil {
		t.Fatalf("ListUpstreamCoreVersions(xray): %v", err)
	}
	if spec.Target != "xray" || len(list) != 3 {
		t.Fatalf("unexpected xray upstream list: %+v", list)
	}
	if list[0].Latest || !list[0].Prerelease || !list[1].Latest || list[1].Tag != "v26.11.9" {
		t.Fatalf("expected first non-prerelease v26.11.9 marked Latest, got %+v", list)
	}
	if _, _, err := svc.ListUpstreamCoreVersions("xray", false); err != nil {
		t.Fatalf("cached ListUpstreamCoreVersions(xray): %v", err)
	}
	if xrayListCalls != 1 {
		t.Fatalf("expected second cached lookup not to hit HTTP, calls=%d", xrayListCalls)
	}

	// Install the explicitly picked older tag v26.10.1.
	results, err := svc.UpdateCore(CoreUpdateOptions{
		Target:           "xray",
		Version:          "v26.10.1",
		RestartFunc:      func(string) error { return nil },
		VerifyHealthFunc: func(CoreUpdateSpec, string) error { return nil },
	})
	if err != nil || len(results) != 1 || results[0].Status != "updated" {
		t.Fatalf("install selected version v26.10.1 failed: results=%+v err=%v", results, err)
	}
	gotBytes, err := os.ReadFile(results[0].DestPath)
	if err != nil || !bytes.Equal(gotBytes, oldELF) {
		t.Fatalf("selected v26.10.1 binary mismatch")
	}

	// Verify GitHub tag fallback for amneziawg-go and GitLab releases for ocserv.
	_, awgList, err := svc.ListUpstreamCoreVersions("awg", true)
	if err != nil || len(awgList) != 2 || awgList[0].Tag != "v3.1.20261116" || !awgList[0].Latest {
		t.Fatalf("unexpected amneziawg-go tags list: %+v err=%v", awgList, err)
	}
	_, ocList, err := svc.ListUpstreamCoreVersions("openconnect", true)
	if err != nil || len(ocList) != 2 || ocList[0].Tag != "1.3.0" || !ocList[0].Latest || !ocList[0].SourceOnly {
		t.Fatalf("unexpected ocserv GitLab releases list: %+v err=%v", ocList, err)
	}
}

func TestUpdateCoreAllSkipsNonPrebuiltCleanly(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv(binutil.CustomBinDirEnv, customDir)
	// Simulate a server without a Go compiler in PATH so source-go targets skip cleanly.
	t.Setenv("PATH", t.TempDir())

	archTok := archTokenForTest(runtime.GOARCH)
	xrayZip := makeTestZipArchive(t, "xray", makeUpdaterTestELF(t, runtime.GOARCH, 0x41))
	telemtTgz := makeTestTarGzArchive(t, "telemt", makeUpdaterTestELF(t, runtime.GOARCH, 0x42))
	sbTgz := makeTestTarGzArchive(t, "sing-box-1.14.4/sing-box", makeUpdaterTestELF(t, runtime.GOARCH, 0x43))

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/XTLS/Xray-core/releases/latest":
			name := fmt.Sprintf("Xray-linux-%s.zip", archTok)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v26.11.9",
				"assets":   []map[string]any{{"name": name, "browser_download_url": srv.URL + "/xray.zip"}},
			})
		case "/repos/telemt/telemt/releases/latest":
			name := fmt.Sprintf("telemt-%s-linux-musl.tar.gz", archTok)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "3.5.17",
				"assets":   []map[string]any{{"name": name, "browser_download_url": srv.URL + "/telemt.tgz"}},
			})
		case "/repos/SagerNet/sing-box/releases/latest":
			name := fmt.Sprintf("sing-box-1.14.4-linux-%s-musl.tar.gz", archTok)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v1.14.4",
				"assets":   []map[string]any{{"name": name, "browser_download_url": srv.URL + "/sb.tgz"}},
			})
		case "/xray.zip":
			_, _ = w.Write(xrayZip)
		case "/telemt.tgz":
			_, _ = w.Write(telemtTgz)
		case "/sb.tgz":
			_, _ = w.Write(sbTgz)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prevBase := githubReleaseAPIBase
	githubReleaseAPIBase = srv.URL
	defer func() { githubReleaseAPIBase = prevBase }()

	svc := &CoreService{}
	results, err := svc.UpdateCore(CoreUpdateOptions{
		Target:           "all",
		RestartFunc:      func(string) error { return nil },
		VerifyHealthFunc: func(CoreUpdateSpec, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("UpdateCore(all) should skip source-only targets cleanly without error, got %v", err)
	}
	byTarget := map[string]string{}
	for _, r := range results {
		byTarget[r.Target] = r.Status
	}
	for _, wantUpd := range []string{"xray", "telemt", "sing-box"} {
		if byTarget[wantUpd] != "updated" {
			t.Fatalf("target %s status = %q, want updated (all=%v)", wantUpd, byTarget[wantUpd], byTarget)
		}
	}
	for _, wantSkip := range []string{"amneziawg-go", "ocserv", "openvpn", "xl2tpd"} {
		if byTarget[wantSkip] != "skipped" {
			t.Fatalf("target %s status = %q, want skipped (all=%v)", wantSkip, byTarget[wantSkip], byTarget)
		}
	}
}
