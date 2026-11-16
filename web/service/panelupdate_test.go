package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
)

// resetUpdateStateForTest clears the package-level update state between cases.
func resetUpdateStateForTest() {
	panelUpdateInFlight.Store(false)
	resetUpdateCounters()
	setUpdateProgress("", 0)
	setPanelUpdateCancel(nil)
}

// The progress bar reads these counters, so a short read must publish bytes even
// when the server sends no Content-Length (chunked), where percent is meaningless.
func TestProgressReaderPublishesCounters(t *testing.T) {
	resetUpdateStateForTest()

	body := bytes.Repeat([]byte("x"), 1000)
	pr := newProgressReader(bytes.NewReader(body), int64(len(body)))
	if _, err := io.Copy(io.Discard, pr); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if got := panelUpdateBytes.Load(); got != 1000 {
		t.Errorf("bytes = %d; want 1000", got)
	}
	if got := panelUpdateTotal.Load(); got != 1000 {
		t.Errorf("total = %d; want 1000", got)
	}
	// Percent tops out at 99: the last 1% is the install phase.
	if got := panelUpdatePercent.Load(); got != 99 {
		t.Errorf("percent = %d; want 99", got)
	}

	// Unknown length: bytes still count, total/percent stay 0.
	resetUpdateStateForTest()
	pr = newProgressReader(bytes.NewReader(body), -1)
	if _, err := io.Copy(io.Discard, pr); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if got := panelUpdateBytes.Load(); got != 1000 {
		t.Errorf("chunked bytes = %d; want 1000", got)
	}
	if got := panelUpdateTotal.Load(); got != 0 {
		t.Errorf("chunked total = %d; want 0 (unknown)", got)
	}
	if got := panelUpdatePercent.Load(); got != 0 {
		t.Errorf("chunked percent = %d; want 0 (no total to divide by)", got)
	}
}

// sampleSpeed must publish a rate only once per interval, and must not divide by a
// near-zero elapsed time (which would report an absurd speed).
func TestProgressReaderSampleSpeed(t *testing.T) {
	resetUpdateStateForTest()

	start := time.Now()
	pr := &progressReader{r: strings.NewReader(""), lastSampleAt: start}

	// Too soon: no sample published.
	pr.read = 1 << 20
	pr.sampleSpeed(start.Add(10 * time.Millisecond))
	if got := panelUpdateSpeed.Load(); got != 0 {
		t.Errorf("speed published before the sample interval elapsed: %d", got)
	}

	// 1 MiB over 1s => 1 MiB/s. First sample has no previous value to smooth against.
	pr.sampleSpeed(start.Add(time.Second))
	if got := panelUpdateSpeed.Load(); got != 1<<20 {
		t.Errorf("speed = %d; want %d (1 MiB/s)", got, 1<<20)
	}

	// Second sample at the same rate must stay at the same rate: an EMA of a constant
	// signal is that constant, whatever alpha is.
	pr.read += 1 << 20
	pr.sampleSpeed(start.Add(2 * time.Second))
	if got := panelUpdateSpeed.Load(); got != 1<<20 {
		t.Errorf("steady-rate speed = %d; want %d", got, 1<<20)
	}

	// A drop to zero throughput must decay toward 0, not snap to it.
	pr.sampleSpeed(start.Add(3 * time.Second))
	got := panelUpdateSpeed.Load()
	if got == 0 {
		t.Error("speed snapped straight to 0; want a smoothed decay")
	}
	if got >= 1<<20 {
		t.Errorf("speed = %d; want a decay below the previous 1 MiB/s", got)
	}
}

// Cancel is only legal during the download. Once installing starts, the DB snapshot
// and binary swap must run to completion.
func TestCancelPanelUpdateGating(t *testing.T) {
	s := &ServerService{}

	t.Run("no update in flight", func(t *testing.T) {
		resetUpdateStateForTest()
		if err := s.CancelPanelUpdate(); err == nil {
			t.Error("cancelling with no update in flight should fail")
		}
	})

	t.Run("cancels while downloading", func(t *testing.T) {
		resetUpdateStateForTest()
		panelUpdateInFlight.Store(true)
		defer resetUpdateStateForTest()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		setPanelUpdateCancel(cancel)
		setUpdateProgress(updatePhaseDownloading, 10)

		if err := s.CancelPanelUpdate(); err != nil {
			t.Fatalf("cancel during download: %v", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Error("cancel did not abort the download context")
		}
	})

	t.Run("refuses once installing", func(t *testing.T) {
		resetUpdateStateForTest()
		panelUpdateInFlight.Store(true)
		defer resetUpdateStateForTest()

		// UpdatePanel drops the cancel hook when it enters the install phase.
		setPanelUpdateCancel(nil)
		setUpdateProgress(updatePhaseInstalling, 99)

		if err := s.CancelPanelUpdate(); err == nil {
			t.Error("cancelling during install should be refused")
		}
	})
}

func testSyntheticELFBytes(goarch string) []byte {
	mach, ok := elfMachineFor(goarch)
	if !ok {
		mach = 0x3E
	}
	var hdr [64]byte
	hdr[0], hdr[1], hdr[2], hdr[3] = 0x7f, 'E', 'L', 'F'
	hdr[4] = 2 // 64-bit
	hdr[5] = 1 // little-endian
	hdr[6] = 1 // EV_CURRENT
	hdr[18] = byte(mach)
	hdr[19] = byte(mach >> 8)
	return append(hdr[:], []byte("synthetic-panel-payload")...)
}

func TestVersionNewerAndRepoConfig(t *testing.T) {
	if !versionNewer("2.0.0", "1.9.4") {
		t.Error("expected 2.0.0 to be newer than 1.9.4")
	}
	if !versionNewer("v2.0.0", "2.0.0-rc.1") {
		t.Error("expected v2.0.0 to be newer than 2.0.0-rc.1")
	}
	if !versionNewer("v2.1.0", "v2.0.9") {
		t.Error("expected v2.1.0 to be newer than v2.0.9")
	}
	if versionNewer("1.9.4", "2.0.0") {
		t.Error("did not expect 1.9.4 to be newer than 2.0.0")
	}

	t.Cleanup(func() {
		config.SetRepoOverride("")
		config.SetGHProxyOverride("")
	})
	config.SetRepoOverride("acme/custom-vpn")
	config.SetGHProxyOverride("https://mirror.local")

	if got := PanelLatestAPIURL(); !strings.Contains(got, "https://mirror.local/https://api.github.com/repos/acme/custom-vpn/releases/latest") {
		t.Errorf("unexpected PanelLatestAPIURL: %q", got)
	}
	if got := PanelDownloadURLForArch("arm64"); !strings.Contains(got, "https://mirror.local/https://github.com/acme/custom-vpn/releases/latest/download/vpn-ui-arm64") {
		t.Errorf("unexpected PanelDownloadURLForArch(arm64): %q", got)
	}
}

func TestStageLocalPanelAssetRawAndTarGz(t *testing.T) {
	dir := t.TempDir()
	exeDir := filepath.Join(dir, "opt")
	if err := os.MkdirAll(exeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	elfData := testSyntheticELFBytes(runtime.GOARCH)
	rawSum := sha256.Sum256(elfData)
	rawHex := hex.EncodeToString(rawSum[:])

	assetName := PanelAssetForArch(runtime.GOARCH)
	binPath := filepath.Join(dir, assetName)
	if err := os.WriteFile(binPath, elfData, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath+".sha256", []byte(rawHex+"  "+assetName+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	staged, _, err := StageLocalPanelAsset(binPath, exeDir)
	if err != nil {
		t.Fatalf("StageLocalPanelAsset(raw): %v", err)
	}
	_ = os.Remove(staged)

	// Corrupt .sha256 sidecar must reject staging.
	if err := os.WriteFile(binPath+".sha256", []byte(strings.Repeat("0", 64)+"  "+assetName+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StageLocalPanelAsset(binPath, exeDir); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected SHA-256 mismatch error, got: %v", err)
	}

	// Build a valid .tar.gz release bundle with VERSION + SHA256SUMS + binary.
	bundlePath := filepath.Join(dir, "vpn-ui-2.0.0-linux-"+runtime.GOARCH+".tar.gz")
	writeTarBundle := func(path string, checksumOverride string) {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		gz := gzip.NewWriter(f)
		defer gz.Close()
		tw := tar.NewWriter(gz)
		defer tw.Close()

		sumHex := rawHex
		if checksumOverride != "" {
			sumHex = checksumOverride
		}
		entries := []struct {
			name string
			body []byte
			mode int64
		}{
			{"VERSION", []byte("2.0.0\n"), 0o644},
			{"SHA256SUMS", []byte(fmt.Sprintf("%s  %s\n", sumHex, assetName)), 0o644},
			{assetName, elfData, 0o755},
		}
		for _, e := range entries {
			hdr := &tar.Header{
				Name: e.name,
				Mode: e.mode,
				Size: int64(len(e.body)),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}

	writeTarBundle(bundlePath, "")
	stagedTar, ver, err := StageLocalPanelAsset(bundlePath, exeDir)
	if err != nil {
		t.Fatalf("StageLocalPanelAsset(tar.gz): %v", err)
	}
	_ = os.Remove(stagedTar)
	if ver != "2.0.0" {
		t.Errorf("extracted bundle version = %q; want 2.0.0", ver)
	}

	badBundle := filepath.Join(dir, "bad.tar.gz")
	writeTarBundle(badBundle, strings.Repeat("a", 64))
	if _, _, err := StageLocalPanelAsset(badBundle, exeDir); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected SHA-256 mismatch for corrupted tar.gz, got: %v", err)
	}
}
