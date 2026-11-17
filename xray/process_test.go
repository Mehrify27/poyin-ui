package xray

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestHelperXrayStubProcess turns the Go test binary into a controllable child
// process when invoked with XRAY_TEST_HELPER_MODE=1.
func TestHelperXrayStubProcess(t *testing.T) {
	if os.Getenv("XRAY_TEST_HELPER_MODE") != "1" {
		return
	}
	if pidFile := os.Getenv("XRAY_TEST_PID_FILE"); pidFile != "" {
		_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)
	}
	time.Sleep(10 * time.Second)
	os.Exit(0)
}

func TestProcessStopWaitsForChildExitAndIsRaceSafe(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "stub.pid")

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperXrayStubProcess$")
	cmd.Env = append(os.Environ(),
		"XRAY_TEST_HELPER_MODE=1",
		"XRAY_TEST_PID_FILE="+pidFile,
	)
	done := make(chan struct{})
	p := &process{
		version:   "test",
		config:    &Config{},
		logWriter: NewLogWriter(),
		cmd:       cmd,
		done:      done,
		startTime: time.Now(),
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start helper child: %v", err)
	}
	go func() {
		defer close(done)
		if err := cmd.Wait(); err != nil {
			p.mu.Lock()
			p.exitErr = err
			p.mu.Unlock()
		}
	}()

	// Wait until helper actually booted and wrote its PID before issuing Stop.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !p.IsRunning() {
		t.Fatal("IsRunning returned false while helper process was alive")
	}

	var wg sync.WaitGroup
	stopReaders := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					_ = p.IsRunning()
					_ = p.GetErr()
					_ = p.GetResult()
				}
			}
		}()
	}

	// Ignore Windows SIGTERM "not supported" fallback behavior; Stop still waits for Kill + exit.
	_ = p.Stop()

	select {
	case <-done:
	default:
		close(stopReaders)
		wg.Wait()
		t.Fatal("process.Stop returned before child exited — restart port-bind race still present")
	}

	if p.IsRunning() {
		close(stopReaders)
		wg.Wait()
		t.Fatal("IsRunning still returned true after Stop completed")
	}

	close(stopReaders)
	wg.Wait()
}

func TestSetEnvOverridesAndLogWriterRaceSafety(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"XRAY_LOCATION_ASSET=/stale/dir",
		"XRAY_SPEEDLIMIT_FILE=/stale/speed.json",
	}
	out := setEnvOverrides(base,
		"XRAY_SPEEDLIMIT_FILE=/opt/vpn-ui/bin/speedlimits.json",
		"XRAY_LOCATION_ASSET=/opt/vpn-ui/bin",
	)
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "/stale/") {
		t.Fatalf("stale env entries were not replaced: %v", out)
	}
	if count := strings.Count(joined, "XRAY_LOCATION_ASSET="); count != 1 {
		t.Fatalf("expected 1 XRAY_LOCATION_ASSET entry, got %d (%v)", count, out)
	}

	lw := NewLogWriter()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = lw.Write([]byte("failed to read geoip.dat"))
				_ = lw.LastLine()
			}
		}()
	}
	wg.Wait()
}
