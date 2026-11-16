package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestInstallPanelBinaryAbortsWhenDBBackupFails(t *testing.T) {
	t.Cleanup(func() { _ = database.CloseDB() })

	dir := t.TempDir()
	t.Setenv("VPNUI_DB_FOLDER", dir)
	_ = database.CloseDB()

	exe := filepath.Join(dir, "vpn-ui")
	staged := filepath.Join(dir, "vpn-ui.new")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new-bin"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := installPanelBinary(staged, exe)
	if err == nil || !strings.Contains(err.Error(), "pre-update DB backup failed") {
		t.Fatalf("expected DB backup abort error, got: %v", err)
	}
	got, readErr := os.ReadFile(exe)
	if readErr != nil || string(got) != "old-bin" {
		t.Fatalf("running binary was modified despite backup failure: content=%q err=%v", string(got), readErr)
	}
	if _, statErr := os.Stat(staged); !os.IsNotExist(statErr) {
		t.Fatalf("expected failed staged binary to be cleaned up")
	}
}

func TestInstallPanelBinaryAbortsOnBinaryBackupFailureAndRollsBackRenameFailure(t *testing.T) {
	t.Cleanup(func() { _ = database.CloseDB() })

	dir := t.TempDir()
	t.Setenv("VPNUI_DB_FOLDER", dir)
	_ = database.CloseDB()
	if err := database.InitDB(config.GetDBPath()); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	if err := database.GetDB().Create(&model.Setting{Key: "updateSafety", Value: "ok"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Case 1: missing source exe makes CopyFile(exe, bakPath) fail before rename.
	missingExe := filepath.Join(dir, "missing-vpn-ui")
	staged1 := filepath.Join(dir, "staged1")
	if err := os.WriteFile(staged1, []byte("new-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := installPanelBinary(staged1, missingExe); err == nil || !strings.Contains(err.Error(), "binary backup failed") {
		t.Fatalf("expected binary backup error, got: %v", err)
	}

	// Case 2: valid DB + exe, rename removes exe and fails -> rollback must restore exe from .bak.
	exe := filepath.Join(dir, "vpn-ui")
	staged2 := filepath.Join(dir, "staged2")
	if err := os.WriteFile(exe, []byte("known-good-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged2, []byte("broken-new-bin"), 0o755); err != nil {
		t.Fatal(err)
	}

	origRename := renamePanelBinary
	t.Cleanup(func() { renamePanelBinary = origRename })
	renamePanelBinary = func(oldPath, newPath string) error {
		_ = os.Remove(newPath)
		return errors.New("simulated EIO during rename")
	}

	err := installPanelBinary(staged2, exe)
	if err == nil || !strings.Contains(err.Error(), "replacing binary failed") {
		t.Fatalf("expected replacing binary failed error, got: %v", err)
	}

	restored, readErr := os.ReadFile(exe)
	if readErr != nil || string(restored) != "known-good-bin" {
		t.Fatalf("expected rollback from .bak to restore exe, got content=%q err=%v", string(restored), readErr)
	}
	bakData, bakErr := os.ReadFile(exe + ".bak")
	if bakErr != nil || string(bakData) != "known-good-bin" {
		t.Fatalf("expected .bak binary preserved, got content=%q err=%v", string(bakData), bakErr)
	}

	// Ensure pre-update backup snapshot was also created and passes integrity validation.
	backups, globErr := filepath.Glob(filepath.Join(dir, "backups", "*.db"))
	if globErr != nil || len(backups) == 0 {
		t.Fatalf("expected at least one DB backup under backups/, globErr=%v count=%d", globErr, len(backups))
	}
	if err := database.ValidateSQLiteDB(backups[0]); err != nil {
		t.Fatalf("DB backup failed ValidateSQLiteDB: %v", err)
	}
}

func TestRollbackPanelUpdateRestoresBinaryAndDatabase(t *testing.T) {
	t.Cleanup(func() { _ = database.CloseDB() })

	dir := t.TempDir()
	t.Setenv("VPNUI_DB_FOLDER", dir)
	_ = database.CloseDB()
	if err := database.InitDB(config.GetDBPath()); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	if err := database.GetDB().Create(&model.Setting{Key: "rollbackMarker", Value: "before-upgrade"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	exe := filepath.Join(dir, "vpn-ui-amd64")
	if err := os.WriteFile(exe, []byte("v1.9.4-good-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	backupDB, err := backupPanelDB()
	if err != nil {
		t.Fatalf("backupPanelDB: %v", err)
	}

	// Simulate an upgrade mutation + bad binary swap.
	if err := database.GetDB().Model(&model.Setting{}).Where("key = ?", "rollbackMarker").Update("value", "broken-after-upgrade").Error; err != nil {
		t.Fatalf("mutate setting: %v", err)
	}
	staged := filepath.Join(dir, "vpn-ui.new")
	if err := os.WriteFile(staged, []byte("v2.0.0-broken-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	backupBin, err := SwapPanelBinaryWithBackup(staged, exe)
	if err != nil {
		t.Fatalf("SwapPanelBinaryWithBackup: %v", err)
	}

	if err := RollbackPanelUpdate(exe, backupBin, backupDB); err != nil {
		t.Fatalf("RollbackPanelUpdate: %v", err)
	}

	binBytes, err := os.ReadFile(exe)
	if err != nil || string(binBytes) != "v1.9.4-good-bin" {
		t.Fatalf("binary after rollback = %q (err=%v); want v1.9.4-good-bin", string(binBytes), err)
	}

	if err := database.InitDB(config.GetDBPath()); err != nil {
		t.Fatalf("re-InitDB after rollback: %v", err)
	}
	var s model.Setting
	if err := database.GetDB().Where("key = ?", "rollbackMarker").First(&s).Error; err != nil {
		t.Fatalf("query restored setting: %v", err)
	}
	if s.Value != "before-upgrade" {
		t.Fatalf("restored setting = %q; want before-upgrade", s.Value)
	}
}
