package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestCLIReadCommandsSafeWhenDBMissingOrUserEmpty(t *testing.T) {
	t.Cleanup(func() { _ = database.CloseDB() })

	dir := t.TempDir()
	t.Setenv("VPNUI_DB_FOLDER", dir)
	_ = database.CloseDB()

	// Calling read CLI commands when the DB does not exist must not panic or create a DB file.
	showSetting(true)
	GetCertificate(true)
	GetListenIP(true)
	if _, err := os.Stat(config.GetDBPath()); !os.IsNotExist(err) {
		t.Fatalf("CLI read commands must not create missing DB file at %s", config.GetDBPath())
	}

	// updateSetting with no write flags must be a pure no-op and avoid initializing DB.
	if err := updateSetting(0, "", "", "", "", false); err != nil {
		t.Fatalf("no-op updateSetting failed: %v", err)
	}
	if _, err := os.Stat(config.GetDBPath()); !os.IsNotExist(err) {
		t.Fatalf("no-op updateSetting should not initialize DB")
	}

	// Now create a real DB, then delete all users so GetFirstUser returns (nil, ErrRecordNotFound).
	if err := database.InitDB(config.GetDBPath()); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	if err := database.GetDB().Where("1 = 1").Delete(&model.User{}).Error; err != nil {
		t.Fatalf("delete users: %v", err)
	}
	if err := database.CloseDB(); err != nil {
		t.Fatalf("CloseDB: %v", err)
	}

	// Must not nil-deref userModel inside showSetting!
	showSetting(true)
	GetCertificate(true)
	GetListenIP(true)
}

func TestBackupPanelDBForUpdateValidatesSnapshot(t *testing.T) {
	t.Cleanup(func() { _ = database.CloseDB() })

	dir := t.TempDir()
	t.Setenv("VPNUI_DB_FOLDER", dir)
	_ = database.CloseDB()

	if _, err := backupPanelDBForUpdate("v1.0.0"); err == nil {
		t.Fatalf("expected error when DB does not exist")
	}

	if err := database.InitDB(config.GetDBPath()); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	if err := database.GetDB().Create(&model.Setting{Key: "bakKey", Value: "bakVal"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	dst, err := backupPanelDBForUpdate("v1.2.3")
	if err != nil {
		t.Fatalf("backupPanelDBForUpdate failed: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("backup file missing at %s: %v", dst, err)
	}
	wantDir := filepath.Join(filepath.Dir(config.GetDBPath()), "backups")
	if filepath.Dir(dst) != wantDir {
		t.Fatalf("backup dir %q != expected %q", filepath.Dir(dst), wantDir)
	}
	if err := database.ValidateSQLiteDB(dst); err != nil {
		t.Fatalf("ValidateSQLiteDB on CLI backup failed: %v", err)
	}
}
