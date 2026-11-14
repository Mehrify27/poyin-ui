package database

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
)

func TestInitReadOnlyDBAndBusyTimeout(t *testing.T) {
	t.Cleanup(func() { _ = CloseDB() })

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "panel.db")

	// Missing DB must return an error rather than silently creating an empty file.
	if err := InitReadOnlyDB(dbPath); err == nil {
		t.Fatalf("expected error opening missing DB in read-only mode")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("InitReadOnlyDB should not create missing DB file")
	}

	t.Setenv("VPNUI_INIT_ADMIN_USER", "")
	t.Setenv("VPNUI_INIT_ADMIN_PASS", "")
	if err := InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	// Default generated credential must NEVER equal "admin".
	var u model.User
	if err := GetDB().First(&u).Error; err != nil {
		t.Fatalf("query initial user: %v", err)
	}
	if crypto.CheckPasswordHash(u.Password, "admin") {
		t.Fatalf("initial user must not use static 'admin' password")
	}
	if !u.IsSuperAdmin || !u.Enable {
		t.Fatalf("expected enabled super-admin, got %+v", u)
	}

	if err := GetDB().Create(&model.Setting{Key: "roTestKey", Value: "roVal"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	if err := CloseDB(); err != nil {
		t.Fatalf("CloseDB: %v", err)
	}
	if GetDB() != nil {
		t.Fatalf("CloseDB must reset global db handle to nil")
	}

	if err := InitReadOnlyDB(dbPath); err != nil {
		t.Fatalf("InitReadOnlyDB: %v", err)
	}
	if val, err := GetSettingValue(dbPath, "roTestKey"); err != nil || val != "roVal" {
		t.Fatalf("GetSettingValue got (%q, %v), want (roVal, nil)", val, err)
	}

	// PRAGMA query_only must block mutations on the read-only handle.
	if err := GetDB().Create(&model.Setting{Key: "shouldFail", Value: "x"}).Error; err == nil {
		t.Fatalf("expected write via read-only DB handle to fail")
	}
}

func TestValidateSQLiteDB(t *testing.T) {
	t.Cleanup(func() { _ = CloseDB() })

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "valid.db")
	if err := InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	if err := Checkpoint(); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if err := CloseDB(); err != nil {
		t.Fatalf("CloseDB: %v", err)
	}
	if err := ValidateSQLiteDB(dbPath); err != nil {
		t.Fatalf("ValidateSQLiteDB on valid db failed: %v", err)
	}

	corrupt := filepath.Join(dir, "corrupt.db")
	if err := os.WriteFile(corrupt, []byte("not a sqlite file"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	if err := ValidateSQLiteDB(corrupt); err == nil {
		t.Fatalf("expected ValidateSQLiteDB to reject corrupt file")
	}
}
