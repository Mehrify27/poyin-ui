package locale

import (
	"embed"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/text/language"
)

// buildBundle loads en_US + fa_IR straight off disk into a fresh bundle so the
// test doesn't depend on the web package's embedded FS.
func buildBundle(t *testing.T) *i18n.Bundle {
	t.Helper()
	b := i18n.NewBundle(language.MustParse("en-US"))
	b.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	for _, f := range []string{"translate.en_US.toml", "translate.fa_IR.toml"} {
		data, err := os.ReadFile("../translation/" + f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := b.ParseMessageFileBytes(data, "translation/"+f); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
	}
	return b
}

// TestEnglishFallback proves the keystone fix: a non-English (Farsi) context asked
// for an en_US-only key (pages.core.title, which fa_IR does not translate) returns
// the English text — not a blank string, and not the raw key.
func TestEnglishFallback(t *testing.T) {
	b := buildBundle(t)
	i18nBundle = b
	localizerDefault = i18n.NewLocalizer(b, "en-US")
	LocalizerWeb = i18n.NewLocalizer(b, "fa-IR") // active locale lacks the key

	want, err := localizerDefault.Localize(&i18n.LocalizeConfig{MessageID: "pages.core.title"})
	if err != nil || want == "" {
		t.Fatalf("en_US is missing pages.core.title (want non-empty): %v", err)
	}

	got := I18n(Web, "pages.core.title")
	if got == "" {
		t.Fatal("fallback failed: got a blank string for an en-only key")
	}
	if got == "pages.core.title" {
		t.Fatal("fallback failed: returned the raw key, not English text")
	}
	if got != want {
		t.Fatalf("fallback mismatch: got %q, want English %q", got, want)
	}
	t.Logf("fa-IR context, en-only key -> English fallback %q", got)
}

type stubSettingService struct {
	lang string
}

func (s stubSettingService) GetTgLang() (string, error) {
	return s.lang, nil
}

func TestDebugModeLoadsAndReloadsDiskTranslations(t *testing.T) {
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmpDir := t.TempDir()
	transDir := filepath.Join(tmpDir, "web", "translation")
	if err := os.MkdirAll(transDir, 0o755); err != nil {
		t.Fatalf("mkdir translation dir: %v", err)
	}
	tomlPath := filepath.Join(transDir, "translate.en_US.toml")
	if err := os.WriteFile(tomlPath, []byte("phase1cHotReloadKey = \"disk-v1\"\n"), 0o644); err != nil {
		t.Fatalf("write initial toml: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origWd)
		i18nMu.Lock()
		i18nBundle = nil
		localizerDefault = nil
		LocalizerWeb = nil
		LocalizerBot = nil
		savedSettingService = nil
		i18nMu.Unlock()
	})
	t.Setenv("VPNUI_DEBUG", "true")

	if err := InitLocalizer(embed.FS{}, stubSettingService{lang: "en-US"}); err != nil {
		t.Fatalf("InitLocalizer in debug mode failed: %v", err)
	}
	if got := I18n(Bot, "phase1cHotReloadKey"); got != "disk-v1" {
		t.Fatalf("initial bot lookup = %q, want %q", got, "disk-v1")
	}

	if err := os.WriteFile(tomlPath, []byte("phase1cHotReloadKey = \"disk-v2\"\n"), 0o644); err != nil {
		t.Fatalf("update toml: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.AddCookie(&http.Cookie{Name: "lang", Value: "en-US"})

	LocalizerMiddleware()(c)

	if got := I18n(Web, "phase1cHotReloadKey"); got != "disk-v2" {
		t.Fatalf("hot-reloaded web lookup = %q, want %q", got, "disk-v2")
	}
	if got := I18n(Bot, "phase1cHotReloadKey"); got != "disk-v2" {
		t.Fatalf("hot-reloaded bot lookup = %q, want %q", got, "disk-v2")
	}
}
