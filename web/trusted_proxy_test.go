package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

func TestConfigureTrustedProxiesAndGinClientIP(t *testing.T) {
	logger.InitLogger(logging.CRITICAL)
	if err := database.InitDB(filepath.Join(t.TempDir(), "trusted-proxies-web.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	gin.SetMode(gin.TestMode)

	buildEngine := func() *gin.Engine {
		r := gin.New()
		ConfigureTrustedProxies(r, &service.SettingService{})
		r.GET("/ip", func(c *gin.Context) {
			c.String(http.StatusOK, c.ClientIP())
		})
		return r
	}

	r := buildEngine()

	// Untrusted public peer must NOT be allowed to spoof X-Forwarded-For or X-Real-IP.
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "198.51.100.44:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if got := rec.Body.String(); got != "198.51.100.44" {
		t.Fatalf("untrusted peer ClientIP = %q, want 198.51.100.44", got)
	}

	// Default trusted loopback proxy SHOULD be allowed to forward real client IP.
	req2 := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req2.RemoteAddr = "127.0.0.1:1234"
	req2.Header.Set("X-Forwarded-For", "203.0.113.8")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if got := rec2.Body.String(); got != "203.0.113.8" {
		t.Fatalf("trusted loopback peer ClientIP = %q, want 203.0.113.8", got)
	}

	// Setting trustedProxies = "none" must pass nil to SetTrustedProxies and ignore forwarded headers even from 127.0.0.1.
	if err := database.GetDB().Create(&model.Setting{Key: "trustedProxies", Value: "none"}).Error; err != nil {
		t.Fatalf("seed trustedProxies=none: %v", err)
	}
	rNone := buildEngine()
	req3 := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req3.RemoteAddr = "127.0.0.1:1234"
	req3.Header.Set("X-Forwarded-For", "203.0.113.8")
	req3.Header.Set("X-Real-IP", "203.0.113.9")
	rec3 := httptest.NewRecorder()
	rNone.ServeHTTP(rec3, req3)
	if got := rec3.Body.String(); got != "127.0.0.1" {
		t.Fatalf("trustedProxies=none ClientIP = %q, want 127.0.0.1", got)
	}
}
