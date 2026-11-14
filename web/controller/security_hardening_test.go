package controller

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

func newControllerSecurityDB(t *testing.T) {
	t.Helper()
	logger.InitLogger(logging.CRITICAL)
	if err := database.InitDB(filepath.Join(t.TempDir(), "controller-sec.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })
}

func TestSettingControllerDisablesSystemdUnitEditRoute(t *testing.T) {
	newControllerSecurityDB(t)
	gin.SetMode(gin.TestMode)

	super := &model.User{
		Id:           1,
		Username:     "root",
		Enable:       true,
		IsSuperAdmin: true,
	}
	r := gin.New()
	r.Use(withUser(super))
	NewSettingController(r.Group("/panel/setting"))

	// POST /panel/setting/service (arbitrary systemd unit edit / root RCE vector) must not exist.
	postReq := httptest.NewRequest(
		http.MethodPost,
		"/panel/setting/service",
		strings.NewReader("name=vpn-ui&unit=%5BService%5D%0AExecStart%3D%2Fbin%2Fsh&enable=true&start=true"),
	)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	r.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusNotFound && postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /panel/setting/service status = %d (body=%s), want 404 or 405", postRec.Code, postRec.Body.String())
	}

	// Read-only systemd status and log endpoints must remain reachable.
	getReq := httptest.NewRequest(http.MethodGet, "/panel/setting/service", nil)
	getRec := httptest.NewRecorder()
	r.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /panel/setting/service status = %d, want 200", getRec.Code)
	}

	logReq := httptest.NewRequest(http.MethodGet, "/panel/setting/service/log", nil)
	logRec := httptest.NewRecorder()
	r.ServeHTTP(logRec, logReq)
	if logRec.Code != http.StatusOK {
		t.Fatalf("GET /panel/setting/service/log status = %d, want 200", logRec.Code)
	}
}

func TestGetRemoteIpAndBrowserHostRespectTrustedProxies(t *testing.T) {
	newControllerSecurityDB(t)
	gin.SetMode(gin.TestMode)

	callHelpers := func(remoteAddr string, headers map[string]string, hostHeader string) (string, string) {
		var gotIP, gotHost string
		r := gin.New()
		r.GET("/probe", func(c *gin.Context) {
			gotIP = getRemoteIp(c)
			gotHost = browserHost(c)
			c.Status(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.RemoteAddr = remoteAddr
		req.Host = hostHeader
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return gotIP, gotHost
	}

	// Untrusted client cannot spoof X-Real-IP, X-Forwarded-For, or X-Forwarded-Host.
	ip, host := callHelpers("198.51.100.20:54321", map[string]string{
		"X-Real-IP":        "1.2.3.4",
		"X-Forwarded-For":  "5.6.7.8",
		"X-Forwarded-Host": "evil.example",
	}, "panel.local:2053")
	if ip != "198.51.100.20" {
		t.Fatalf("untrusted remote getRemoteIp = %q, want 198.51.100.20", ip)
	}
	if host != "panel.local" {
		t.Fatalf("untrusted remote browserHost = %q, want panel.local", host)
	}

	// Default trusted loopback proxy can supply real client IP (rightmost untrusted hop) and host.
	ip, host = callHelpers("127.0.0.1:54321", map[string]string{
		"X-Real-IP":        "203.0.113.5",
		"X-Forwarded-For":  "8.8.8.8, 203.0.113.5",
		"X-Forwarded-Host": "vpn.example.com",
	}, "panel.local:2053")
	if ip != "203.0.113.5" {
		t.Fatalf("trusted proxy getRemoteIp = %q, want 203.0.113.5", ip)
	}
	if host != "vpn.example.com" {
		t.Fatalf("trusted proxy browserHost = %q, want vpn.example.com", host)
	}

	// Explicit "none" disables trust even for loopback peers.
	if err := database.GetDB().Create(&model.Setting{Key: "trustedProxies", Value: "none"}).Error; err != nil {
		t.Fatalf("seed trustedProxies=none: %v", err)
	}
	ip, host = callHelpers("127.0.0.1:54321", map[string]string{
		"X-Real-IP":        "203.0.113.5",
		"X-Forwarded-For":  "203.0.113.5",
		"X-Forwarded-Host": "vpn.example.com",
	}, "panel.local:2053")
	if ip != "127.0.0.1" {
		t.Fatalf("trustedProxies=none getRemoteIp = %q, want 127.0.0.1", ip)
	}
	if host != "panel.local" {
		t.Fatalf("trustedProxies=none browserHost = %q, want panel.local", host)
	}
}
