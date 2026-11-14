package sub

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestSubResolveRequestTrustedProxy(t *testing.T) {
	newSubTestDB(t)
	t.Cleanup(func() { _ = database.CloseDB() })

	gin.SetMode(gin.TestMode)
	svc := subSvc()

	runResolve := func(remoteAddr string) (string, string, string, string) {
		var scheme, host, hostWithPort, hostHeader string
		r := gin.New()
		r.GET("/sub", func(c *gin.Context) {
			scheme, host, hostWithPort, hostHeader = svc.ResolveRequest(c)
			c.Status(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodGet, "/sub", nil)
		req.RemoteAddr = remoteAddr
		req.Host = "sub.example.com:2096"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "evil.example:8443")
		req.Header.Set("X-Real-IP", "1.1.1.1")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return scheme, host, hostWithPort, hostHeader
	}

	// Untrusted external IP must NOT spoof X-Forwarded-Proto, X-Forwarded-Host, or X-Real-IP.
	scheme, host, hostWithPort, hostHeader := runResolve("203.0.113.9:1234")
	if scheme != "http" || host != "sub.example.com" || hostWithPort != "sub.example.com:2096" || hostHeader != "sub.example.com" {
		t.Fatalf("untrusted ResolveRequest = (%q, %q, %q, %q), want (http, sub.example.com, sub.example.com:2096, sub.example.com)",
			scheme, host, hostWithPort, hostHeader)
	}

	// Default trusted loopback proxy should be honored.
	scheme, host, hostWithPort, hostHeader = runResolve("127.0.0.1:1234")
	if scheme != "https" || host != "evil.example" || hostWithPort != "evil.example:8443" || hostHeader != "evil.example:8443" {
		t.Fatalf("trusted ResolveRequest = (%q, %q, %q, %q), want (https, evil.example, evil.example:8443, evil.example:8443)",
			scheme, host, hostWithPort, hostHeader)
	}

	// Explicitly disabling trusted proxies via "none" must reject loopback forwarded headers too.
	if err := database.GetDB().Create(&model.Setting{Key: "trustedProxies", Value: "none"}).Error; err != nil {
		t.Fatalf("seed trustedProxies=none: %v", err)
	}
	scheme, host, hostWithPort, hostHeader = runResolve("127.0.0.1:1234")
	if scheme != "http" || host != "sub.example.com" || hostWithPort != "sub.example.com:2096" || hostHeader != "sub.example.com" {
		t.Fatalf("trustedProxies=none ResolveRequest = (%q, %q, %q, %q), want forwarded headers ignored",
			scheme, host, hostWithPort, hostHeader)
	}
}
