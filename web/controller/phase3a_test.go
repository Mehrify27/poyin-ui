package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestJSONAndFormDualParamHelpers(t *testing.T) {
	r := gin.New()
	r.Use(JSONBodyPreserver())
	r.POST("/dual", func(c *gin.Context) {
		var bound struct {
			Tag    string `form:"tag" json:"tag"`
			Enable bool   `form:"enable" json:"enable"`
		}
		if err := bindRequest(c, &bound); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"tag":      bound.Tag,
			"enable":   bound.Enable,
			"settings": postParam(c, "settings"),
			"cores":    postParamArray(c, "cores"),
			"flag":     postParam(c, "flag"),
		})
	})

	// 1. application/json with nested object, array, bool scalar, and rewind after bindRequest
	jsonPayload := `{"tag":"wg-exit","enable":true,"flag":false,"cores":["xray","awg"],"settings":{"endpoint":"1.2.3.4:51820"}}`
	req1 := httptest.NewRequest(http.MethodPost, "/dual", strings.NewReader(jsonPayload))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("JSON request status=%d body=%s", w1.Code, w1.Body.String())
	}
	var out1 struct {
		Tag      string   `json:"tag"`
		Enable   bool     `json:"enable"`
		Settings string   `json:"settings"`
		Cores    []string `json:"cores"`
		Flag     string   `json:"flag"`
	}
	if err := json.Unmarshal(w1.Body.Bytes(), &out1); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out1.Tag != "wg-exit" || !out1.Enable || out1.Flag != "false" {
		t.Fatalf("unexpected bound/scalar values: %+v", out1)
	}
	if !strings.Contains(out1.Settings, `"endpoint":"1.2.3.4:51820"`) {
		t.Fatalf("expected JSON settings object serialized cleanly, got %q", out1.Settings)
	}
	if len(out1.Cores) != 2 || out1.Cores[0] != "xray" || out1.Cores[1] != "awg" {
		t.Fatalf("unexpected cores array: %+v", out1.Cores)
	}

	// 2. application/x-www-form-urlencoded backward compatibility
	formPayload := "tag=ssh-egress&enable=true&flag=true&cores=xray&cores=sing-box&settings=%7B%22port%22%3A22%7D"
	req2 := httptest.NewRequest(http.MethodPost, "/dual", strings.NewReader(formPayload))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("form request status=%d body=%s", w2.Code, w2.Body.String())
	}
	var out2 struct {
		Tag      string   `json:"tag"`
		Enable   bool     `json:"enable"`
		Settings string   `json:"settings"`
		Cores    []string `json:"cores"`
		Flag     string   `json:"flag"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("unmarshal form response: %v", err)
	}
	if out2.Tag != "ssh-egress" || !out2.Enable || out2.Flag != "true" {
		t.Fatalf("unexpected form values: %+v", out2)
	}
	if out2.Settings != `{"port":22}` {
		t.Fatalf("unexpected form settings: %q", out2.Settings)
	}
	if len(out2.Cores) != 2 || out2.Cores[0] != "xray" || out2.Cores[1] != "sing-box" {
		t.Fatalf("unexpected form cores array: %+v", out2)
	}
}

func TestBootstrapAndPWARoutesRespectBasePathAndAuthBoundary(t *testing.T) {
	const basePath = "/edge-panel/"
	r := gin.New()
	r.Use(sessions.Sessions("vpn-ui", cookie.NewStore([]byte("test-secret"))))
	r.Use(func(c *gin.Context) {
		c.Set("base_path", basePath)
		c.Next()
	})
	g := r.Group(basePath)
	NewBootstrapController(g)
	NewPWAController(g)

	// 1. Unauthenticated /api/bootstrap must expose basePath & PWA config, NEVER user/donate/caps
	reqBoot := httptest.NewRequest(http.MethodGet, basePath+"api/bootstrap", nil)
	wBoot := httptest.NewRecorder()
	r.ServeHTTP(wBoot, reqBoot)
	if wBoot.Code != http.StatusOK {
		t.Fatalf("bootstrap status=%d body=%s", wBoot.Code, wBoot.Body.String())
	}
	var env struct {
		Success bool           `json:"success"`
		Obj     map[string]any `json:"obj"`
	}
	if err := json.Unmarshal(wBoot.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal bootstrap: %v", err)
	}
	if !env.Success {
		t.Fatalf("expected success=true bootstrap")
	}
	if env.Obj["basePath"] != basePath || env.Obj["appBasePath"] != basePath+"app/" {
		t.Fatalf("unexpected basePaths: %v %v", env.Obj["basePath"], env.Obj["appBasePath"])
	}
	if auth, _ := env.Obj["authenticated"].(bool); auth {
		t.Fatalf("expected unauthenticated request to report authenticated=false")
	}
	for _, secretKey := range []string{"user", "perms", "reseller", "donate", "capabilities", "ui"} {
		if _, leaked := env.Obj[secretKey]; leaked {
			t.Fatalf("unauthenticated bootstrap leaked %q", secretKey)
		}
	}
	locales, _ := env.Obj["supportedLocales"].([]any)
	if len(locales) != 13 {
		t.Fatalf("expected 13 supportedLocales, got %d", len(locales))
	}

	// 2. Dynamic PWA manifest.webmanifest
	reqMan := httptest.NewRequest(http.MethodGet, basePath+"manifest.webmanifest", nil)
	wMan := httptest.NewRecorder()
	r.ServeHTTP(wMan, reqMan)
	if wMan.Code != http.StatusOK {
		t.Fatalf("manifest status=%d", wMan.Code)
	}
	if ct := wMan.Header().Get("Content-Type"); !strings.Contains(ct, "application/manifest+json") {
		t.Fatalf("unexpected manifest content-type: %q", ct)
	}
	var man map[string]any
	if err := json.Unmarshal(wMan.Body.Bytes(), &man); err != nil {
		t.Fatalf("invalid manifest JSON: %v", err)
	}
	if man["start_url"] != basePath+"app/" || man["scope"] != basePath+"app/" {
		t.Fatalf("manifest scope/start_url mismatch: start_url=%v scope=%v", man["start_url"], man["scope"])
	}

	// 3. Dynamic PWA sw.js
	reqSW := httptest.NewRequest(http.MethodGet, basePath+"sw.js", nil)
	wSW := httptest.NewRecorder()
	r.ServeHTTP(wSW, reqSW)
	if wSW.Code != http.StatusOK {
		t.Fatalf("sw.js status=%d", wSW.Code)
	}
	if allow := wSW.Header().Get("Service-Worker-Allowed"); allow != basePath {
		t.Fatalf("Service-Worker-Allowed=%q want %q", allow, basePath)
	}
	swBody := wSW.Body.String()
	for _, needle := range []string{`"/edge-panel/"`, `"/edge-panel/app/"`, `"api/"`, `"panel/"`, `"sub/"`} {
		if !strings.Contains(swBody, needle) {
			t.Fatalf("sw.js missing expected directive %s", needle)
		}
	}
}

func TestSPAControllerInjectionFallbackAndAsset404(t *testing.T) {
	mockDist := fstest.MapFS{
		"index.html": &fstest.MapFile{
			Data: []byte(`<!doctype html><html><head><base href="/__VPN_UI_APP_BASE__/" /><link rel="manifest" href="./manifest.webmanifest" /><script type="module" src="./assets/main.js"></script></head><body><div id="app"></div></body></html>`),
		},
		"assets/main.js": &fstest.MapFile{
			Data: []byte(`console.log("vpn-ui-spa");`),
		},
	}

	const basePath = "/proxy-base/"
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("base_path", basePath)
		c.Next()
	})
	g := r.Group(basePath)
	NewSPAController(g, mockDist, "")

	// 1. Entry HTML rewrites base href + assets + injects runtime config
	reqIdx := httptest.NewRequest(http.MethodGet, basePath+"app/cores", nil)
	wIdx := httptest.NewRecorder()
	r.ServeHTTP(wIdx, reqIdx)
	if wIdx.Code != http.StatusOK {
		t.Fatalf("SPA fallback route status=%d body=%s", wIdx.Code, wIdx.Body.String())
	}
	body := wIdx.Body.String()
	if !strings.Contains(body, `<base href="/proxy-base/app/" />`) {
		t.Fatalf("base href not rewritten cleanly: %s", body)
	}
	if !strings.Contains(body, `src="/proxy-base/app/assets/main.js"`) {
		t.Fatalf("asset script path not rewritten: %s", body)
	}
	if !strings.Contains(body, `href="/proxy-base/manifest.webmanifest"`) {
		t.Fatalf("manifest link not rewritten: %s", body)
	}
	if !strings.Contains(body, `window.__VPN_UI_RUNTIME__=`) || !strings.Contains(body, `"basePath":"/proxy-base/"`) {
		t.Fatalf("runtime bootstrap script missing from SPA HTML: %s", body)
	}

	// 2. Existing static JS asset returns immutable headers and JS mime
	reqAsset := httptest.NewRequest(http.MethodGet, basePath+"app/assets/main.js", nil)
	wAsset := httptest.NewRecorder()
	r.ServeHTTP(wAsset, reqAsset)
	if wAsset.Code != http.StatusOK || !strings.Contains(wAsset.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("static asset response unexpected: code=%d cc=%q", wAsset.Code, wAsset.Header().Get("Cache-Control"))
	}

	// 3. Missing static JS asset MUST return 404 (not index.html)
	reqMissing := httptest.NewRequest(http.MethodGet, basePath+"app/assets/does-not-exist.js", nil)
	wMissing := httptest.NewRecorder()
	r.ServeHTTP(wMissing, reqMissing)
	if wMissing.Code != http.StatusNotFound {
		t.Fatalf("missing static asset expected 404, got %d", wMissing.Code)
	}
}
