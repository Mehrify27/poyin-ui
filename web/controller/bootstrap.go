package controller

import (
	"runtime"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// SupportedLocale describes one panel translation supported by both the
// legacy templates and the decoupled Vue 3 SPA.
type SupportedLocale struct {
	Code string `json:"code"`
	Name string `json:"name"`
	Icon string `json:"icon"`
	RTL  bool   `json:"rtl"`
}

var supportedLocales = []SupportedLocale{
	{Code: "ar-EG", Name: "العربية", Icon: "🇪🇬", RTL: true},
	{Code: "en-US", Name: "English", Icon: "🇺🇸", RTL: false},
	{Code: "fa-IR", Name: "فارسی", Icon: "🇮🇷", RTL: true},
	{Code: "zh-CN", Name: "简体中文", Icon: "🇨🇳", RTL: false},
	{Code: "zh-TW", Name: "繁體中文", Icon: "🇹🇼", RTL: false},
	{Code: "ja-JP", Name: "日本語", Icon: "🇯🇵", RTL: false},
	{Code: "ru-RU", Name: "Русский", Icon: "🇷🇺", RTL: false},
	{Code: "vi-VN", Name: "Tiếng Việt", Icon: "🇻🇳", RTL: false},
	{Code: "es-ES", Name: "Español", Icon: "🇪🇸", RTL: false},
	{Code: "id-ID", Name: "Indonesian", Icon: "🇮🇩", RTL: false},
	{Code: "uk-UA", Name: "Український", Icon: "🇺🇦", RTL: false},
	{Code: "tr-TR", Name: "Türkçe", Icon: "🇹🇷", RTL: false},
	{Code: "pt-BR", Name: "Português", Icon: "🇧🇷", RTL: false},
}

// BootstrapController exposes runtime bootstrap configuration, authenticated
// user/permission/reseller state, and host protocol capabilities for the SPA
// without breaking custom webBasePath reverse-proxy setups.
type BootstrapController struct {
	settingService service.SettingService
	serverService  service.ServerService
	coreService    service.CoreService
}

// NewBootstrapController creates a BootstrapController and binds public
// runtime bootstrap routes directly under basePath.
func NewBootstrapController(g *gin.RouterGroup) *BootstrapController {
	a := &BootstrapController{}
	g.GET("/api/bootstrap", a.GetBootstrap)
	return a
}

func normalizeBasePath(raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// GetBootstrap handles GET <basePath>api/bootstrap (and /panel/api/server/bootstrap).
// Unauthenticated requests only receive safe shell metadata (basePath, version,
// PWA URLs, supported locales); authenticated requests receive the full session,
// permission, reseller, UI default, and protocol capability context.
func (a *BootstrapController) GetBootstrap(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	payload := a.BuildBootstrapPayload(c)
	jsonObj(c, payload, nil)
}

// GetCapabilities handles GET <basePath>panel/api/server/capabilities (auth-gated).
func (a *BootstrapController) GetCapabilities(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	user := session.GetLoginUser(c)
	includeCorePaths := user != nil && user.Can(model.PermCoreSettings)
	jsonObj(c, a.buildCapabilities(includeCorePaths), nil)
}

// BuildBootstrapPayload gathers runtime shell metadata and, if logged in, the
// authenticated operator/reseller context matching everything legacy templates
// inject into server-rendered HTML pages.
func (a *BootstrapController) BuildBootstrapPayload(c *gin.Context) gin.H {
	basePath := normalizeBasePath(c.GetString("base_path"))
	appBasePath := basePath + "app/"
	loggedIn := session.IsLogin(c)

	out := gin.H{
		"version":          config.GetVersion(),
		"assetVersion":     config.GetAssetVersion(),
		"basePath":         basePath,
		"appBasePath":      appBasePath,
		"apiBasePath":      basePath + "panel/api/",
		"wsPath":           basePath + "ws",
		"authenticated":    loggedIn,
		"defaultTheme":     "dark",
		"defaultLocale":    "en-US",
		"supportedLocales": supportedLocales,
		"host":             browserHost(c),
		"pwa": gin.H{
			"manifestUrl": basePath + "manifest.webmanifest",
			"swUrl":       basePath + "sw.js",
			"scope":       appBasePath,
		},
	}

	if !loggedIn {
		return out
	}

	user := session.GetLoginUser(c)
	if user == nil {
		out["authenticated"] = false
		return out
	}

	out["user"] = gin.H{
		"id":              user.Id,
		"username":        user.Username,
		"isSuperAdmin":    user.IsSuperAdmin,
		"isReseller":      user.IsReseller,
		"twoFactorEnable": currentTwoFactorEnabled(c),
	}
	out["perms"] = templatePerms(c)
	out["reseller"] = templateReseller(c)
	out["landingPath"] = a.resolveLandingRoute(c)

	host := browserHost(c)
	legacyForm, _ := a.settingService.GetLegacyInboundForm()
	serverName, _ := a.settingService.GetServerName()
	defaults, err := a.settingService.GetDefaultSettings(host, user.Can(model.PermPanelSettings))
	if err != nil {
		defaults = map[string]any{}
	}

	uiData := gin.H{
		"legacyInboundForm": legacyForm,
		"serverName":        serverName,
		"defaults":          defaults,
	}
	if overviewAccess(user) || user.Can(model.PermPanelSettings) {
		panelName, domain := a.serverService.BackupNameParts(host)
		tgEnabled, _ := a.settingService.GetTgbotEnabled()
		certFile, _ := a.settingService.GetCertFile()
		subCertFile, _ := a.settingService.GetSubCertFile()
		uiData["backupPanelName"] = panelName
		uiData["backupDomain"] = domain
		uiData["telegramEnabled"] = tgEnabled
		uiData["panelTlsEnabled"] = strings.TrimSpace(certFile) != ""
		uiData["subTlsEnabled"] = strings.TrimSpace(subCertFile) != ""
		out["donate"] = donateAddresses
	}
	out["ui"] = uiData
	out["capabilities"] = a.buildCapabilities(user.Can(model.PermCoreSettings))
	return out
}

func (a *BootstrapController) resolveLandingRoute(c *gin.Context) string {
	// landingPath in permission.go returns "<basePath>panel/..." — map it to SPA path cleanly.
	basePath := normalizeBasePath(c.GetString("base_path"))
	full := landingPath(c)
	rel := strings.TrimPrefix(full, basePath+"panel")
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return "/"
	}
	return "/" + rel
}

func (a *BootstrapController) buildCapabilities(includePaths bool) gin.H {
	engines := a.coreService.GetDaemonVersions()
	protocolCaps := gin.H{
		"awgAvailable":       false,
		"awgKernel":          false,
		"awgUserspace":       false,
		"awgMode":            "missing",
		"hysteria2Available": false,
		"mtprotoAvailable":   false,
		"wireguardKernel":    false,
		"greKernel":          false,
		"xrayAvailable":      false,
		"xrayVersion":        "",
		"xrayPatched":        false,
	}

	safeEngines := make([]service.ProtocolEngineInfo, 0, len(engines))
	for _, eng := range engines {
		switch eng.ID {
		case "xray":
			protocolCaps["xrayAvailable"] = eng.Available
			protocolCaps["xrayVersion"] = eng.Version
			protocolCaps["xrayPatched"] = eng.CustomPatched
		case "hysteria2":
			protocolCaps["hysteria2Available"] = eng.Available
			protocolCaps["hysteria2Version"] = eng.Version
		case "mtproto":
			protocolCaps["mtprotoAvailable"] = eng.Available
			protocolCaps["mtprotoVersion"] = eng.Version
		case "wgc":
			protocolCaps["wireguardKernel"] = eng.Available
		case "gre":
			protocolCaps["greKernel"] = eng.Available
		case "awg":
			awgKernel := eng.KernelLoaded
			awgUserspace := eng.BinaryPath != "" || eng.Source == "bundled" || eng.Source == "custom-override" ||
				strings.Contains(strings.ToLower(eng.Detail), "amneziawg-go")
			mode := "missing"
			switch {
			case awgKernel && awgUserspace:
				mode = "kernel+userspace"
			case awgUserspace:
				mode = "userspace"
			case awgKernel:
				mode = "kernel"
			}
			protocolCaps["awgAvailable"] = eng.Available
			protocolCaps["awgKernel"] = awgKernel
			protocolCaps["awgUserspace"] = awgUserspace
			protocolCaps["awgMode"] = mode
			protocolCaps["awgVersion"] = eng.Version
		}

		if !includePaths {
			redacted := eng
			redacted.BinaryPath = ""
			redacted.Banner = ""
			redacted.HelperTools = nil
			safeEngines = append(safeEngines, redacted)
		} else {
			safeEngines = append(safeEngines, eng)
		}
	}

	certFile, _ := a.settingService.GetCertFile()
	subCertFile, _ := a.settingService.GetSubCertFile()
	tgEnabled, _ := a.settingService.GetTgbotEnabled()

	return gin.H{
		"os":               runtime.GOOS,
		"arch":             runtime.GOARCH,
		"provisioned":      a.coreService.IsProvisioned(),
		"missingProtocols": a.coreService.MissingProtocols(),
		"protocols":        protocolCaps,
		"panelTlsEnabled":  strings.TrimSpace(certFile) != "",
		"subTlsEnabled":    strings.TrimSpace(subCertFile) != "",
		"telegramEnabled":  tgEnabled,
		"engines":          safeEngines,
	}
}
