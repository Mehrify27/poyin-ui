package controller

import (
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/config"

	"github.com/gin-gonic/gin"
)

// SPAController serves the decoupled Vue 3 Vite bundle under <basePath>app/ with
// dynamic webBasePath injection, immutable caching for hashed assets, and clean
// history-mode fallback that never masks API routes or missing asset files.
type SPAController struct {
	embedFS  fs.FS
	debugDir string
}

// NewSPAController registers SPA routes under <basePath>app on group g.
// embedFS must be rooted at the built dist directory (containing index.html).
func NewSPAController(g *gin.RouterGroup, embedFS fs.FS, debugDir string) *SPAController {
	s := &SPAController{
		embedFS:  embedFS,
		debugDir: debugDir,
	}
	g.GET("/app", s.redirectToSlash)
	g.HEAD("/app", s.redirectToSlash)
	g.GET("/app/*filepath", s.serve)
	g.HEAD("/app/*filepath", s.serve)
	return s
}

func (s *SPAController) redirectToSlash(c *gin.Context) {
	basePath := normalizeBasePath(c.GetString("base_path"))
	c.Redirect(http.StatusFound, basePath+"app/")
}

func (s *SPAController) activeFS() fs.FS {
	if config.IsDebug() && s.debugDir != "" {
		if info, err := os.Stat(s.debugDir); err == nil && info.IsDir() {
			if _, idxErr := os.Stat(path.Join(s.debugDir, "index.html")); idxErr == nil {
				return os.DirFS(s.debugDir)
			}
		}
	}
	return s.embedFS
}

func contentTypeForPath(rel string) string {
	ext := strings.ToLower(path.Ext(rel))
	switch ext {
	case ".js", ".mjs":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".woff2":
		return "font/woff2"
	case ".woff":
		return "font/woff"
	case ".ttf":
		return "font/ttf"
	case ".png":
		return "image/png"
	case ".json", ".webmanifest":
		return "application/json; charset=utf-8"
	default:
		if mt := mime.TypeByExtension(ext); mt != "" {
			return mt
		}
		return "application/octet-stream"
	}
}

func looksLikeAssetRequest(rel string) bool {
	if strings.HasPrefix(rel, "assets/") || strings.HasPrefix(rel, "icons/") {
		return true
	}
	ext := strings.ToLower(path.Ext(rel))
	switch ext {
	case ".js", ".mjs", ".css", ".map", ".woff", ".woff2", ".ttf", ".otf",
		".svg", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".json", ".webmanifest":
		return true
	}
	return false
}

func (s *SPAController) serve(c *gin.Context) {
	fsys := s.activeFS()
	if fsys == nil {
		c.String(http.StatusServiceUnavailable, "Frontend SPA filesystem unavailable")
		return
	}

	raw := strings.TrimPrefix(c.Param("filepath"), "/")
	cleaned := strings.TrimPrefix(path.Clean("/"+raw), "/")
	if cleaned == "." {
		cleaned = ""
	}

	if cleaned != "" && cleaned != "index.html" {
		if f, err := fsys.Open(cleaned); err == nil {
			defer func() { _ = f.Close() }()
			if info, statErr := f.Stat(); statErr == nil && !info.IsDir() {
				if cleaned == "offline.html" {
					s.serveTransformedHTML(c, fsys, cleaned)
					return
				}
				data, readErr := io.ReadAll(f)
				if readErr != nil {
					c.AbortWithStatus(http.StatusInternalServerError)
					return
				}
				if strings.HasPrefix(cleaned, "assets/") {
					c.Header("Cache-Control", "public, max-age=31536000, immutable")
				}
				c.Data(http.StatusOK, contentTypeForPath(cleaned), data)
				return
			}
		}

		// Missing static asset must fail with 404 instead of masquerading as index.html.
		if looksLikeAssetRequest(cleaned) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
	}

	s.serveTransformedHTML(c, fsys, "index.html")
}

func (s *SPAController) serveTransformedHTML(c *gin.Context, fsys fs.FS, file string) {
	rawBytes, err := fs.ReadFile(fsys, file)
	if err != nil {
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.String(http.StatusServiceUnavailable,
			"VPN-UI frontend assets are not built yet. Run: cd web/frontend && npm ci && npm run build")
		return
	}

	basePath := normalizeBasePath(c.GetString("base_path"))
	appBase := basePath + "app/"

	htmlStr := string(rawBytes)
	htmlStr = strings.ReplaceAll(htmlStr, "./assets/", appBase+"assets/")
	htmlStr = strings.ReplaceAll(htmlStr, "./icons/", appBase+"icons/")
	htmlStr = strings.ReplaceAll(htmlStr, "./manifest.webmanifest", basePath+"manifest.webmanifest")
	htmlStr = strings.ReplaceAll(htmlStr, "/__VPN_UI_APP_BASE__/", appBase)
	htmlStr = strings.ReplaceAll(htmlStr, "/__VPN_UI_BASE_PATH__/", basePath)

	runtimeCfg := gin.H{
		"basePath":     basePath,
		"appBasePath":  appBase,
		"apiBasePath":  basePath + "panel/api/",
		"wsPath":       basePath + "ws",
		"manifestUrl":  basePath + "manifest.webmanifest",
		"swUrl":        basePath + "sw.js",
		"version":      config.GetVersion(),
		"assetVersion": config.GetAssetVersion(),
	}
	runtimeJSON, _ := json.Marshal(runtimeCfg)
	injection := `<script id="vpn-ui-runtime">window.__VPN_UI_RUNTIME__=` + string(runtimeJSON) + `;</script>`
	if strings.Contains(htmlStr, "</head>") {
		htmlStr = strings.Replace(htmlStr, "</head>", "  "+injection+"\n</head>", 1)
	} else {
		htmlStr = injection + htmlStr
	}

	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(htmlStr))
}
