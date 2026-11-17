package web

import (
	"io/fs"
	"path"
	"strings"
	"testing"
)

func TestEmbeddedSPABundleOfflineClean(t *testing.T) {
	sub, err := fs.Sub(spaDistFS, "frontend/dist")
	if err != nil {
		t.Fatalf("sub fs frontend/dist: %v", err)
	}
	indexBytes, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		t.Skipf("frontend/dist/index.html not built yet (%v); build web/frontend before release packaging", err)
	}
	if !strings.Contains(string(indexBytes), `id="app"`) {
		t.Fatalf("embedded index.html looks malformed")
	}

	// Verify NO external font/script CDNs anywhere in built SPA assets.
	forbiddenHosts := []string{
		"fonts.googleapis.com",
		"fonts.gstatic.com",
		"cdn.jsdelivr.net",
		"unpkg.com",
		"cdnjs.cloudflare.com",
	}
	walkErr := fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(path.Ext(p))
		if ext != ".html" && ext != ".js" && ext != ".css" {
			return nil
		}
		data, rErr := fs.ReadFile(sub, p)
		if rErr != nil {
			return rErr
		}
		lower := strings.ToLower(string(data))
		for _, host := range forbiddenHosts {
			if strings.Contains(lower, host) {
				t.Errorf("built SPA asset %s references forbidden external CDN %q", p, host)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk spaDistFS: %v", walkErr)
	}
}

func TestEmbeddedSVGBrandingAssets(t *testing.T) {
	for _, assetPath := range []string{"assets/img/logo.svg", "assets/img/icon.svg"} {
		data, err := assetsFS.ReadFile(assetPath)
		if err != nil {
			t.Fatalf("missing embedded vector asset %s: %v", assetPath, err)
		}
		if !strings.Contains(string(data), "<svg") {
			t.Errorf("%s does not contain an <svg element", assetPath)
		}
	}
}
