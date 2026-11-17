package locale

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

var expectedLocales = []string{
	"ar-EG",
	"en-US",
	"fa-IR",
	"zh-CN",
	"zh-TW",
	"ja-JP",
	"ru-RU",
	"vi-VN",
	"es-ES",
	"id-ID",
	"uk-UA",
	"tr-TR",
	"pt-BR",
}

func flattenAnyMap(prefix string, src map[string]any, dst map[string]string) {
	for k, v := range src {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch typed := v.(type) {
		case map[string]any:
			flattenAnyMap(key, typed, dst)
		default:
			dst[key] = fmt.Sprint(typed)
		}
	}
}

func TestExportedJSONLocalesMatchTOML(t *testing.T) {
	transDir := filepath.Join("..", "translation")
	jsonDir := filepath.Join("..", "frontend", "src", "locales")
	goPlaceholderRe := regexp.MustCompile(`\{\{\s*\.([A-Za-z0-9_]+)\s*\}\}`)

	criticalKeys := []string{
		"menu.dashboard",
		"menu.inbounds",
		"menu.core",
		"pages.login.title",
		"pwa.installApp",
		"pwa.offlineTitle",
		"spa.appTitle",
		"spa.inbounds.flow",
		"spa.inbounds.perInboundTraffic",
		"spa.inbounds.awg2Title",
		"spa.inbounds.hysteria2Title",
		"spa.core.sidecarUpdaterTitle",
		"spa.core.networkTuningTitle",
	}

	for _, bcp47 := range expectedLocales {
		tomlFile := filepath.Join(transDir, "translate."+strings.ReplaceAll(bcp47, "-", "_")+".toml")
		jsonFile := filepath.Join(jsonDir, bcp47+".json")

		tomlRaw, err := os.ReadFile(tomlFile)
		if err != nil {
			t.Fatalf("read %s: %v", tomlFile, err)
		}
		jsonRaw, err := os.ReadFile(jsonFile)
		if err != nil {
			t.Fatalf("read %s: %v", jsonFile, err)
		}

		var tomlMap map[string]any
		if err := toml.Unmarshal(tomlRaw, &tomlMap); err != nil {
			t.Fatalf("parse %s: %v", tomlFile, err)
		}
		var jsonMap map[string]any
		if err := json.Unmarshal(jsonRaw, &jsonMap); err != nil {
			t.Fatalf("parse %s: %v", jsonFile, err)
		}

		flatToml := make(map[string]string)
		flatJSON := make(map[string]string)
		flattenAnyMap("", tomlMap, flatToml)
		flattenAnyMap("", jsonMap, flatJSON)

		if len(flatToml) != len(flatJSON) {
			t.Errorf("%s: key count mismatch TOML=%d JSON=%d", bcp47, len(flatToml), len(flatJSON))
		}

		for k, tv := range flatToml {
			jv, ok := flatJSON[k]
			if !ok {
				t.Errorf("%s: missing key in exported JSON: %s", bcp47, k)
				continue
			}
			expected := goPlaceholderRe.ReplaceAllString(tv, `{$1}`)
			if strings.Contains(expected, "@") {
				expected = strings.ReplaceAll(expected, "@", "{'@'}")
			}
			if jv != expected {
				t.Errorf("%s (%s): conversion mismatch\ngot:  %q\nwant: %q", bcp47, k, jv, expected)
			}
			if strings.Contains(jv, "{{") || strings.Contains(jv, "}}") {
				t.Errorf("%s (%s): unconverted Go template delimiter in %q", bcp47, k, jv)
			}
		}

		for _, reqKey := range criticalKeys {
			if strings.TrimSpace(flatJSON[reqKey]) == "" {
				t.Errorf("%s: missing critical exported key %q", bcp47, reqKey)
			}
		}
	}
}
