// Package locale provides internationalization (i18n) support for the vpn-ui web panel,
// including translation loading, localization, and middleware for web and bot interfaces.
package locale

import (
	"embed"
	"io/fs"
	"os"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"

	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/text/language"
)

var (
	i18nMu              sync.RWMutex
	i18nBundle          *i18n.Bundle
	LocalizerWeb        *i18n.Localizer
	LocalizerBot        *i18n.Localizer
	localizerDefault    *i18n.Localizer // always English; fallback for keys missing in the active locale
	savedSettingService SettingService
)

// I18nType represents the type of interface for internationalization.
type I18nType string

const (
	Bot I18nType = "bot" // Bot interface type
	Web I18nType = "web" // Web interface type
)

// SettingService interface defines methods for accessing locale settings.
type SettingService interface {
	GetTgLang() (string, error)
}

func newI18nBundle() *i18n.Bundle {
	bundle := i18n.NewBundle(language.MustParse("en-US"))
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	return bundle
}

func diskTranslationFS() (fs.FS, bool) {
	if info, err := os.Stat("web/translation"); err == nil && info.IsDir() {
		return os.DirFS("web"), true
	}
	if info, err := os.Stat("../translation"); err == nil && info.IsDir() {
		return os.DirFS(".."), true
	}
	if info, err := os.Stat("translation"); err == nil && info.IsDir() {
		return os.DirFS("."), true
	}
	return nil, false
}

// InitLocalizer initializes the internationalization system with embedded translation files.
// In debug mode (VPNUI_DEBUG=true), translation files are loaded from disk when available
// and reloaded on demand in LocalizerMiddleware so UI copy edits take effect without restart.
func InitLocalizer(i18nFS embed.FS, settingService SettingService) error {
	bundle := newI18nBundle()

	loadedFromDisk := false
	if config.IsDebug() {
		if _, ok := diskTranslationFS(); ok {
			if err := loadTranslationsFromDisk(bundle); err != nil {
				logger.Warning("debug i18n load from disk failed, falling back to embedded FS:", err)
				bundle = newI18nBundle()
			} else {
				loadedFromDisk = true
			}
		}
	}
	if !loadedFromDisk {
		if err := parseTranslationFiles(i18nFS, bundle); err != nil {
			return err
		}
	}

	i18nMu.Lock()
	i18nBundle = bundle
	// English fallback localizer: strings that exist only in en_US resolve
	// through this instead of rendering blank in another language.
	localizerDefault = i18n.NewLocalizer(bundle, "en-US")
	savedSettingService = settingService
	i18nMu.Unlock()

	// setup bot locale
	if err := initTGBotLocalizer(settingService); err != nil {
		return err
	}

	return nil
}

// createTemplateData creates a template data map from parameters with optional separator.
func createTemplateData(params []string, separator ...string) map[string]any {
	var sep string = "=="
	if len(separator) > 0 {
		sep = separator[0]
	}

	templateData := make(map[string]any)
	for _, param := range params {
		parts := strings.SplitN(param, sep, 2)
		templateData[parts[0]] = parts[1]
	}

	return templateData
}

// I18n retrieves a localized message for the given key and type.
// It supports both bot and web contexts, with optional template parameters.
// Returns the localized message or an empty string if localization fails.
func I18n(i18nType I18nType, key string, params ...string) string {
	var localizer *i18n.Localizer
	var fallback *i18n.Localizer

	i18nMu.RLock()
	switch i18nType {
	case "bot":
		localizer = LocalizerBot
	case "web":
		localizer = LocalizerWeb
	default:
		i18nMu.RUnlock()
		logger.Errorf("Invalid type for I18n: %s", i18nType)
		return ""
	}
	fallback = localizerDefault
	i18nMu.RUnlock()

	templateData := createTemplateData(params)

	if localizer == nil {
		// Fallback to key if localizer not ready; prevents nil panic on pages like sub
		return key
	}

	msg, err := localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    key,
		TemplateData: templateData,
	})
	if err != nil {
		// Key missing/failed in the active locale. Fall back to English so a
		// string that exists only in en_US shows readable text instead of a
		// blank (this is the common case for not-yet-translated keys, so it is
		// not logged). Only if English also fails do we surface the key itself.
		if fallback != nil {
			if enMsg, enErr := fallback.Localize(&i18n.LocalizeConfig{
				MessageID:    key,
				TemplateData: templateData,
			}); enErr == nil {
				return enMsg
			}
		}
		logger.Errorf("Failed to localize message: %v", err)
		return key
	}

	return msg
}

// initTGBotLocalizer initializes the bot localizer with the configured language.
func initTGBotLocalizer(settingService SettingService) error {
	if settingService == nil {
		return nil
	}
	botLang, err := settingService.GetTgLang()
	if err != nil {
		return err
	}

	i18nMu.Lock()
	bundle := i18nBundle
	if bundle != nil {
		LocalizerBot = i18n.NewLocalizer(bundle, botLang)
	}
	i18nMu.Unlock()
	return nil
}

// LocalizerMiddleware returns a Gin middleware that sets up localization for web requests.
// It determines the user's language from cookies or Accept-Language header,
// creates a localizer instance, and stores it in the Gin context for use in handlers.
// Also provides the I18n function in the context for template rendering.
func LocalizerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		i18nMu.RLock()
		needInit := i18nBundle == nil
		svc := savedSettingService
		i18nMu.RUnlock()

		if config.IsDebug() {
			if _, ok := diskTranslationFS(); ok {
				fresh := newI18nBundle()
				if err := loadTranslationsFromDisk(fresh); err != nil {
					logger.Warning("debug i18n reload failed:", err)
				} else {
					var botLoc *i18n.Localizer
					if svc != nil {
						if botLang, err := svc.GetTgLang(); err == nil {
							botLoc = i18n.NewLocalizer(fresh, botLang)
						}
					}
					i18nMu.Lock()
					i18nBundle = fresh
					localizerDefault = i18n.NewLocalizer(fresh, "en-US")
					if botLoc != nil {
						LocalizerBot = botLoc
					}
					i18nMu.Unlock()
					needInit = false
				}
			}
		}

		// Ensure bundle is initialized so creating a Localizer won't panic
		if needInit {
			fresh := newI18nBundle()
			if err := loadTranslationsFromDisk(fresh); err != nil {
				logger.Warning("i18n lazy load failed:", err)
			}
			i18nMu.Lock()
			if i18nBundle == nil {
				i18nBundle = fresh
				localizerDefault = i18n.NewLocalizer(fresh, "en-US")
			}
			i18nMu.Unlock()
		}

		var lang string
		if cookie, err := c.Request.Cookie("lang"); err == nil {
			lang = cookie.Value
		} else {
			lang = c.GetHeader("Accept-Language")
		}

		i18nMu.Lock()
		bundle := i18nBundle
		loc := i18n.NewLocalizer(bundle, lang)
		LocalizerWeb = loc
		i18nMu.Unlock()

		c.Set("localizer", loc)
		c.Set("I18n", I18n)
		c.Next()
	}
}

// loadTranslationsFromDisk attempts to load translation files from the local filesystem.
func loadTranslationsFromDisk(bundle *i18n.Bundle) error {
	root, ok := diskTranslationFS()
	if !ok {
		root = os.DirFS("web")
	}
	return fs.WalkDir(root, "translation", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(root, path)
		if err != nil {
			return err
		}
		_, err = bundle.ParseMessageFileBytes(data, path)
		return err
	})
}

// parseTranslationFiles parses embedded translation files and adds them to the i18n bundle.
func parseTranslationFiles(i18nFS embed.FS, i18nBundle *i18n.Bundle) error {
	err := fs.WalkDir(i18nFS, "translation",
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			data, err := i18nFS.ReadFile(path)
			if err != nil {
				return err
			}

			_, err = i18nBundle.ParseMessageFileBytes(data, path)
			return err
		})
	if err != nil {
		return err
	}

	return nil
}
