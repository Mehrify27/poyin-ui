package xray

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestXraySpeedLimitEnvWiring guarantees the panel passes the speedlimits.json
// sidecar file via XRAY_SPEEDLIMIT_FILE when launching Xray-core.
func TestXraySpeedLimitEnvWiring(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "process.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse process.go: %v", err)
	}

	var foundSpeedLimitPath, foundEnvInjection bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name.Name == "GetSpeedLimitPath" {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "speedlimits.json") {
					foundSpeedLimitPath = true
					return false
				}
				return true
			})
		}
		if fn.Name.Name == "Start" {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "XRAY_SPEEDLIMIT_FILE=") {
					foundEnvInjection = true
					return false
				}
				return true
			})
		}
	}

	if !foundSpeedLimitPath {
		t.Fatalf("GetSpeedLimitPath in xray/process.go no longer references speedlimits.json")
	}
	if !foundEnvInjection {
		t.Fatalf("Start() in xray/process.go no longer injects XRAY_SPEEDLIMIT_FILE env var")
	}
}

// TestXrayBuildScriptForkAndSpliceGuard ensures the core build pipeline points
// at upstream Xray-core with our reproducible patches and refuses to compile
// without the speedlimit.DisableSplice (CanSpliceCopy = 3) patch.
func TestXrayBuildScriptForkAndSpliceGuard(t *testing.T) {
	scriptPath := filepath.Join("..", "build", "core", "build.sh")
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	script := string(raw)
	required := []string{
		"https://github.com/XTLS/Xray-core",
		"third_party/Xray-core/go.mod",
		"patches/xray",
		"stage_patched_src",
		"verify_xray_patches",
		"verify_speedlimit_splice_patch",
		"common/speedlimit/speedlimit.go",
		"app/dispatcher/default.go",
		"CanSpliceCopy",
		"speedlimit.DisableSplice",
	}
	for _, needle := range required {
		if !strings.Contains(script, needle) {
			t.Fatalf("build/core/build.sh missing required splice guard token %q", needle)
		}
	}
}

// TestXrayCoreSubmoduleSpliceDisableGuard verifies that either a pre-patched
// third_party/Xray-core checkout or the reproducible patch bundle in patches/xray
// defines speedlimit.DisableSplice (CanSpliceCopy = 3) and invokes it from both
// dispatcher seams (getLink and WrapLink).
func TestXrayCoreSubmoduleSpliceDisableGuard(t *testing.T) {
	coreRoot := filepath.Join("..", "third_party", "Xray-core")
	speedlimitGo := filepath.Join(coreRoot, "common", "speedlimit", "speedlimit.go")
	dispatcherGo := filepath.Join(coreRoot, "app", "dispatcher", "default.go")

	if _, err := os.Stat(speedlimitGo); err != nil {
		// Upstream clean submodule layout: verify the staged patch defines DisableSplice
		// and TestXrayPatchesApplyCleanly validates the full AST after applying patches.
		patchRaw, pErr := os.ReadFile(filepath.Join("..", "patches", "xray", "04-speedlimit-disable-splice.patch"))
		if pErr != nil {
			t.Fatalf("speedlimit.go absent in %s and patch missing: %v", speedlimitGo, pErr)
		}
		p := string(patchRaw)
		if !strings.Contains(p, "func DisableSplice(") || !strings.Contains(p, "CanSpliceCopy = 3") {
			t.Fatalf("04-speedlimit-disable-splice.patch must define DisableSplice setting CanSpliceCopy = 3")
		}
		if strings.Count(p, "speedlimit.DisableSplice(sessionInbound)") < 2 {
			t.Fatalf("04-speedlimit-disable-splice.patch must call speedlimit.DisableSplice in both dispatcher seams")
		}
		return
	}
	if _, err := os.Stat(dispatcherGo); err != nil {
		t.Skip("core submodule not checked out:", err)
	}

	fset := token.NewFileSet()
	slAST, err := parser.ParseFile(fset, speedlimitGo, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", speedlimitGo, err)
	}
	var hasDisableSplice, setsCanSpliceCopy bool
	for _, decl := range slAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "DisableSplice" || fn.Body == nil {
			continue
		}
		hasDisableSplice = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "CanSpliceCopy" && i < len(assign.Rhs) {
					if lit, ok := assign.Rhs[i].(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "3" {
						setsCanSpliceCopy = true
						return false
					}
				}
			}
			return true
		})
	}
	if !hasDisableSplice || !setsCanSpliceCopy {
		t.Fatalf("%s must define DisableSplice setting CanSpliceCopy = 3", speedlimitGo)
	}

	dispAST, err := parser.ParseFile(fset, dispatcherGo, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", dispatcherGo, err)
	}
	foundFuncs := map[string]bool{
		"getLink":  false,
		"WrapLink": false,
	}
	for _, decl := range dispAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if _, wanted := foundFuncs[fn.Name.Name]; !wanted {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "DisableSplice" {
				return true
			}
			if pkgIdent, ok := sel.X.(*ast.Ident); ok && pkgIdent.Name == "speedlimit" {
				foundFuncs[fn.Name.Name] = true
				return false
			}
			return true
		})
	}
	for name, ok := range foundFuncs {
		if !ok {
			t.Fatalf("%s: %s must invoke speedlimit.DisableSplice", dispatcherGo, name)
		}
	}
}
