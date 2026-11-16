package xray

import (
	"archive/tar"
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestXrayPatchesInventory ensures all required reproducible patches exist in patches/xray
// and carry their essential implementation symbols.
func TestXrayPatchesInventory(t *testing.T) {
	patchDir := filepath.Join("..", "patches", "xray")
	checks := []struct {
		file     string
		required []string
	}{
		{
			file:     "01-shadowsocks-cipher-fallback.patch",
			required: []string{"infra/conf/shadowsocks.go", "cipher := user.Cipher", "cipher = v.Cipher"},
		},
		{
			file:     "02-speedlimit-rate.patch",
			required: []string{"common/speedlimit/speedlimit.go", "func LookupSession", "speedlimit.NewWriter", "speedlimit.NewReader"},
		},
		{
			file:     "03-speedlimit-iplimit.patch",
			required: []string{"common/speedlimit/iplimit.go", "func Admit(", "speedlimit.Admit(ctx)"},
		},
		{
			file:     "04-speedlimit-disable-splice.patch",
			required: []string{"common/speedlimit/splice_test.go", "func DisableSplice(", "CanSpliceCopy = 3", "speedlimit.DisableSplice(sessionInbound)"},
		},
		{
			file:     "05-anytls-tuic-naive.patch",
			required: []string{"proxy/anytls/inbound.go", "proxy/tuic/inbound.go", "proxy/naive/server.go", "common/singbridge", `"anytls"`, `"tuic"`, `"naive"`},
		},
		{
			file:     "06-legacy-reverse.patch",
			required: []string{"infra/conf/xray.go", `-		return nil, errors.PrintRemovedFeatureError(`},
		},
	}

	for _, tc := range checks {
		raw, err := os.ReadFile(filepath.Join(patchDir, tc.file))
		if err != nil {
			t.Fatalf("missing required Xray patch %s: %v", tc.file, err)
		}
		text := string(raw)
		if strings.Contains(text, "\r\n") {
			t.Fatalf("patch %s contains CRLF line endings; normalize to LF so Linux git apply works cleanly", tc.file)
		}
		for _, needle := range tc.required {
			if !strings.Contains(text, needle) {
				t.Fatalf("patch %s missing expected token %q", tc.file, needle)
			}
		}
	}
}

// TestXrayPatchesApplyCleanly extracts the pinned third_party/Xray-core commit into a
// throwaway temp directory (never modifying the submodule), applies patches/xray/*.patch
// sequentially, and verifies the resulting AST still preserves every vpn-ui patch.
func TestXrayPatchesApplyCleanly(t *testing.T) {
	coreRoot := filepath.Join("..", "third_party", "Xray-core")
	if _, err := os.Stat(filepath.Join(coreRoot, "go.mod")); err != nil {
		t.Skip("third_party/Xray-core submodule not checked out:", err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary unavailable:", err)
	}

	archiveCmd := exec.Command("git", "-C", coreRoot, "archive", "--format=tar", "HEAD")
	var tarBuf bytes.Buffer
	var errBuf bytes.Buffer
	archiveCmd.Stdout = &tarBuf
	archiveCmd.Stderr = &errBuf
	if err := archiveCmd.Run(); err != nil {
		t.Fatalf("git archive third_party/Xray-core failed: %v (%s)", err, errBuf.String())
	}

	stageDir := t.TempDir()
	tr := tar.NewReader(&tarBuf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read git archive tar: %v", err)
		}
		cleanRel := filepath.Clean(hdr.Name)
		if cleanRel == "." || strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
			continue
		}
		target := filepath.Join(stageDir, cleanRel)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatalf("mkdir parent %s: %v", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				t.Fatalf("open %s: %v", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				t.Fatalf("write %s: %v", target, err)
			}
			_ = f.Close()
		}
	}

	initCmd := exec.Command("git", "-C", stageDir, "init", "-q")
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("git init %s: %v (%s)", stageDir, err, string(out))
	}

	patchDir, err := filepath.Abs(filepath.Join("..", "patches", "xray"))
	if err != nil {
		t.Fatalf("abs patchDir: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(patchDir, "*.patch"))
	if err != nil {
		t.Fatalf("glob patches: %v", err)
	}
	sort.Strings(matches)
	if len(matches) < 6 {
		t.Fatalf("expected >= 6 patches in %s, got %d", patchDir, len(matches))
	}
	for _, p := range matches {
		cmd := exec.Command("git", "-C", stageDir, "apply", p)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git apply %s failed: %v\n%s", filepath.Base(p), err, string(out))
		}
	}

	// Verify splice guard & dispatcher hooks on the resulting patched AST.
	assertSpeedlimitPatchedAST(t, stageDir)
}

func assertSpeedlimitPatchedAST(t *testing.T, stageDir string) {
	t.Helper()
	fset := token.NewFileSet()
	slPath := filepath.Join(stageDir, "common", "speedlimit", "speedlimit.go")
	slAST, err := parser.ParseFile(fset, slPath, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", slPath, err)
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
		t.Fatalf("%s must define DisableSplice setting CanSpliceCopy = 3", slPath)
	}

	dispPath := filepath.Join(stageDir, "app", "dispatcher", "default.go")
	dispAST, err := parser.ParseFile(fset, dispPath, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", dispPath, err)
	}
	spliceCalls := map[string]bool{"getLink": false, "WrapLink": false}
	admitCalls := map[string]bool{"Dispatch": false, "DispatchLink": false}
	for _, decl := range dispAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "speedlimit" {
				return true
			}
			if _, ok := spliceCalls[fn.Name.Name]; ok && sel.Sel.Name == "DisableSplice" {
				spliceCalls[fn.Name.Name] = true
			}
			if _, ok := admitCalls[fn.Name.Name]; ok && sel.Sel.Name == "Admit" {
				admitCalls[fn.Name.Name] = true
			}
			return true
		})
	}
	for name, ok := range spliceCalls {
		if !ok {
			t.Fatalf("%s: %s must invoke speedlimit.DisableSplice", dispPath, name)
		}
	}
	for name, ok := range admitCalls {
		if !ok {
			t.Fatalf("%s: %s must invoke speedlimit.Admit", dispPath, name)
		}
	}
}
