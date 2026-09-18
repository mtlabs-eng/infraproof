package providers_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryExportedDeclarationIsDocumented catches a defect this project has
// now made twice: a declaration inserted between a doc comment and the thing it
// documents, which detaches the comment silently. `go vet` does not report it,
// the build does not care, and the only symptom is that `go doc` prints a bare
// signature — which nobody runs during review.
//
// It is mechanised rather than eyeballed because the second occurrence proved
// that eyeballing does not survive a refactor.
func TestEveryExportedDeclarationIsDocumented(t *testing.T) {
	for _, directory := range ourPackageDirectories(t) {
		set := token.NewFileSet()
		packages, err := parser.ParseDir(set, directory, func(f fs.FileInfo) bool {
			return !strings.HasSuffix(f.Name(), "_test.go")
		}, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", directory, err)
		}

		for _, parsed := range packages {
			for _, file := range parsed.Files {
				for _, declaration := range file.Decls {
					name, documented, position := documentationOf(declaration)
					if name == "" || !ast.IsExported(exportedPart(name)) {
						continue
					}
					if !documented {
						t.Errorf("%s: %s is exported and carries no doc comment",
							set.Position(position), name)
					}
				}
			}
		}
	}
}

// documentationOf reports a declaration's name, whether it carries a doc
// comment, and where it is.
func documentationOf(declaration ast.Decl) (string, bool, token.Pos) {
	switch typed := declaration.(type) {
	case *ast.FuncDecl:
		name := typed.Name.Name
		if typed.Recv != nil && len(typed.Recv.List) > 0 {
			name = receiverName(typed.Recv.List[0].Type) + "." + name
		}
		return name, typed.Doc != nil, typed.Pos()
	case *ast.GenDecl:
		if typed.Tok == token.IMPORT {
			return "", false, 0
		}
		// A parenthesised group documents its members individually or as a
		// group; either is enough.
		if typed.Lparen.IsValid() {
			return "", false, 0
		}
		if len(typed.Specs) == 0 {
			return "", false, 0
		}
		switch spec := typed.Specs[0].(type) {
		case *ast.TypeSpec:
			return spec.Name.Name, typed.Doc != nil, typed.Pos()
		case *ast.ValueSpec:
			if len(spec.Names) == 0 {
				return "", false, 0
			}
			return spec.Names[0].Name, typed.Doc != nil, typed.Pos()
		}
	}
	return "", false, 0
}

// exportedPart returns the part of a name that decides whether it is exported:
// the method name for a method, the name itself otherwise.
func exportedPart(name string) string {
	if _, method, found := strings.Cut(name, "."); found {
		return method
	}
	return name
}

func receiverName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.StarExpr:
		return receiverName(typed.X)
	case *ast.Ident:
		return typed.Name
	case *ast.IndexExpr:
		return receiverName(typed.X)
	default:
		return "?"
	}
}

// ourPackageDirectories returns every directory in this module holding Go code.
func ourPackageDirectories(t *testing.T) []string {
	t.Helper()

	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	var directories []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			directories = append(directories, filepath.Clean(line))
		}
	}
	if len(directories) < 5 {
		t.Fatalf("expected several packages, got %v", directories)
	}
	return directories
}
