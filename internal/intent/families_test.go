package intent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

// A family is named in three places that have to agree: the contract's own
// constants, the list of families a contract may name, and the model's typed
// family the rules read. The policy engine casts between the second and the
// third, so a name that differs by a byte makes a declaration about a family
// nothing can find.
//
// Nothing asserted the agreement. This is the restated-predicate failure this
// repository keeps finding -- a grammar written twice comes to disagree with
// itself -- and the cost of the guard is one test.
func TestEveryFamilyAContractMayNameIsAFamilyTheModelHas(t *testing.T) {
	if len(knownFamilies) == 0 {
		t.Fatal("no family is known, so this test asserts nothing")
	}

	for _, family := range knownFamilies {
		t.Run(family, func(t *testing.T) {
			if !modelFamilies(t)[model.Family(family)] {
				t.Errorf("a contract may name %q and the model has no such family; the policy "+
					"engine casts between the two, so a declaration about it reaches no rule",
					family)
			}
		})
	}
}

// And the other direction, which is the one that goes quiet: a family the model
// has and a contract may not name is a family nobody can declare anything about,
// so every resource of it is reported against a contract that was never allowed
// to mention it.
//
// FamilyUnknown is excluded deliberately -- it is what a resource no mapper
// claimed is filed under, and a contract naming it would be declaring intent
// about the absence of interpretation.
func TestEveryFamilyTheModelHasIsAFamilyAContractMayName(t *testing.T) {
	known := map[string]bool{}
	for _, family := range knownFamilies {
		known[family] = true
	}

	for family := range modelFamilies(t) {
		if family == model.FamilyUnknown {
			continue
		}
		t.Run(string(family), func(t *testing.T) {
			if !known[string(family)] {
				t.Errorf("the model has %q and no contract may name it, so nothing can be "+
					"declared about a resource of that family", family)
			}
		})
	}
}

// TestEveryKnownFamilyIsNamedByAValidationArm covers the second half of the same
// agreement, and the half that fails permissively.
//
// validateFamilyFields decides which fields a family requires and which it
// refuses. Object storage reached its arm through `default:`, which was invisible
// with two families: a third added to knownFamilies and forgotten here would
// validate as an exposure family in silence, and the author of a contract
// constraining something no rule reads would be told nothing.
//
// Read from the source rather than exercised, because the arms are a switch and
// what this asserts is that the switch names every family -- not what any one of
// them does with it.
func TestEveryKnownFamilyIsNamedByAValidationArm(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "validate.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing validate.go: %v", err)
	}

	named := map[string]bool{}
	var found bool
	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.FuncDecl)
		if !ok || declaration.Name.Name != "validateFamilyFields" {
			return true
		}
		found = true
		ast.Inspect(declaration, func(inner ast.Node) bool {
			clause, ok := inner.(*ast.CaseClause)
			if !ok {
				return true
			}
			if len(clause.List) == 0 {
				// `default:`, which is what this test exists to refuse as a
				// family's only route into validation.
				return true
			}
			for _, expression := range clause.List {
				switch reference := expression.(type) {
				case *ast.Ident:
					named[familyValue(t, reference.Name)] = true
				case *ast.BasicLit:
					if text, err := strconv.Unquote(reference.Value); err == nil {
						named[text] = true
					}
				}
			}
			return true
		})
		return false
	})
	if !found {
		t.Fatal("validateFamilyFields is not in validate.go, so this guard reads nothing")
	}

	for _, family := range knownFamilies {
		if !named[family] {
			t.Errorf("a contract may name %q and no arm of validateFamilyFields names it, so it "+
				"inherits another family's required and forbidden fields", family)
		}
	}
}

// modelFamilies reads the model's family constants from its source.
//
// Parsed rather than listed, because a list here would be the model's family set
// written a fourth time -- the same defect this file exists to catch, one layer
// up. A constant block is the authority; restating it would make the guard agree
// with itself.
//
// Every file in the package, not just resource.go. This milestone's own
// convention is a file per family, so a family declared in the next one would
// have been invisible to the guard whose comment calls it the one that goes
// quiet -- and the floor below only fires if every constant moves at once.
func modelFamilies(t *testing.T) map[model.Family]bool {
	t.Helper()

	families := map[model.Family]bool{}
	for _, path := range packageFiles(t, filepath.Join("..", "model")) {
		collectFamilies(t, path, families)
	}
	if len(families) == 0 {
		t.Fatal("no family constant was found in the model, so this guard reads nothing")
	}
	return families
}

// collectFamilies records every Family constant one file declares.
func collectFamilies(t *testing.T, path string, into map[model.Family]bool) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
			return true
		}
		name, ok := spec.Type.(*ast.Ident)
		if !ok || name.Name != "Family" {
			return true
		}
		literal, ok := spec.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		if text, err := strconv.Unquote(literal.Value); err == nil {
			into[model.Family(text)] = true
		}
		return true
	})
}

// packageFiles lists a package's own source, test files excluded.
func packageFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}
	var out []string
	for _, path := range entries {
		if !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no source, so this guard reads nothing", dir)
	}
	return out
}

// familyValue resolves a family constant's name to the string a contract writes.
//
// Read from contract.go rather than switched on here. The first version of this
// helper listed the constants it knew and returned the identifier's name for the
// rest, so adding a family made the guard above report that family as having no
// validation arm when it had one -- the restated-predicate defect this whole file
// exists to catch, inside the guard against it.
func familyValue(t *testing.T, name string) string {
	t.Helper()
	for constant, value := range declaredFamilies(t) {
		if constant == name {
			return value
		}
	}
	return name
}

// declaredFamilies reads the contract's family constants by name and value.
func declaredFamilies(t *testing.T) map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "contract.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing the contract's families: %v", err)
	}

	families := map[string]string{}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
			return true
		}
		if !strings.HasPrefix(spec.Names[0].Name, "Family") {
			return true
		}
		literal, ok := spec.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		if text, err := strconv.Unquote(literal.Value); err == nil {
			families[spec.Names[0].Name] = text
		}
		return true
	})
	if len(families) == 0 {
		t.Fatal("no family constant was found in the contract, so this guard reads nothing")
	}
	return families
}

// TestEveryKnownFamilyIsJudgedBySomeRule closes the gap the validation guard
// cannot see.
//
// Naming a family in a validation arm says which fields it may carry. It says
// nothing about whether any rule reads them, and a review added a fourth family
// to all three places, shared an existing validation arm, wrote no rule, and
// kept the whole suite green. Coverage would report such a family honestly at
// runtime -- a declaration nothing exercised -- but a contract field that no rule
// can ever read is a promise this build cannot keep, and it should fail at build
// time.
//
// Read from the policy package's source, by the family constant each rule asks
// the graph for. A rule that judges a family calls graph.OfFamily with it.
func TestEveryKnownFamilyIsJudgedBySomeRule(t *testing.T) {
	judged := map[string]bool{}
	for _, path := range packageFiles(t, filepath.Join("..", "policy")) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for constant, value := range declaredFamilies(t) {
			if strings.Contains(string(raw), "OfFamily(model."+strings.Replace(constant, "Family", "Family", 1)+")") {
				judged[value] = true
			}
		}
	}
	if len(judged) == 0 {
		t.Fatal("no rule asks the graph for a family, so this guard reads nothing")
	}

	for _, family := range knownFamilies {
		if !judged[family] {
			t.Errorf("a contract may declare %q and no rule in internal/policy judges a resource "+
				"of that family, so the field is a promise this build cannot keep", family)
		}
	}
}
