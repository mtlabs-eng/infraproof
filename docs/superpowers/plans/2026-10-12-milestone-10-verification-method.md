# Milestone 10: verification method — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every finding carries `verification_steps` — one `{fact, method}` per fact its verdict rests on — and no mapper presents a defaulted, table-derived or policy-interpreted value as one the plan stated.

**Architecture:** The method is born on `model.Fact[T]`: `model.Known` requires one, so the compiler lists every site a mapper must decide. The policy layer copies a fact's method into a step and adds the steps only it knows (contract comparison, action classification, the database→gate hop). The Evidence Bundle gains a versioned, validated, canonically ordered `verification_steps` field in `1.3`; it reaches no decision.

**Tech Stack:** Go (stdlib only), Terraform 1.14 for one real offline plan fixture.

**Spec:** `docs/milestones/10-verification-method.md` (amended by Task 0 — read both).

## Global Constraints

- Never run `terraform apply` or `terraform destroy`. `terraform plan -refresh=false` with fake credentials only; no cloud contacted.
- Never read, request, store or print cloud credentials.
- The method is **never load-bearing**: no decision, disposition or exit code depends on it.
- A step carries no value — a fact path and a method only.
- Closed method set, exactly: `plan-stated-value`, `provider-default`, `policy-document-interpreted`, `reference-resolved`, `documented-table`, `plan-action`, `intent-comparison`.
- Bundle `1.3` requires ≥1 step per finding; `1.2` and earlier are valid without the field; a present field is validated whatever the version.
- Universal rules in `internal/policy` import no provider package and name no cloud (`internal/policy/boundary_test.go` enforces this).
- The 226 goldens under `internal/verify/testdata/baseline/` are **not re-recorded**. They are the milestone 09 verdict baseline and stay byte-for-byte as they are.
- Write the test first, run it, see it fail for the stated reason, then implement.
- Never delete, weaken or skip a valid test to make the suite pass.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Work on branch `milestone-10-verification-method`, never on `main`.

## Review Focus

1. **A KNOWN fact with an empty method reaching a bundle** — must fail bundle validation (render returns an error), never render as a valid step. Pinned in Task 7 Step 1 (`TestAZeroMethodNeverReachesABundle`).
2. **A disjunctive grant proven by both a stated and an interpreted source** (AWS ACL *and* policy both public; GCP `allUsers` member *and* public `policy_data`) — the method is the stated one, because the cited proof is the stated one. Pinned in Task 4 Step 1 and Task 5 Step 1.
3. **A GCP firewall whose grant is cancelled by a deny whose own `direction` is defaulted** — the resulting `Known(false)` is `provider-default`, because the verdict rests on that deny's default. Pinned in Task 5 Step 1.
4. **A gate that admits every port in front of a database with a known port** — the port did not enter the verdict, so no `database.port` step. Pinned in Task 7 Step 1 (`TestThePortStepAppearsOnlyWhenThePortDecided`).
5. **A `1.2`-declared bundle carrying a malformed step** — rejected, the same rule `intent_digest` follows. Pinned in Task 1 Step 1.

---

## Spec amendments found while planning

Measured against `3b50544`; Task 0 writes them into the milestone file. **The user must confirm these before Task 0 runs.**

1. **AWS unwritten `ingress` is not a `provider-default` site.** `internal/providers/aws/network.go:80` uses `declared.Unwritten(subject, "ingress")` only to suppress `unread`; `Known(false)` requires `stated` (`:115`), which is false when `ingress` is unwritten, and `Known(true)` rests on a stated separate rule. The default never decides a KNOWN fact, so every AWS network KNOWN is `plan-stated-value`.
2. **`PortInferred` is kept, not absorbed.** Azure's port comes from `portOf(subject.Type)` — a table, so `documented-table` — but `internal/providers/azure/database.go:310-313` documents it as *certain*, which is why `PortInferred` is false there. Method answers "where did the value come from"; `PortInferred` answers "is it a default the deployment could differ from". Two questions, two fields. `DATABASE_PORT_INFERRED` keeps reading `PortInferred`.
3. **A disjunctive grant takes the method of the proof the mapper cites.** AWS storage cites the first unblocked granting channel (ACL before policy, `aws.go:204-208`); GCP storage settles on any granting binding. A stated grant wins over an interpreted one. A conjunctive fact (GCP rule + deny directions) takes the method of the input that is not stated.
4. **Criterion 8 is proven by the frozen goldens, not by re-recording them.** The baseline test strips `verification_steps` and restores `schema_version: "1.2"` before comparing, so the 226 files stay exactly as milestone 09 left them. The 23 plan fixtures with no golden are compared by building binaries at `3b50544` and at the branch head (Task 9). The throwaway recording script is dropped.
5. **The GCP `ipv4_enabled` default reaches a finding only when `authorized_networks` is written and `ipv4_enabled` is not.** No committed fixture has that shape (`implicit` writes no `ip_configuration`, so nothing is authorized and nothing is reachable). Task 5 adds it as real `terraform plan` output.
6. **The `database.port` step needs a signal the policy does not have.** `rangesReach` gains a third result, `byPort`, true only when a known port's containment decided reachability and no range covered every usable port.

---

## File map

| File | Responsibility | Task |
| --- | --- | --- |
| `docs/milestones/10-verification-method.md` | spec amendments; limitations as built | 0, 9 |
| `internal/evidence/bundle.go` | `VerificationStep`, `Finding.VerificationSteps` | 1 |
| `internal/evidence/enums.go` | `VerificationMethod` enum | 1 |
| `internal/evidence/validate.go` | version-gated step validation | 1 |
| `internal/evidence/canonical.go` | step order, finding tie-break | 1 |
| `internal/evidence/doc.go` | `verificationStepsMinor`; `SchemaVersion` → `1.3` (Task 7) | 1, 7 |
| `internal/evidence/steps_test.go` (new) | step validation and order tests | 1 |
| `internal/verify/verify_test.go` | baseline normalization; exhaustive step test | 2, 7 |
| `internal/model/fact.go` | `Method`, `Known(value, method, ...)`, `Fact.Method()` | 3 |
| `internal/model/fact_test.go` | method tests | 3 |
| every `model.Known(` call site (30 prod, 30 test) | pass a method | 3 |
| `internal/providers/aws/{aws,database}.go` | non-stated methods | 4 |
| `internal/providers/gcp/{gcp,database,network}.go` | non-stated methods | 5 |
| `internal/providers/gcp/testdata/real-databases-ipv4-unwritten.json` (new) | real plan | 5 |
| `internal/providers/gcp/testdata/public-iam-policy-data.json` (new) | hand-authored | 5 |
| `internal/providers/gcp/testdata/fw-public-direction-omitted.json` (new) | hand-authored | 5 |
| `internal/providers/azure/database.go` | port method | 6 |
| `internal/policy/steps.go` (new) | step helpers | 7 |
| `internal/policy/{storage,network,database,rules}.go` | emit steps | 7 |
| `internal/policy/steps_test.go` (new) | per-rule step tests | 7 |
| `internal/render/markdown.go` + goldens | "Verified by" bullet | 8 |
| `docs/EVIDENCE-BUNDLE.md`, `docs/examples/evidence-bundle.json`, `docs/ARCHITECTURE.md`, `docs/PRODUCT.md` | docs | 8, 9 |

---

### Task 0: Branch and spec amendments

**Files:**
- Modify: `docs/milestones/10-verification-method.md`

- [ ] **Step 1: Create the branch**

```bash
git switch -c milestone-10-verification-method
```

- [ ] **Step 2: Amend the spec**

In `docs/milestones/10-verification-method.md`:

1. In **Product decisions**, replace the bullet beginning `- **`PortInferred` is absorbed.**` with:

```markdown
- **`PortInferred` stays.** Measured while planning: Azure's port comes from a
  table keyed on the resource type, so its method is `documented-table`, and the
  Azure mapper documents that port as certain rather than a default -- which is
  why `PortInferred` is false there. The method says where a value came from;
  `PortInferred` says whether the deployment could differ from it. Folding one
  into the other would make `DATABASE_PORT_INFERRED` claim an Azure port is a
  default. `DATABASE_PORT_INFERRED` keeps reading `PortInferred`.
```

2. After the bullet beginning `- **A fact derived from several inputs`, add:

```markdown
- **A disjunctive grant takes the method of the proof the mapper cites.** AWS
  storage settles on the first unblocked granting channel, the ACL before the
  policy; GCP storage on any granting binding. A grant proven by a stated value
  is `plan-stated-value` even when an interpreted policy document also grants,
  because the stated proof is the one the finding cites.
```

3. In **Scope**, delete the two lines:

```markdown
  - AWS network: unwritten `ingress` read as no inline rules is
    `provider-default`.
```

and add under the list:

```markdown
  Measured while planning: AWS unwritten `ingress` only suppresses an unread
  set. `Known(false)` requires the set to be stated and `Known(true)` rests on a
  stated separate rule, so the default never decides a KNOWN fact and every AWS
  network fact is `plan-stated-value`.
```

4. Replace criterion 3's AWS sentence (`The two AWS defaults resolve to ... on the fact instead.`) with:

```markdown
   The AWS `publicly_accessible` default resolves to `Known(false)` and can
   never produce a finding; a mapper test asserts its method on the fact instead.
```

5. Replace criterion 8 with:

```markdown
8. No verdict changes. The 226 baselines recorded at `3b50544` are not
   re-recorded: the baseline test removes `verification_steps` and restores
   `schema_version: "1.2"` before comparing, so every one of them still matches
   byte for byte -- `DATABASE_PORT_INFERRED` included. The plan fixtures with no
   baseline are compared by building binaries at `3b50544` and at the end of
   this milestone, as milestone 09 did.
```

6. In **Explicitly out of scope**, replace the bullet `- An automatic baseline-recording flag...` with:

```markdown
- Re-recording the baselines, or an automatic recording flag. They stay the
  milestone 09 verdict baseline, and criterion 8 compares against them as they
  are.
```

- [ ] **Step 3: Commit**

```bash
git add docs/milestones/10-verification-method.md
git commit -m "docs(m10): six amendments measured while planning

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1: Evidence Bundle — the field, its validation and its order

**Files:**
- Modify: `internal/evidence/enums.go`, `internal/evidence/bundle.go`, `internal/evidence/validate.go`, `internal/evidence/canonical.go`, `internal/evidence/doc.go`
- Test: `internal/evidence/steps_test.go` (create)

**Interfaces:**
- Produces:
  - `type VerificationMethod string` with constants `MethodPlanStatedValue`, `MethodProviderDefault`, `MethodPolicyDocumentInterpreted`, `MethodReferenceResolved`, `MethodDocumentedTable`, `MethodPlanAction`, `MethodIntentComparison`; `func (m VerificationMethod) Valid() bool`
  - `type VerificationStep struct { Fact string \`json:"fact"\`; Method VerificationMethod \`json:"method"\` }`
  - `Finding.VerificationSteps []VerificationStep \`json:"verification_steps,omitempty"\``
  - `const verificationStepsMinor = 3` (unexported)
  - `SchemaVersion` **stays `"1.2"`** in this task; Task 7 raises it.

- [ ] **Step 1: Write the failing tests**

Create `internal/evidence/steps_test.go`:

```go
package evidence

import (
	"strings"
	"testing"
)

// withSteps returns a block bundle declaring the given version whose finding
// carries the given steps.
func withSteps(version string, steps []VerificationStep) Bundle {
	b := blockBundle()
	b.SchemaVersion = version
	b.Findings[0].VerificationSteps = steps
	return b
}

func stated() []VerificationStep {
	return []VerificationStep{
		{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
		{Fact: "contract.object_storage.exposure", Method: MethodIntentComparison},
	}
}

func TestEveryMethodInTheClosedSetIsValid(t *testing.T) {
	for _, m := range []VerificationMethod{
		MethodPlanStatedValue, MethodProviderDefault, MethodPolicyDocumentInterpreted,
		MethodReferenceResolved, MethodDocumentedTable, MethodPlanAction, MethodIntentComparison,
	} {
		if !m.Valid() {
			t.Errorf("%q is in the closed set and was refused", m)
		}
	}
	for _, m := range []VerificationMethod{"", "plan", "PLAN-STATED-VALUE", " plan-stated-value"} {
		if m.Valid() {
			t.Errorf("%q is not in the closed set and was accepted", m)
		}
	}
}

func TestAVersionWithStepsRequiresThem(t *testing.T) {
	if err := withSteps("1.3", nil).Validate(); err == nil ||
		!strings.Contains(err.Error(), "verification_steps") {
		t.Errorf("a 1.3 finding with no step was accepted: %v", err)
	}
	if err := withSteps("1.3", stated()).Validate(); err != nil {
		t.Errorf("a well-formed 1.3 bundle was refused: %v", err)
	}
}

func TestAnEarlierVersionIsValidWithoutSteps(t *testing.T) {
	if err := withSteps("1.2", nil).Validate(); err != nil {
		t.Errorf("a 1.2 bundle predating the field was refused: %v", err)
	}
}

func TestAStepPresentIsValidatedWhateverTheVersion(t *testing.T) {
	cases := map[string]VerificationStep{
		"unknown method":   {Fact: "object_storage.public_access", Method: "guessed"},
		"empty method":     {Fact: "object_storage.public_access"},
		"empty fact":       {Fact: "  ", Method: MethodPlanStatedValue},
		"multi-line fact":  {Fact: "object_storage\n# forged", Method: MethodPlanStatedValue},
		"control in fact":  {Fact: "object\x1b[2Jstorage", Method: MethodPlanStatedValue},
	}
	for name, step := range cases {
		for _, version := range []string{"1.2", "1.3"} {
			if err := withSteps(version, []VerificationStep{step}).Validate(); err == nil {
				t.Errorf("%s at %s: accepted", name, version)
			}
		}
	}
}

func TestStepsAreOrderedByFactThenMethod(t *testing.T) {
	b := withSteps("1.3", []VerificationStep{
		{Fact: "database.port", Method: MethodDocumentedTable},
		{Fact: "contract.database.exposure", Method: MethodIntentComparison},
		{Fact: "database.admitted_by", Method: MethodReferenceResolved},
		{Fact: "database.admitted_by", Method: MethodPlanStatedValue},
	})
	got := Canonical(b).Findings[0].VerificationSteps
	want := []VerificationStep{
		{Fact: "contract.database.exposure", Method: MethodIntentComparison},
		{Fact: "database.admitted_by", Method: MethodPlanStatedValue},
		{Fact: "database.admitted_by", Method: MethodReferenceResolved},
		{Fact: "database.port", Method: MethodDocumentedTable},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step %d = %v, want %v", i, got[i], want[i])
		}
	}
	if b.Findings[0].VerificationSteps[0].Fact != "database.port" {
		t.Error("Canonical reordered the caller's slice")
	}
}

func TestFindingsDifferingOnlyInStepsAreOrderedByContent(t *testing.T) {
	a := blockBundle().Findings[0]
	a.VerificationSteps = []VerificationStep{{Fact: "object_storage.public_access", Method: MethodPolicyDocumentInterpreted}}
	b := blockBundle().Findings[0]
	b.VerificationSteps = []VerificationStep{{Fact: "object_storage.public_access", Method: MethodPlanStatedValue}}

	if compareFindings(a, b) == 0 {
		t.Fatal("two findings differing in their steps compared equal")
	}
	if compareFindings(a, b) != -compareFindings(b, a) {
		t.Error("the order is not antisymmetric")
	}
}
```

- [ ] **Step 2: Run, expect a compile failure**

Run: `go test ./internal/evidence/ -run 'Method|Steps|Step' -v`
Expected: FAIL — `undefined: VerificationStep`, `undefined: MethodPlanStatedValue`.

- [ ] **Step 3: Implement**

Append to `internal/evidence/enums.go`:

```go
// VerificationMethod is how one fact a finding rests on was established. It is
// provenance, not technique: a reader is told whether the verdict rests on what
// the plan states, on a provider default, or on something this build inferred.
//
// It is never load-bearing. No decision, disposition or exit code depends on it.
type VerificationMethod string

const (
	// MethodPlanStatedValue means the value is stated in the plan.
	MethodPlanStatedValue VerificationMethod = "plan-stated-value"
	// MethodProviderDefault means the argument is unwritten and the value is the
	// provider's documented default.
	MethodProviderDefault VerificationMethod = "provider-default"
	// MethodPolicyDocumentInterpreted means the value results from this build's
	// reading of a JSON policy document.
	MethodPolicyDocumentInterpreted VerificationMethod = "policy-document-interpreted"
	// MethodReferenceResolved means the fact joins two resources through
	// configuration references.
	MethodReferenceResolved VerificationMethod = "reference-resolved"
	// MethodDocumentedTable means the value comes from a closed, documented table
	// in this build.
	MethodDocumentedTable VerificationMethod = "documented-table"
	// MethodPlanAction means the value is the classification of the plan's
	// actions.
	MethodPlanAction VerificationMethod = "plan-action"
	// MethodIntentComparison means the fact is the comparison with the intent
	// contract.
	MethodIntentComparison VerificationMethod = "intent-comparison"
)

// Valid reports whether m is a member of the closed method set.
func (m VerificationMethod) Valid() bool {
	switch m {
	case MethodPlanStatedValue, MethodProviderDefault, MethodPolicyDocumentInterpreted,
		MethodReferenceResolved, MethodDocumentedTable, MethodPlanAction, MethodIntentComparison:
		return true
	}
	return false
}
```

In `internal/evidence/bundle.go`, add to `Finding` after `Evidence`:

```go
	// VerificationSteps says how each fact the verdict rests on was established:
	// the "verification method" CLAUDE.md requires of every finding. A list,
	// because one verdict can rest on facts of different provenance. It carries
	// no value, and nothing decides on it.
	VerificationSteps []VerificationStep `json:"verification_steps,omitempty"`
```

and after `EvidenceRef`:

```go
// VerificationStep is one fact a finding rests on and how it was established.
// It has no value field by construction, like an evidence reference.
type VerificationStep struct {
	// Fact is a capability path, or contract.<field> for the comparison with
	// the intent contract.
	Fact string `json:"fact"`
	// Method is how the fact was established.
	Method VerificationMethod `json:"method"`
}
```

In `internal/evidence/doc.go`, append:

```go
// verificationStepsMinor is the minor version that added
// findings[].verification_steps. A bundle declaring an earlier one is valid
// without the field, for the reason intentDigestMinor gives.
const verificationStepsMinor = 3
```

In `internal/evidence/validate.go`, replace `carriesIntentDigest` with a general helper and keep the old name as a caller:

```go
// carriesIntentDigest reports whether a declared version is one that has
// subject.intent_digest.
func carriesIntentDigest(version string) bool { return atLeastMinor(version, intentDigestMinor) }

// carriesVerificationSteps reports whether a declared version is one that
// requires findings[].verification_steps.
func carriesVerificationSteps(version string) bool {
	return atLeastMinor(version, verificationStepsMinor)
}

// atLeastMinor reports whether a declared version is at or after a minor
// version. An unreadable version is not treated as an old one:
// validateSchemaVersion refuses it separately, and reading it as "before the
// field existed" would let anything skip the check by mangling one string.
func atLeastMinor(version string, minor int) bool {
	_, declared, found := strings.Cut(version, ".")
	if !found || !isPlainNumber(declared) {
		return true
	}
	value, err := strconv.Atoi(declared)
	return err != nil || value >= minor
}
```

In `Validate`, change the finding loop to pass the requirement:

```go
	requireSteps := carriesVerificationSteps(b.SchemaVersion)
	for i, f := range ordered.Findings {
		errs = append(errs, validateFinding(fmt.Sprintf("findings[%d]", i), f, requireSteps)...)
	}
```

Change `validateFinding`'s signature to `func validateFinding(path string, f Finding, requireSteps bool) []error` and, just before `return errs`, add:

```go
	if requireSteps && len(f.VerificationSteps) == 0 {
		errs = append(errs, violation(path+".verification_steps",
			"must say how at least one fact the finding rests on was established"))
	}
	errs = append(errs, validateSteps(path, f.VerificationSteps)...)
```

and add:

```go
// validateSteps checks every verification step, whatever version the bundle
// declares: a field that is present is held to its contract, as intent_digest
// is.
func validateSteps(parent string, steps []VerificationStep) []error {
	var errs []error
	for i, step := range steps {
		path := fmt.Sprintf("%s.verification_steps[%d]", parent, i)
		if strings.TrimSpace(step.Fact) == "" {
			errs = append(errs, violation(path+".fact", "must name the fact"))
		}
		if err := validateSingleLine(path+".fact", step.Fact); err != nil {
			errs = append(errs, err)
		}
		if !step.Method.Valid() {
			errs = append(errs, violation(path+".method", "unrecognized verification method %q",
				string(step.Method)))
		}
	}
	return errs
}
```

`validateSingleLine` (`validate.go:475`) refuses only `\r` and `\n`, and `Inline`'s comment explains that other controls are deliberately *valid* in prose. A fact path is different: this build produces it from constants and never from plan text, so no legitimate step carries a control. Add, inside the loop in `validateSteps`:

```go
		// Stricter than prose: a fact path is a constant of this build, never
		// plan text, so a control character in one is a defect, not a value.
		if strings.IndexFunc(step.Fact, isControlChar) >= 0 {
			errs = append(errs, violation(path+".fact", "must not carry a control character"))
		}
```

In `internal/evidence/canonical.go`, inside the finding loop of `Canonical`, add:

```go
		out.Findings[i].VerificationSteps = canonicalSteps(out.Findings[i].VerificationSteps)
```

replace the last line of `compareFindings` with:

```go
	if c := compareEvidenceSlice(a.Evidence, b.Evidence); c != 0 {
		return c
	}
	return compareSteps(a.VerificationSteps, b.VerificationSteps)
```

and add:

```go
// canonicalSteps returns a sorted copy, ordered by fact and then method. Nil
// stays nil, so a bundle that predates the field renders without it.
func canonicalSteps(steps []VerificationStep) []VerificationStep {
	if steps == nil {
		return nil
	}
	out := slices.Clone(steps)
	slices.SortStableFunc(out, compareStep)
	return out
}

func compareStep(a, b VerificationStep) int {
	if c := cmp.Compare(a.Fact, b.Fact); c != 0 {
		return c
	}
	return cmp.Compare(string(a.Method), string(b.Method))
}

func compareSteps(a, b []VerificationStep) int {
	return slices.CompareFunc(a, b, compareStep)
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/evidence/ && go vet ./internal/evidence/`
Expected: PASS. `TestABundleFromAnEarlierMinorVersionStillValidates` must still pass unchanged.

- [ ] **Step 5: Run everything**

Run: `go build ./... && go test ./...`
Expected: PASS — `SchemaVersion` is still `1.2`, so no producer is yet required to emit steps.

- [ ] **Step 6: Commit**

```bash
git add internal/evidence
git commit -m "feat(evidence): verification_steps, validated from 1.3 and whenever present

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Freeze the verdict baseline

**Files:**
- Modify: `internal/verify/verify_test.go:448-530` (`TestEveryFixtureProducesItsBaselineBundle`)

**Interfaces:**
- Consumes: `evidence.Finding.VerificationSteps` (Task 1).
- Produces: `func verdictOnly(b evidence.Bundle) evidence.Bundle` (test helper in package `verify_test`).

- [ ] **Step 1: Write the failing check**

Add the helper and use it. In the subtest, replace `got, err := render.JSON(bundle)` with `got, err := render.JSON(verdictOnly(bundle))`. Add near the test:

```go
// verdictOnly is the bundle as milestone 09 would have written it: no
// verification steps, and the version that predates them.
//
// The baselines are the milestone 09 verdict baseline and are not re-recorded.
// Stripping only what milestone 10 adds means every other byte -- decision,
// findings, unknowns, evidence, DATABASE_PORT_INFERRED -- is still compared, so
// a verdict cannot change behind the new field.
func verdictOnly(b evidence.Bundle) evidence.Bundle {
	out := b
	out.SchemaVersion = "1.2"
	out.Findings = slices.Clone(b.Findings)
	for i := range out.Findings {
		out.Findings[i].VerificationSteps = nil
	}
	return out
}
```

Add `"slices"` and `"github.com/mtlabs-eng/infraproof/internal/evidence"` to the imports if absent.

Then prove the comparison bites: temporarily change `out.SchemaVersion = "1.2"` to `"1.9"`.

Run: `go test ./internal/verify/ -run TestEveryFixtureProducesItsBaselineBundle`
Expected: FAIL — `this plan's verdict changed since the baseline was recorded` on every fixture.

Restore `"1.2"`.

- [ ] **Step 2: Run, expect pass**

Run: `go test ./internal/verify/`
Expected: PASS, and `git status --short internal/verify/testdata` prints nothing.

- [ ] **Step 3: Commit**

```bash
git add internal/verify/verify_test.go
git commit -m "test(verify): the baselines stay milestone 09's, compared without the new field

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: A KNOWN fact cannot be made without a method

**Files:**
- Modify: `internal/model/fact.go`
- Test: `internal/model/fact_test.go`
- Modify mechanically: every `model.Known(` call — production sites in `internal/providers/{aws,azure,gcp}/*.go`, `internal/providers/declared/environment.go`, `internal/policy/database.go`; and ~30 test sites (`grep -rn "model\.Known(" internal --include='*_test.go'`).

**Interfaces:**
- Produces:
  - `type Method string`; constants `MethodStated = "plan-stated-value"`, `MethodProviderDefault = "provider-default"`, `MethodPolicyDocument = "policy-document-interpreted"`, `MethodReferenceResolved = "reference-resolved"`, `MethodDocumentedTable = "documented-table"`. The strings are identical to the evidence constants; Task 7's test pins that.
  - `func Known[T any](value T, method Method, sources ...Provenance) Fact[T]`
  - `func (f Fact[T]) Method() Method` — `""` for any state but `FactKnown`.

- [ ] **Step 1: Write the failing test**

Append to `internal/model/fact_test.go` (create the file with `package model` and `import "testing"` if it does not exist):

```go
func TestAKnownFactCarriesTheMethodItWasGiven(t *testing.T) {
	f := Known(true, MethodProviderDefault, Provenance{ResourceAddress: "a", AttributePath: "b"})
	if f.Method() != MethodProviderDefault {
		t.Errorf("Method() = %q, want %q", f.Method(), MethodProviderDefault)
	}
	if f.Canonical().Method() != MethodProviderDefault {
		t.Error("Canonical dropped the method")
	}
}

func TestOnlyAKnownFactHasAMethod(t *testing.T) {
	for name, f := range map[string]Fact[bool]{
		"unknown":  Unknown[bool](),
		"absent":   Absent[bool](),
		"redacted": Redacted[bool](),
	} {
		if f.Method() != "" {
			t.Errorf("%s fact reports method %q; nothing was established", name, f.Method())
		}
	}
}

func TestTheZeroMethodIsNotStated(t *testing.T) {
	var zero Method
	if zero == MethodStated {
		t.Fatal("the zero method reads as plan-stated-value, which is the default this milestone removes")
	}
}
```

- [ ] **Step 2: Run, expect a compile failure**

Run: `go test ./internal/model/`
Expected: FAIL — `undefined: MethodProviderDefault`, `too many arguments in call to Known`.

- [ ] **Step 3: Implement in `internal/model/fact.go`**

Add after `FactState`'s constants:

```go
// Method is how a mapper established a KNOWN fact's value. Only a KNOWN fact has
// one; the other states established nothing.
//
// The zero value is not a method. A fact nobody gave one reaches the bundle as
// an unrecognized method and fails validation, rather than reading as stated --
// a default of "stated" would present every defaulted, inferred or interpreted
// value as one the plan wrote, which is the defect milestone 10 removes.
type Method string

const (
	// MethodStated means the plan states the value.
	MethodStated Method = "plan-stated-value"
	// MethodProviderDefault means the argument is unwritten and the value is the
	// provider's documented default.
	MethodProviderDefault Method = "provider-default"
	// MethodPolicyDocument means the value is this build's reading of a JSON
	// policy document.
	MethodPolicyDocument Method = "policy-document-interpreted"
	// MethodReferenceResolved means the value joins two resources through
	// configuration references.
	MethodReferenceResolved Method = "reference-resolved"
	// MethodDocumentedTable means the value comes from a closed, documented table
	// in this build.
	MethodDocumentedTable Method = "documented-table"
)
```

Change `Fact` and `Known`:

```go
type Fact[T any] struct {
	State   FactState
	value   T
	method  Method
	Sources []Provenance
}

// Known returns a fact a mapper determined, how it determined it, and the
// sources it is attributed to. There is no constructor without a method, so
// every site that establishes a value has to say how.
func Known[T any](value T, method Method, sources ...Provenance) Fact[T] {
	return Fact[T]{State: FactKnown, value: value, method: method, Sources: sources}
}

// Method returns how the value was established, or "" for any state but
// FactKnown.
func (f Fact[T]) Method() Method {
	if f.State != FactKnown {
		return ""
	}
	return f.method
}
```

Also update the `FactKnown` comment to: `// FactKnown means a mapper determined the value; Method says how.`

- [ ] **Step 4: Update every call site with `MethodStated`, except the two in policy**

Run: `go build ./... 2>&1 | grep -c "not enough arguments\|cannot use"` to see the count, then edit each `model.Known(v, sources...)` to `model.Known(v, model.MethodStated, sources...)`. This task assigns `MethodStated` everywhere **on purpose**: Tasks 4–6 change the non-stated sites one at a time, each behind its own failing test, so no site's method is decided without a test watching it.

The two sites in `internal/policy/database.go` take their real methods now, because they are not mapper facts:

At `:220` (a gate decided):

```go
			return model.Known(true, model.MethodReferenceResolved, referencesTo(gate)...), how
```

At `:251` (settled false):

```go
	method := model.MethodReferenceResolved
	if len(capabilities.GatedBy) == 0 {
		// No gate was consulted: the mapper's own fact settled it.
		method = capabilities.AdmitsAnyAddress.Method()
	}
	return model.Known(false, method, capabilities.AdmitsAnyAddress.Sources...), how
```

Test sites: pass `model.MethodStated` (or `MethodStated` inside package `model`).

- [ ] **Step 5: Run everything**

Run: `gofmt -l . ; go vet ./... && go test ./...`
Expected: `gofmt` prints nothing; PASS. No bundle changed — nothing reads the method yet.

- [ ] **Step 6: Commit**

```bash
git add -A internal
git commit -m "feat(model): a known fact says how it was established

Every site is MethodStated for now; the sites that are not are changed one
at a time, each behind its own test.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: AWS mapper methods

**Files:**
- Modify: `internal/providers/aws/database.go:128-141, 343, 365`; `internal/providers/aws/aws.go:172-176, 204-208, 288-318`
- Test: `internal/providers/aws/method_test.go` (create)

**Interfaces:**
- Consumes: `model.Method*`, `Fact.Method()` (Task 3); test helpers `database(t, fixture, address)` (`database_test.go:12`), `bucket(t, fixture)` (`aws_test.go:34`), `bucketPlanNoBlock(t, acl, extraChange, extraConfig)` (`aws_test.go:775`).
- Produces: `channel.method model.Method` (unexported field).

- [ ] **Step 1: Write the failing tests**

Create `internal/providers/aws/method_test.go`:

```go
package aws_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

func TestAnUnwrittenSwitchIsTheProvidersDefault(t *testing.T) {
	endpoint := database(t, "rds-switch-stated-nowhere", "aws_rds_cluster_instance.ax").Database.PublicEndpoint
	if !endpoint.IsKnown() || endpoint.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q (state %s), want %q", endpoint.Method(), endpoint.State, model.MethodProviderDefault)
	}
}

func TestAWrittenSwitchIsStated(t *testing.T) {
	endpoint := database(t, "real-databases", "aws_db_instance.reachable").Database.PublicEndpoint
	if endpoint.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", endpoint.Method(), model.MethodStated)
	}
}

func TestAnEngineDerivedPortIsFromTheTable(t *testing.T) {
	port := database(t, "real-databases", "aws_db_instance.reachable").Database.Port
	if !port.IsKnown() || port.Method() != model.MethodDocumentedTable {
		t.Errorf("method = %q (state %s), want %q", port.Method(), port.State, model.MethodDocumentedTable)
	}
}

func TestAStatedPortIsStated(t *testing.T) {
	// rds-port-written states its port; use the address the fixture defines.
	graph := normalize(t, "rds-port-written")
	for _, r := range graph.Resources {
		if r.Database == nil || !r.Database.Port.IsKnown() {
			continue
		}
		if r.Database.Port.Method() != model.MethodStated {
			t.Errorf("%s: method = %q, want %q", r.Address, r.Database.Port.Method(), model.MethodStated)
		}
		return
	}
	t.Fatal("no database with a known port in rds-port-written")
}

func TestAPolicyGrantIsInterpreted(t *testing.T) {
	access := bucket(t, "public-policy").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodPolicyDocument {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodPolicyDocument)
	}
}

func TestAnACLGrantIsStated(t *testing.T) {
	access := bucket(t, "public-acl").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// Review Focus 2: two proofs, one stated and one interpreted. The finding cites
// the stated one, so the method is stated.
func TestAGrantProvenTwiceTakesTheStatedProof(t *testing.T) {
	access := bucket(t, "public-acl-and-policy").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}
```

`model.Graph` exposes its resources as the field `Resources` (`internal/model/resource.go:176`); `normalize` is `aws_test.go:14`. Create `internal/providers/aws/testdata/public-acl-and-policy.json` by copying `public-policy.json` and adding the `aws_s3_bucket_acl` resource change and configuration entry from `public-acl.json` (same bucket reference), and add one line to `internal/providers/aws/testdata/README.md` under the hand-authored list: `public-acl-and-policy.json — both channels grant; the ACL is the cited proof.`

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/providers/aws/ -run 'Default|Stated|Table|Interpreted|Twice' -v`
Expected: FAIL on `TestAnUnwrittenSwitchIsTheProvidersDefault`, `TestAnEngineDerivedPortIsFromTheTable`, `TestAPolicyGrantIsInterpreted` (each reports `plan-stated-value`); the stated cases PASS.

- [ ] **Step 3: Implement**

`internal/providers/aws/database.go` — both `declared.Unwritten(subject, attrPubliclyAccessible)` branches (`:129`, `:141`):

```go
			return model.Known(false, model.MethodProviderDefault, cited)
```

`:365`:

```go
	return model.Known(port, model.MethodDocumentedTable, cited), true
```

(`:343` stays `MethodStated`.)

`internal/providers/aws/aws.go` — add `method model.Method` to `channel`:

```go
type channel struct {
	grant   answer
	blocked answer
	// method is how the grant, if any, was established: a canned ACL is stated,
	// a policy document is this build's reading of one.
	method  model.Method
	sources []model.Provenance
}
```

In `aclChannel`, initialise `c := channel{method: model.MethodStated, blocked: ...}`. In `policyChannel`, initialise `c := channel{method: model.MethodPolicyDocument, blocked: ...}`. In `publicAccess`, the settling loop:

```go
			return model.Known(true, c.method, c.sources...).Canonical()
```

(`Known(false, ...)` at `:240` stays `MethodStated`: a block's flags are stated.)

- [ ] **Step 4: Run**

Run: `go test ./internal/providers/aws/ && go test ./internal/verify/`
Expected: PASS. The verify baseline is unchanged because steps do not exist yet.

- [ ] **Step 5: Commit**

```bash
git add internal/providers/aws
git commit -m "feat(aws): defaults, the port table and policy documents say so

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: GCP mapper methods

**Files:**
- Modify: `internal/providers/gcp/database.go:121-127, 289`; `internal/providers/gcp/gcp.go:146-163, 197-222`; `internal/providers/gcp/network.go:66-141, 217-300`
- Create: `internal/providers/gcp/testdata/real-databases-ipv4-unwritten.json` (real plan), `public-iam-policy-data.json`, `public-member-and-policy-data.json`, `fw-public-direction-omitted.json`, `fw-denied-lower-direction-omitted.json` (hand-authored); README entries
- Test: `internal/providers/gcp/method_test.go` (create)

**Interfaces:**
- Consumes: `instance(t, fixture, name)` (`database_test.go:16`), `bucket(t, fixture)` (`gcp_test.go:13`), `firewall(t, fixture)` (`network_test.go:37`), `graphOf(t, fixture)` (`network_test.go:16`).
- Produces: `firewallRule.directionDefaulted bool`; `publicBinding` returns `(answer, model.Method, []model.Provenance)`.

- [ ] **Step 1: Generate the real plan**

In the scratchpad (never in the repo), following `docs/milestones/research/README.md`'s procedure:

```bash
S=$SCRATCH/m10-gcp
mkdir -p "$S" && cd "$S"
cat > main.tf <<'EOF'
terraform {
  required_providers { google = { source = "hashicorp/google", version = "~> 6.0" } }
}
provider "google" {
  project     = "infraproof-fixture"
  region      = "europe-west1"
  credentials = "placeholder.json"
}
resource "google_sql_database_instance" "default_endpoint" {
  name             = "default-endpoint"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      authorized_networks {
        name  = "everyone"
        value = "0.0.0.0/0"
      }
    }
  }
}
EOF
echo '{"type":"service_account","project_id":"infraproof-fixture","private_key_id":"0","private_key":"PLACEHOLDER-NOT-A-KEY","client_email":"x@infraproof-fixture.iam.gserviceaccount.com","client_id":"0","token_uri":"https://oauth2.googleapis.com/token"}' > placeholder.json
terraform init -input=false
terraform plan -refresh=false -input=false -out=plan.bin
terraform show -json plan.bin > plan.json
```

If `terraform plan` tries to contact Google and fails, stop and report — do not supply real credentials. Copy `plan.json` to `internal/providers/gcp/testdata/real-databases-ipv4-unwritten.json`, then confirm the shape: `ipv4_enabled` absent or unknown in `after` under `settings[0].ip_configuration[0]`, and absent from `configuration...expressions.settings[0].ip_configuration[0]`. Record the measured `after` state of `ipv4_enabled` in the README row.

Add to `internal/providers/gcp/testdata/README.md`'s database table:

```markdown
| `real-databases-ipv4-unwritten.json` | `ip_configuration` written with an allow list for everyone, `ipv4_enabled` not: the provider's public-IP default decides a finding. Real `terraform plan` output, Terraform 1.14, `hashicorp/google` v6, `-refresh=false`, placeholder credentials. |
```

- [ ] **Step 2: Hand-author the four other fixtures**

- `fw-public-direction-omitted.json`: copy `fw-public.json`; delete the `"direction": "INGRESS"` key from `after` and the `direction` expression from `configuration`. Everything else identical.
- `fw-denied-lower-direction-omitted.json`: copy `fw-denied-lower.json`; delete `direction` from the **deny** firewall only (both `after` and `configuration`).
- `public-iam-policy-data.json`: copy `redacted-iam-policy-data.json`; make `policy_data` a known string `{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]}]}` and remove it from `after_sensitive`.
- `public-member-and-policy-data.json`: copy `public-iam-member.json` and add the `google_storage_bucket_iam_policy` change and configuration from `public-iam-policy-data.json` on the same bucket.

Add one README line each under the hand-authored list, saying what it pins.

- [ ] **Step 3: Write the failing tests**

Create `internal/providers/gcp/method_test.go`:

```go
package gcp_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

func TestAnUnwrittenIPv4SwitchIsTheProvidersDefault(t *testing.T) {
	db := instance(t, "real-databases-ipv4-unwritten", "default_endpoint").Database
	if !db.PublicEndpoint.IsKnown() || !db.PublicEndpoint.Get() {
		t.Fatalf("endpoint = %s; the provider default is a public IP", db.PublicEndpoint.State)
	}
	if db.PublicEndpoint.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodProviderDefault)
	}
}

func TestAWrittenIPv4SwitchIsStated(t *testing.T) {
	db := instance(t, "real-databases", "reachable").Database
	if db.PublicEndpoint.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodStated)
	}
}

func TestAVersionDerivedPortIsFromTheTable(t *testing.T) {
	port := instance(t, "real-databases", "reachable").Database.Port
	if !port.IsKnown() || port.Method() != model.MethodDocumentedTable {
		t.Errorf("method = %q, want %q", port.Method(), model.MethodDocumentedTable)
	}
}

func TestAnOmittedDirectionIsTheProvidersDefault(t *testing.T) {
	stated := firewall(t, "fw-public").Network.PublicIngress
	omitted := firewall(t, "fw-public-direction-omitted").Network.PublicIngress
	if stated.Method() != model.MethodStated {
		t.Errorf("stated direction: method = %q, want %q", stated.Method(), model.MethodStated)
	}
	if !omitted.IsKnown() || !omitted.Get() || omitted.Method() != model.MethodProviderDefault {
		t.Errorf("omitted direction: method = %q, want %q", omitted.Method(), model.MethodProviderDefault)
	}
}

// The real plan's implicit firewall: direction unknown and unwritten.
func TestAnUnknownUnwrittenDirectionIsTheProvidersDefault(t *testing.T) {
	r, ok := graphOf(t, "real-firewalls").At("google_compute_firewall.implicit_public")
	if !ok {
		t.Fatal("implicit_public not in real-firewalls")
	}
	if r.Network.PublicIngress.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q, want %q", r.Network.PublicIngress.Method(), model.MethodProviderDefault)
	}
}

// Review Focus 3: the verdict rests on the deny, and the deny's direction is
// the provider's default.
func TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault(t *testing.T) {
	for _, r := range graphOf(t, "fw-denied-lower-direction-omitted").Resources {
		if r.Network == nil || !r.Network.PublicIngress.IsKnown() || r.Network.PublicIngress.Get() {
			continue
		}
		if r.Network.PublicIngress.Method() != model.MethodProviderDefault {
			t.Errorf("%s: method = %q, want %q", r.Address, r.Network.PublicIngress.Method(),
				model.MethodProviderDefault)
		}
		return
	}
	t.Fatal("no firewall read as closed; the deny no longer cancels the grant")
}

func TestAPolicyDataGrantIsInterpreted(t *testing.T) {
	access := bucket(t, "public-iam-policy-data").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodPolicyDocument {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodPolicyDocument)
	}
}

func TestAMemberGrantIsStated(t *testing.T) {
	access := bucket(t, "public-iam-member").ObjectStorage.PublicAccess
	if access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// Review Focus 2.
func TestAGrantProvenTwiceTakesTheStatedProof(t *testing.T) {
	access := bucket(t, "public-member-and-policy-data").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}
```

`instance(t, fixture, name)` prefixes `google_sql_database_instance.` itself (`database_test.go:16-23`), so pass the bare name as above.

- [ ] **Step 4: Run, expect failure**

Run: `go test ./internal/providers/gcp/ -run 'Default|Stated|Table|Interpreted|Twice' -v`
Expected: FAIL on the four default/table/interpreted cases with `plan-stated-value`; stated cases PASS.

- [ ] **Step 5: Implement**

`database.go:127` → `model.Known(true, model.MethodProviderDefault, cited)`; `:289` → `model.Known(port, model.MethodDocumentedTable, cited)`.

`network.go` — add to `firewallRule`:

```go
	// directionDefaulted reports that direction was unwritten and read as the
	// provider's INGRESS default, so a verdict resting on this rule rests on it.
	directionDefaulted bool
```

In `readFirewall`, the `StateAbsent` case gets `read.directionDefaulted = true`, and the `default:` case, after the `!declared.Unwritten` early return, gets `read.directionDefaulted = true`.

In `ingressOf`, after `rule := readFirewall(subject)`, add `defaulted := rule.directionDefaulted`; where a deny is applied (`cited = append(cited, deny.cited...)`), add `defaulted = defaulted || deny.directionDefaulted`. Then:

```go
	method := model.MethodStated
	if defaulted {
		method = model.MethodProviderDefault
	}
	switch {
	case len(opened) > 0:
		capabilities.PublicIngress = model.Known(true, method, cited...)
	default:
		capabilities.PublicIngress = model.Known(false, method, cited...)
	}
```

`gcp.go` — `publicBinding` returns the method of the strongest proof:

```go
// publicBinding reports whether any related IAM resource names everyone, and how
// the grant was established: a member list is stated, a policy document is this
// build's reading of one. A stated grant wins, because it is the proof the
// finding can rest on without trusting a grammar.
func publicBinding(related []terraformplan.ResourceChange) (answer, model.Method, []model.Provenance) {
	var sources []model.Provenance
	result := answerNo
	method := model.MethodStated
	statedGrant := false
	// escalate is unchanged.
	...
		case typeIAMMember:
			...
			candidate := memberIsEveryone(change.After.Field("member"))
			statedGrant = statedGrant || candidate == answerYes
			escalate(candidate)
		case typeIAMBinding:
			...
			candidate := membersIncludeEveryone(change.After.Field("members"))
			statedGrant = statedGrant || candidate == answerYes
			escalate(candidate)
		case typeIAMPolicy:
			... (unchanged)
	}
	if result == answerYes && !statedGrant {
		method = model.MethodPolicyDocument
	}
	return result, method, sources
}
```

and `publicAccess`: `grant, method, grantSources := publicBinding(related)` and `model.Known(true, method, grantSources...)`.

- [ ] **Step 6: Run**

Run: `go test ./internal/providers/gcp/ ./internal/verify/`
Expected: PASS. The verify baseline is still unchanged.

- [ ] **Step 7: Commit**

```bash
git add internal/providers/gcp
git commit -m "feat(gcp): the IPv4 and direction defaults, the version table and policy_data say so

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Azure port method

**Files:**
- Modify: `internal/providers/azure/database.go:309-323`
- Test: `internal/providers/azure/method_test.go` (create)

- [ ] **Step 1: Write the failing test**

```go
package azure_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

// The port is from a table keyed on the type -- documented-table -- and is
// certain, so PortInferred stays false. Two questions, two fields.
func TestATypeDerivedPortIsFromTheTableAndNotInferred(t *testing.T) {
	db := databaseAt(t, "sql-reachable", "azurerm_mssql_server.db").Database
	if !db.Port.IsKnown() || db.Port.Method() != model.MethodDocumentedTable {
		t.Errorf("method = %q, want %q", db.Port.Method(), model.MethodDocumentedTable)
	}
	if db.PortInferred {
		t.Error("PortInferred = true; the type fixes the port, so it is not a default")
	}
}

func TestTheEndpointSwitchIsStated(t *testing.T) {
	db := databaseAt(t, "sql-reachable", "azurerm_mssql_server.db").Database
	if db.PublicEndpoint.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodStated)
	}
}
```

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/providers/azure/ -run 'Table|Stated' -v`
Expected: FAIL on the port test with `plan-stated-value`.

- [ ] **Step 3: Implement**

`database.go:322` → `return model.Known(port, model.MethodDocumentedTable, portCitation(subject))`, and extend the `listeningPort` comment's last sentence to: `That is why PortInferred stays false here, and why the method is still documented-table: the value comes from portOf, a table this build keeps.`

- [ ] **Step 4: Run**

Run: `go test ./internal/providers/... ./internal/verify/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/providers/azure
git commit -m "feat(azure): the type-derived port is from the table, and still certain

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: The policy emits steps; the bundle becomes 1.3

**Files:**
- Create: `internal/policy/steps.go`, `internal/policy/steps_test.go`
- Modify: `internal/policy/storage.go:124-155`, `internal/policy/network.go:~112`, `internal/policy/database.go` (`approximation`, `admitsAnyAddress`, `rangesReach`, `reachableFinding` and its caller at `:133`), `internal/policy/rules.go:98, 166, 242`, `internal/evidence/doc.go`
- Modify: `internal/verify/verify_test.go` (exhaustive test)
- Modify any test that builds a `1.3`-declared bundle by hand without steps (find by running the suite).

**Interfaces:**
- Consumes: `evidence.VerificationStep`, `evidence.Method*` (Task 1); `model.Fact.Method()` (Task 3).
- Produces:
  - `func factStep[T any](path string, f model.Fact[T]) evidence.VerificationStep`
  - `func contractStep(field string) evidence.VerificationStep`
  - `approximation.gate model.Fact[bool]` (the deciding gate's `PublicIngress`), `approximation.byPort bool`
  - `func rangesReach(open []model.OpenRange, port model.Fact[int]) (reaches, wider, byPort bool)`
  - `evidence.SchemaVersion = "1.3"`

- [ ] **Step 1: Write the failing tests**

Create `internal/policy/steps_test.go`:

```go
package policy_test

import (
	"slices"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
)

func stepsOf(t *testing.T, result policy.Result, rule, address string) []evidence.VerificationStep {
	t.Helper()
	for _, f := range result.Findings {
		if f.RuleID == rule && f.Resource != nil && f.Resource.Address == address {
			return evidence.Canonical(evidence.Bundle{Findings: []evidence.Finding{f}}).Findings[0].VerificationSteps
		}
	}
	t.Fatalf("no %s finding about %s", rule, address)
	return nil
}

func assertSteps(t *testing.T, got []evidence.VerificationStep, want ...evidence.VerificationStep) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("steps\n got %v\nwant %v", got, want)
	}
}

func step(fact string, m evidence.VerificationMethod) evidence.VerificationStep {
	return evidence.VerificationStep{Fact: fact, Method: m}
}

// The model and evidence spell every shared method identically, because the
// policy converts one to the other by type conversion.
func TestEveryModelMethodIsAnEvidenceMethod(t *testing.T) {
	for _, m := range []model.Method{model.MethodStated, model.MethodProviderDefault,
		model.MethodPolicyDocument, model.MethodReferenceResolved, model.MethodDocumentedTable} {
		if !evidence.VerificationMethod(m).Valid() {
			t.Errorf("model method %q is not a valid evidence method", m)
		}
	}
}

func TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate(t *testing.T) {
	result := evaluateDatabase(t, "aws", "real-databases", requiringPrivate())
	assertSteps(t, stepsOf(t, result, policy.RuleDatabasePublicReachable, "aws_db_instance.reachable"),
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodReferenceResolved),
		step("database.port", evidence.MethodDocumentedTable),
		step("database.public_endpoint", evidence.MethodPlanStatedValue),
		step("network.public_ingress", evidence.MethodPlanStatedValue),
	)
}

// Criterion 3, GCP ipv4_enabled: the pair differs in that one method and in
// nothing else.
func TestTheIPv4DefaultChangesOneStepAndNothingElse(t *testing.T) {
	written := stepsOf(t, evaluateDatabase(t, "gcp", "real-databases", requiringPrivate()),
		policy.RuleDatabasePublicReachable, "google_sql_database_instance.reachable")
	unwritten := stepsOf(t, evaluateDatabase(t, "gcp", "real-databases-ipv4-unwritten", requiringPrivate()),
		policy.RuleDatabasePublicReachable, "google_sql_database_instance.default_endpoint")
	assertSteps(t, written,
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodPlanStatedValue),
		step("database.public_endpoint", evidence.MethodPlanStatedValue),
	)
	assertSteps(t, unwritten,
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodPlanStatedValue),
		step("database.public_endpoint", evidence.MethodProviderDefault),
	)
}

// Criterion 3, GCP direction.
func TestTheDirectionDefaultChangesOneStepAndNothingElse(t *testing.T) {
	written := stepsOf(t, evaluateNetwork(t, "gcp", "fw-public", declaringPort()),
		policy.RuleNetworkPublicIngress, "google_compute_firewall.web")
	omitted := stepsOf(t, evaluateNetwork(t, "gcp", "fw-public-direction-omitted", declaringPort()),
		policy.RuleNetworkPublicIngress, "google_compute_firewall.web")
	assertSteps(t, written,
		step("contract.network.public_ports", evidence.MethodIntentComparison),
		step("network.public_ingress", evidence.MethodPlanStatedValue))
	assertSteps(t, omitted,
		step("contract.network.public_ports", evidence.MethodIntentComparison),
		step("network.public_ingress", evidence.MethodProviderDefault))
}

func TestAPolicyDocumentGrantIsInterpretedInTheStep(t *testing.T) {
	assertSteps(t, stepsOf(t, evaluate(t, "aws", "public-policy"), policy.RuleStoragePublic, "aws_s3_bucket.assets"),
		step("contract.object_storage.exposure", evidence.MethodIntentComparison),
		step("object_storage.public_access", evidence.MethodPolicyDocumentInterpreted))
}
```

Before running: confirm the bucket address in `public-policy.json` and the firewall address in `fw-public.json` (`google_compute_firewall.web`, measured) and fix the literals. Confirm `declaringPort()` declares a port that leaves `fw-public`'s opening reported; if not, use a contract declaring nothing (`intent.Contract{SchemaVersion: "1.2", ChangeID: "t", Environment: "test", AllowedClouds: []string{"gcp"}, DestructiveChanges: intent.DestructiveForbidden}`).

Add the generic-rule tests in the same file (contract helpers come from `internal/policy/contract_test.go`; build the resource with `model.NormalizedResource` directly):

```go
func TestEveryGenericRuleSaysHowItKnows(t *testing.T) {
	resource := model.NormalizedResource{
		Address: "aws_s3_bucket.assets", Provider: "registry.terraform.io/hashicorp/aws",
		Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Destructive: true,
		Environment: model.Known("production", model.MethodStated,
			model.Provenance{ResourceAddress: "aws_s3_bucket.assets", AttributePath: "tags.environment"}),
	}
	graph := model.Graph{Resources: []model.NormalizedResource{resource}}
	contract := intent.Contract{SchemaVersion: "1.2", ChangeID: "t", Environment: "staging",
		AllowedClouds: []string{"gcp"}, DestructiveChanges: intent.DestructiveForbidden}

	assertSteps(t, stepsOf(t, policy.DestructiveChange(contract, graph), policy.RuleDestructiveChange, resource.Address),
		step("change.destructive", evidence.MethodPlanAction),
		step("contract.destructive_changes", evidence.MethodIntentComparison))
	assertSteps(t, stepsOf(t, policy.CloudAllowed(contract, graph), policy.RuleCloudNotAllowed, resource.Address),
		step("contract.allowed_clouds", evidence.MethodIntentComparison),
		step("resource.cloud", evidence.MethodPlanStatedValue))
	assertSteps(t, stepsOf(t, policy.EnvironmentMatch(contract, graph), policy.RuleEnvironmentMismatch, resource.Address),
		step("contract.environment", evidence.MethodIntentComparison),
		step("resource.environment", evidence.MethodPlanStatedValue))
}
```

The rule functions are `DestructiveChange`, `CloudAllowed` and `EnvironmentMatch` (`rules.go:51, 129, 198`); `model.Graph` is a struct with one exported field, `Resources`.

Review Focus 1 and 4 — add to `internal/policy/steps_test.go`:

```go
// Review Focus 4: a gate admitting every usable port decides without the port,
// so the finding names no port step; a gate open on the port alone names one.
// Built with reproduction_test.go's helpers (reachable, known, knownPort,
// group, rngR, declaringExposure, unknownBool), which Task 3 already updated
// to pass a method.
func TestThePortStepAppearsOnlyWhenThePortDecided(t *testing.T) {
	hasPortStep := func(r policy.Result) bool {
		for _, f := range r.Findings {
			for _, s := range f.VerificationSteps {
				if s.Fact == "database.port" {
					return true
				}
			}
		}
		return false
	}
	contract := declaringExposure(intent.ExposurePrivate)

	everyPort := policy.DatabaseExposure(contract, reachable(known(true), unknownBool(), knownPort(5432),
		group("aws_security_group.db", known(true), rngR(model.ProtocolTCP, 0, 65535))))
	if len(everyPort.Findings) == 0 {
		t.Fatal("a group open on every port in front of a public endpoint produced no finding")
	}
	if hasPortStep(everyPort) {
		t.Error("every port was admitted, so the port decided nothing, and a port step was emitted")
	}

	onePort := policy.DatabaseExposure(contract, reachable(known(true), unknownBool(), knownPort(5432),
		group("aws_security_group.db", known(true), rngR(model.ProtocolTCP, 5432, 5432))))
	if len(onePort.Findings) == 0 {
		t.Fatal("a group open on the database port produced no finding")
	}
	if !hasPortStep(onePort) {
		t.Error("the port decided reachability and no port step was emitted")
	}
}
```

The calls match the helpers' use in `TestR01InlineFalseHidesAnOpenGate` and `TestR03InferredPortSilenceIsUndisclosed`; confirm their signatures in `reproduction_test.go` before running.

```go
// Review Focus 1: a KNOWN fact with no method reaches render as an error, not
// as a step.
func TestAZeroMethodNeverReachesABundle(t *testing.T) {
	// The zero method, passed explicitly: what a mapper that forgot would emit.
	resource := model.NormalizedResource{
		Address: "aws_s3_bucket.assets", Provider: "registry.terraform.io/hashicorp/aws",
		Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
		ObjectStorage: &model.ObjectStorageCapabilities{PublicAccess: model.Known(true, model.Method(""),
			model.Provenance{ResourceAddress: "aws_s3_bucket.assets", AttributePath: "acl"})},
	}
	result := policy.StorageExposure(privateStorage, model.Graph{Resources: []model.NormalizedResource{resource}})
	bundle := evidence.Bundle{SchemaVersion: evidence.SchemaVersion, Decision: evidence.DecisionBlock,
		Summary: "s", Subject: evidence.Subject{IntentSource: "i", PlanFormatVersion: "1.x",
			PlanDigest:   "sha256:" + strings.Repeat("0", 64),
			IntentDigest: "sha256:" + strings.Repeat("0", 64)},
		Verification: []evidence.Verification{{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"}},
		Findings: result.Findings, Unknowns: []evidence.Unknown{}}
	if err := bundle.Validate(); err == nil || !strings.Contains(err.Error(), "verification_steps") {
		t.Errorf("a fact with no method validated: %v", err)
	}
}
```

(add `"strings"` and `intent` imports.)

In `internal/verify/verify_test.go`, add the exhaustive criterion-1 test:

```go
// TestEveryFindingSaysHowItKnows is criterion 1 over every committed plan
// fixture, not a sample: each finding carries at least one step and the bundle
// validates as 1.3.
func TestEveryFindingSaysHowItKnows(t *testing.T) {
	intent := filepath.Join("testdata", "baseline", "intent.json")
	findings := 0
	for _, fixture := range planFixtures(t) {
		bundle, err := verify.FromFiles(intent, fixture, verify.Options{})
		if err != nil {
			continue // reported by TestEveryFixtureProducesItsBaselineBundle
		}
		if bundle.SchemaVersion != "1.3" {
			t.Fatalf("%s: schema_version = %q, want 1.3", fixture, bundle.SchemaVersion)
		}
		for _, f := range bundle.Findings {
			findings++
			if len(f.VerificationSteps) == 0 {
				t.Errorf("%s: %s on %v carries no step", fixture, f.RuleID, f.Resource)
			}
		}
		if err := bundle.Validate(); err != nil {
			t.Errorf("%s: %v", fixture, err)
		}
	}
	if findings == 0 {
		t.Fatal("no fixture produced a finding; the test asserted nothing")
	}
}
```

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/policy/ ./internal/verify/ -run 'Step|HowItKnows|Hop|Default|Interpreted|Generic|Zero|PortStep|EveryModel' -v`
Expected: FAIL — steps are empty; schema_version is `1.2`.

- [ ] **Step 3: Implement the helpers**

Create `internal/policy/steps.go`:

```go
package policy

import (
	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

// factStep says how one plan fact a verdict rests on was established. The method
// is the fact's own, never recomputed here: the mapper that read the value is
// the only one that knows whether the plan stated it. A fact nobody gave a
// method converts to an empty method, which the bundle refuses.
func factStep[T any](path string, f model.Fact[T]) evidence.VerificationStep {
	return evidence.VerificationStep{Fact: path, Method: evidence.VerificationMethod(f.Method())}
}

// contractStep is the comparison with the intent contract. It is on every
// finding, including one where the contract declares nothing: silence is read,
// and is what made the finding a WARN.
func contractStep(field string) evidence.VerificationStep {
	return evidence.VerificationStep{Fact: "contract." + field, Method: evidence.MethodIntentComparison}
}
```

- [ ] **Step 4: Emit steps in each rule**

`storage.go`, `publicFinding`'s returned finding:

```go
		VerificationSteps: []evidence.VerificationStep{
			factStep("object_storage.public_access", capabilities.PublicAccess),
			contractStep("object_storage.exposure"),
		},
```

`network.go`, `ingressFinding`'s `finding`:

```go
		VerificationSteps: []evidence.VerificationStep{
			factStep("network.public_ingress", capabilities.PublicIngress),
			contractStep("network.public_ports"),
		},
```

`rules.go` — `DESTRUCTIVE_CHANGE`:

```go
			VerificationSteps: []evidence.VerificationStep{
				{Fact: "change.destructive", Method: evidence.MethodPlanAction},
				contractStep("destructive_changes"),
			},
```

`CLOUD_NOT_ALLOWED`:

```go
			VerificationSteps: []evidence.VerificationStep{
				// The cloud is whichever mapper claimed the provider the plan
				// names in provider_name, which is stated.
				{Fact: "resource.cloud", Method: evidence.MethodPlanStatedValue},
				contractStep("allowed_clouds"),
			},
```

`ENVIRONMENT_MISMATCH`:

```go
			VerificationSteps: []evidence.VerificationStep{
				factStep("resource.environment", declared),
				contractStep("environment"),
			},
```

`database.go`:

1. `approximation` gains:

```go
	// gate is the deciding gate's own ingress fact, when a gate decided, so the
	// finding can say how the gate's openness was established.
	gate model.Fact[bool]
	// byPort: reachability was decided by a known port falling in a range, so
	// the port entered the verdict.
	byPort bool
```

2. `rangesReach` returns `(reaches, wider, byPort bool)`. Every `return true, false` inside the `!port.IsKnown()` branch and the protocol early-return become `return …, …, false`; the final containment loop becomes:

```go
	wanted := model.PortRange{From: port.Get(), To: port.Get()}
	everyPort := false
	for _, admitted := range ported {
		if admitted.Ports.Contains(model.PortRange{From: 1, To: 65535}) {
			everyPort = true
		}
	}
	for _, admitted := range ported {
		if admitted.Ports.Contains(wanted) {
			// A range admitting every usable port reaches the database whatever
			// it listens on, so the port did not decide.
			return true, false, !everyPort
		}
	}
	return false, false, false
```

3. In `admitsAnyAddress`, the reaching branch:

```go
		reaches, wider, byPort := rangesReach(gate.Network.OpenToAnyAddress, capabilities.Port)
		if reaches {
			how.widerThanReality = how.widerThanReality || wider
			how.gate = gate.Network.PublicIngress
			how.byPort = byPort
			return model.Known(true, model.MethodReferenceResolved, referencesTo(gate)...), how
		}
```

4. `reachableFinding` gains a `how approximation` parameter (update its caller at `:133` to pass `how`) and builds:

```go
	steps := []evidence.VerificationStep{
		factStep("database.public_endpoint", capabilities.PublicEndpoint),
		factStep("database.admitted_by", admits),
		contractStep("database.exposure"),
	}
	if how.gate.IsKnown() {
		steps = append(steps, factStep("network.public_ingress", how.gate))
	}
	if how.byPort {
		steps = append(steps, factStep("database.port", capabilities.Port))
	}
```

and sets `VerificationSteps: steps` on the finding.

5. `evidence/doc.go`: `const SchemaVersion = "1.3"`.

- [ ] **Step 5: Run everything and fix hand-built bundles**

Run: `go test ./...`
Expected: the new tests PASS. Any test that hand-builds a bundle with `SchemaVersion: evidence.SchemaVersion` and findings without steps now fails validation (`internal/evidence/bundle_test.go`'s `blockBundle`, `warnFinding`, `infoFinding`; `internal/render/*_test.go`; `internal/mcp`). Fix each by giving its findings a step — e.g. in `blockBundle`:

```go
				VerificationSteps: []VerificationStep{
					{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
					{Fact: "contract.object_storage.exposure", Method: MethodIntentComparison},
				},
```

`warnFinding`: `{Fact: "object_storage.versioning", Method: MethodPlanStatedValue}`; `infoFinding`: `{Fact: "object_storage.public_access", Method: MethodPlanStatedValue}`. This adds data to fixtures; it weakens no assertion. Do **not** touch the 226 baselines; `TestEveryFixtureProducesItsBaselineBundle` must pass through `verdictOnly`.

Render goldens fail here too; leave them failing — Task 8 owns them. Run `go test ./... 2>&1 | grep FAIL` and confirm the only failures are in `internal/render`, `docs/examples` comparison and `cmd/infraproof` goldens.

- [ ] **Step 6: Commit**

```bash
git add internal
git commit -m "feat(policy): every finding says how it knows; bundle 1.3

Render goldens are re-recorded in the next commit.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Rendering, goldens and the bundle contract

**Files:**
- Modify: `internal/render/markdown.go:76-102`
- Modify: `internal/render/testdata/{pass,redacted}.golden.json`, `{pass,redacted,block}.golden.md`, `docs/examples/evidence-bundle.json`, `cmd/infraproof/testdata/inspect-nested-modules.golden.json`
- Modify: `docs/EVIDENCE-BUNDLE.md`
- Test: `internal/render/markdown_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/render/markdown_test.go`:

```go
func TestAFindingSaysHowItWasVerified(t *testing.T) {
	b := blockingBundle(t) // use the existing helper that builds a BLOCK bundle; check the file for its name
	out, err := render.Markdown(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"- Verified by: `object_storage.public_access` (plan-stated-value)",
		"- Verified by: `contract.object_storage.exposure` (intent-comparison)",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
```

Adapt the helper name and the two step facts to whatever the bundle built in `markdown_test.go:24` carries (set its finding's steps explicitly in the test if needed).

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/render/ -run Verified -v`
Expected: FAIL — `missing "- Verified by: …"`.

- [ ] **Step 3: Implement**

In `findingBullets`, after the evidence loop and before the remediation bullet:

```go
	for _, step := range f.VerificationSteps {
		// A fact path is produced by this build, but it goes in a code span like
		// every other path, and the method is from a closed set.
		bullets = append(bullets, fmt.Sprintf("- Verified by: %s (%s)",
			code(step.Fact), inlineText(string(step.Method))))
	}
```

and raise the capacity hint to `5+len(f.Evidence)+len(f.VerificationSteps)`.

- [ ] **Step 4: Re-record the render and example goldens by hand**

These files are not the verdict baseline; they pin rendering. For each failing golden, run the test, read the diff, and confirm it is **only** `schema_version` `1.2`→`1.3` and added `verification_steps` / `Verified by` lines. Then update the file to the new output. For `docs/examples/evidence-bundle.json`, write the steps by hand to match `docs/EVIDENCE-BUNDLE.md`'s example (Step 5).

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 5: Document the contract**

In `docs/EVIDENCE-BUNDLE.md`:

1. Example: `"schema_version": "1.3"`, and in the finding, after `evidence`:

```json
      "verification_steps": [
        { "fact": "contract.object_storage.exposure", "method": "intent-comparison" },
        { "fact": "object_storage.public_access", "method": "plan-stated-value" }
      ],
```

2. Under **Required invariants**, add:

```markdown
- `verification_steps` is the verification method every finding owes: one step per fact the verdict rests on, each a fact path and how it was established. A bundle declaring `1.3` or later carries at least one on every finding. A step carries no value. Steps are ordered by fact, then method, and take part in the total order of findings.
- A verification method is never load-bearing. No decision, disposition or exit code depends on one.
```

3. Under **Enumerations**, add:

````markdown
Verification method:

```text
plan-stated-value | provider-default | policy-document-interpreted | reference-resolved | documented-table | plan-action | intent-comparison
```

A step's fact is a capability path for a plan fact, and `contract.<field>` for the comparison with the intent contract. `policy-document-interpreted` is distinct from `plan-stated-value` because it rests on this build's reading of a policy grammar.
````

4. Under **Compatibility**, prepend to the first bullet: ``verification_steps` arrived in `1.3`: a bundle declaring an earlier minor version is valid without it, and one carrying it must carry it well-formed whatever version it declares.``

Run: `go test ./internal/render/` (the example is compared against the code).
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/render cmd/infraproof/testdata docs/EVIDENCE-BUNDLE.md docs/examples
git commit -m "feat(render): each finding says what verified it; the contract documents 1.3

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Mutation measurement, binary comparison, docs, verification

**Files:**
- Modify: `docs/milestones/10-verification-method.md` (append `## Limitations as built` and the criterion 9 record), `docs/ARCHITECTURE.md` (the `Fact<T>` paragraph near `:65-75`), `docs/PRODUCT.md` (`## What a result means`)

- [ ] **Step 1: Criterion 9 — mutation by hand**

For each site below, change the method to `model.MethodStated`, run `go test ./internal/... 2>&1 | grep -E '^(---|FAIL|ok)'`, record which test failed, and revert with `git checkout -- <file>`:

| site | expected to break |
| --- | --- |
| `aws/database.go` `publicly_accessible` default (both) | `TestAnUnwrittenSwitchIsTheProvidersDefault` |
| `aws/database.go:365` port | `TestAnEngineDerivedPortIsFromTheTable`, `TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate` |
| `aws/aws.go` policy channel | `TestAPolicyGrantIsInterpreted`, `TestAPolicyDocumentGrantIsInterpretedInTheStep` |
| `gcp/database.go:127` | `TestAnUnwrittenIPv4SwitchIsTheProvidersDefault`, `TestTheIPv4DefaultChangesOneStepAndNothingElse` |
| `gcp/database.go:289` | `TestAVersionDerivedPortIsFromTheTable` |
| `gcp/network.go` direction | `TestAnOmittedDirectionIsTheProvidersDefault`, `TestTheDirectionDefaultChangesOneStepAndNothingElse` |
| `gcp/network.go` deny direction (`defaulted = defaulted || deny...`) | `TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault` |
| `gcp/gcp.go` policy_data | `TestAPolicyDataGrantIsInterpreted` |
| `gcp/gcp.go` `statedGrant` (force `false`) | `TestAGrantProvenTwiceTakesTheStatedProof` (gcp) |
| `azure/database.go:322` | `TestATypeDerivedPortIsFromTheTableAndNotInferred` |
| `policy/database.go` `byPort` (force `true`) | `TestThePortStepAppearsOnlyWhenThePortDecided` |

Any site whose mutation breaks nothing is a gap: add the missing test to the task that owns the site, commit it, and re-measure. Record the table, with what actually broke, under `## Criterion 9, measured` in the milestone file.

- [ ] **Step 2: Criterion 8 for fixtures with no baseline**

```bash
S=$SCRATCH/m10-binaries
mkdir -p "$S"
git worktree add "$S/before" 3b50544
(cd "$S/before" && go build -o "$S/infraproof-before" ./cmd/infraproof)
go build -o "$S/infraproof-after" ./cmd/infraproof
```

For every `*.json` under `internal/providers/*/testdata` and `internal/providers/testdata` that is a plan, run both binaries with `check --intent internal/verify/testdata/baseline/intent.json --plan <fixture> --format json` (confirm flag names with `"$S/infraproof-after" check --help`). Pipe the *after* output through `python3 -I -c 'import json,sys; b=json.load(sys.stdin); b["schema_version"]="1.2"; [f.pop("verification_steps",None) for f in b["findings"]]; print(json.dumps(b,indent=2,ensure_ascii=False))'` and the *before* output through the same script without the edits, then `diff`. Expected: no difference for every fixture that existed at `3b50544`; the four new fixtures are listed as new. Record the count in the milestone file. Remove the worktree: `git worktree remove "$S/before"`.

- [ ] **Step 3: Docs**

- `ARCHITECTURE.md`: after the `Fact<T>` states paragraph, add: `A KNOWN fact also carries how it was established -- stated by the plan, a provider default, a documented table, a policy document this build interpreted, or a reference it resolved -- and the constructor requires it, so no mapper can leave it out. A finding's verification steps are those methods, plus the steps only the policy layer knows.`
- `PRODUCT.md`, under **What a result means**, add a paragraph: `Every finding says how each fact behind it was established. A BLOCK resting on a provider default or on this build's reading of a policy document says so, and a reader who trusts only what the plan states can see which findings those are. The method decides nothing.`
- Milestone file: `## Limitations as built`, written from what the tests measure. At minimum: the AWS `vpc_security_group_ids` hop is a step but not a citation; unknowns carry no steps; `CORRELATION_UNRESOLVED` still reaches object storage only; GCP `direction` remains uncited as evidence; the result of Step 1 and Step 2.

- [ ] **Step 4: Full verification**

```bash
gofmt -l .
go vet ./...
go test ./... -count=1
go run ./cmd/infraproof --version
git status --short internal/verify/testdata/baseline
```

Expected: `gofmt` prints nothing; vet clean; all PASS; the last command prints nothing (no baseline touched).

- [ ] **Step 5: Commit**

```bash
git add docs
git commit -m "docs(m10): limitations as built, criterion 8 and 9 measured

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 6: Hand off to review**

Per the project memory, run several independent adversarial review rounds (one worktree each) before the branch merges. Do not merge or push without the user's instruction.
