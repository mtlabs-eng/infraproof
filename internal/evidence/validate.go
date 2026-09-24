package evidence

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// identifierPattern constrains stable rule and check identifiers so that they
// remain safe to embed in output and comparable across releases.
var identifierPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// digestPrefix is the only digest algorithm the Version 1 contract defines.
const digestPrefix = "sha256:"

// ValidationError reports one violated bundle invariant. It carries a field
// path and an explanation only; it never carries a fact value, so reporting a
// violation on a sensitive field cannot disclose that field.
type ValidationError struct {
	// Path locates the offending field, such as "findings[0].severity".
	Path string
	// Message explains the violation without quoting any fact value.
	Message string
}

// Error renders the violation as "path: message".
func (e *ValidationError) Error() string {
	return e.Path + ": " + e.Message
}

// violation builds a ValidationError for the given field path.
func violation(path, format string, args ...any) error {
	return &ValidationError{Path: path, Message: fmt.Sprintf(format, args...)}
}

// Validate reports every violated invariant of the Version 1 contract, joined
// into a single error. A bundle that does not validate must not be rendered.
func (b Bundle) Validate() error {
	var errs []error

	errs = append(errs, b.validateEnvelope()...)
	errs = append(errs, b.validateVerification()...)
	for i, f := range b.Findings {
		errs = append(errs, validateFinding(fmt.Sprintf("findings[%d]", i), f)...)
	}
	for i, u := range b.Unknowns {
		errs = append(errs, validateUnknown(fmt.Sprintf("unknowns[%d]", i), u)...)
	}
	errs = append(errs, b.validateDecisionConsistency()...)

	return errors.Join(errs...)
}

// validateEnvelope checks the schema version, decision, summary, and subject.
// inlineFields returns every free-text field of the bundle envelope that
// reaches a report as inline text, with the path to report it under.
//
// It is written as one list per structure rather than as checks scattered
// through the validators, because scattering is how five of these came to be
// missing: each was added to the contract without anyone remembering there was
// a rule to add it to.
func (b Bundle) inlineFields() [][2]string {
	fields := [][2]string{
		{"subject.intent_source", b.Subject.IntentSource},
		{"subject.plan_format_version", b.Subject.PlanFormatVersion},
		// The digests are computed rather than plan-derived, but the rule is
		// about what a field can carry, not about who happens to fill it.
		{"subject.plan_digest", b.Subject.PlanDigest},
		{"subject.intent_digest", b.Subject.IntentDigest},
	}
	for i, check := range b.Verification {
		fields = append(fields,
			[2]string{fmt.Sprintf("verification[%d].name", i), check.Name},
			[2]string{fmt.Sprintf("verification[%d].method", i), check.Method})
	}
	return fields
}

func (b Bundle) validateEnvelope() []error {
	var errs []error

	for _, field := range b.inlineFields() {
		if err := validateSingleLine(field[0], field[1]); err != nil {
			errs = append(errs, err)
		}
	}

	if err := validateSchemaVersion(b.SchemaVersion); err != nil {
		errs = append(errs, err)
	}
	if !b.Decision.Valid() {
		errs = append(errs, violation("decision", "unrecognized decision %q", string(b.Decision)))
	}
	if err := validateProse("summary", b.Summary, "must state the conclusion and must not be empty"); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(b.Subject.IntentSource) == "" {
		errs = append(errs, violation("subject.intent_source", "must not be empty"))
	}
	if strings.TrimSpace(b.Subject.PlanFormatVersion) == "" {
		errs = append(errs, violation("subject.plan_format_version", "must not be empty"))
	}
	if err := validateDigest("subject.plan_digest", b.Subject.PlanDigest); err != nil {
		errs = append(errs, err)
	}
	if err := validateDigest("subject.intent_digest", b.Subject.IntentDigest); err != nil {
		errs = append(errs, err)
	}

	return errs
}

// validateDigest holds a digest field to what the contract says it is: sha256
// over the exact input bytes.
//
// The check was the prefix and a non-blank remainder, so "sha256:the same plan
// as yesterday" passed. A digest is the only thing a reader has to correlate a
// report with the input it came from, and a field that accepts prose is one a
// later producer fills with prose.
func validateDigest(path, value string) error {
	body, ok := strings.CutPrefix(value, digestPrefix)
	if !ok || len(body) != sha256HexLength {
		return violation(path, "must be %q followed by %d hexadecimal characters",
			digestPrefix, sha256HexLength)
	}
	for _, char := range body {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return violation(path, "must be %q followed by %d hexadecimal characters",
				digestPrefix, sha256HexLength)
		}
	}
	return nil
}

// sha256HexLength is how many characters a sha256 digest takes in hexadecimal.
const sha256HexLength = 64

// validateSchemaVersion accepts any "1.<minor>" version. Minor additions are
// backward-compatible within the major version; a different major version is a
// different contract.
func validateSchemaVersion(version string) error {
	major, minor, ok := strings.Cut(version, ".")
	if !ok || strings.Contains(minor, ".") {
		return violation("schema_version", "must be %q formatted as major.minor, got %q", SchemaVersion, version)
	}
	if !isPlainNumber(minor) {
		return violation("schema_version", "minor version must be a plain decimal number without sign or leading zero, got %q", version)
	}
	if major != "1" {
		return violation("schema_version", "unsupported schema_version major version %q; this build implements 1.x", version)
	}
	return nil
}

// validateVerification checks that coverage is recorded and named uniquely.
func (b Bundle) validateVerification() []error {
	var errs []error

	if len(b.Verification) == 0 {
		errs = append(errs, violation("verification", "must record at least one check"))
		return errs
	}

	seen := make(map[string]struct{}, len(b.Verification))
	for i, v := range b.Verification {
		path := fmt.Sprintf("verification[%d]", i)
		// Compare names with surrounding space removed: two entries that a
		// reader cannot tell apart must not both be accepted.
		name := strings.TrimSpace(v.Name)
		if name == "" {
			errs = append(errs, violation(path+".name", "must not be empty"))
		} else if _, dup := seen[name]; dup {
			errs = append(errs, violation(path+".name", "duplicate check name %q", name))
		} else {
			seen[name] = struct{}{}
		}
		if !v.Status.Valid() {
			errs = append(errs, violation(path+".status", "unrecognized verification status %q", string(v.Status)))
		}
		if strings.TrimSpace(v.Method) == "" {
			errs = append(errs, violation(path+".method", `must name the technique used, or "none"`))
		}
	}

	return errs
}

// validateFinding checks one finding and everything it contains.
func validateFinding(path string, f Finding) []error {
	var errs []error

	if !identifierPattern.MatchString(f.RuleID) {
		errs = append(errs, violation(path+".rule_id", "must be a stable identifier matching %s, got %q", identifierPattern, f.RuleID))
	}
	if !f.Severity.Valid() {
		errs = append(errs, violation(path+".severity", "unrecognized severity %q", string(f.Severity)))
	}
	if !f.Disposition.Valid() {
		errs = append(errs, violation(path+".disposition", "unrecognized disposition %q", string(f.Disposition)))
	}
	if err := validateProse(path+".claim", f.Claim, "must state the finding concisely and must not be empty"); err != nil {
		errs = append(errs, err)
	}
	if err := validateProse(path+".remediation", f.Remediation, "must describe the fix or explain why none is available"); err != nil {
		errs = append(errs, err)
	}

	if f.Resource != nil {
		if strings.TrimSpace(f.Resource.Address) == "" {
			errs = append(errs, violation(path+".resource.address", "must not be empty"))
		}
		if err := validateSingleLine(path+".resource.address", f.Resource.Address); err != nil {
			errs = append(errs, err)
		}
		if strings.TrimSpace(f.Resource.Provider) == "" {
			errs = append(errs, violation(path+".resource.provider", "must not be empty"))
		}
		if err := validateSingleLine(path+".resource.provider", f.Resource.Provider); err != nil {
			errs = append(errs, err)
		}
		if !f.Resource.Cloud.Valid() {
			errs = append(errs, violation(path+".resource.cloud", "unrecognized cloud %q", string(f.Resource.Cloud)))
		}
	}

	if f.Expected != nil {
		if strings.TrimSpace(f.Expected.Path) == "" {
			errs = append(errs, violation(path+".expected.path", "must not be empty"))
		}
		if err := validateSingleLine(path+".expected.path", f.Expected.Path); err != nil {
			errs = append(errs, err)
		}
		if !f.Expected.Value.Valid() {
			errs = append(errs, violation(path+".expected.value", "must be built with Bool, String, or Int"))
		}
		if err := validateScalarText(path+".expected.value", f.Expected.Value); err != nil {
			errs = append(errs, err)
		}
	}

	if f.Observed != nil {
		errs = append(errs, validateObserved(path+".observed", *f.Observed)...)
	}

	if f.Disposition == DispositionBlock && len(f.Evidence) == 0 {
		errs = append(errs, violation(path+".evidence", "a BLOCK finding requires at least one evidence reference"))
	}
	errs = append(errs, validateEvidence(path, f.Evidence)...)

	return errs
}

// validateObserved enforces that only a KNOWN fact carries a value. The field
// path is reported; the value never is.
func validateObserved(path string, o ObservedFact) []error {
	var errs []error

	if strings.TrimSpace(o.Path) == "" {
		errs = append(errs, violation(path+".path", "must not be empty"))
	}
	if err := validateSingleLine(path+".path", o.Path); err != nil {
		errs = append(errs, err)
	}
	if err := validateScalarText(path+".value", o.Value); err != nil {
		errs = append(errs, err)
	}
	if !o.State.Valid() {
		errs = append(errs, violation(path+".state", "unrecognized fact state %q", string(o.State)))
	}
	switch {
	case o.State == FactKnown && !o.Value.Valid():
		errs = append(errs, violation(path+".value", "a KNOWN fact at %q must carry a value", o.Path))
	case o.State != FactKnown && o.Value != nil:
		errs = append(errs, violation(path+".value", "the fact at %q must omit its value unless its state is KNOWN", o.Path))
	}

	return errs
}

// validateEvidence checks every evidence reference under the given parent path.
func validateEvidence(parent string, refs []EvidenceRef) []error {
	var errs []error

	for i, ref := range refs {
		path := fmt.Sprintf("%s.evidence[%d]", parent, i)
		if strings.TrimSpace(ref.Source) == "" {
			errs = append(errs, violation(path+".source", "must name the evidence source"))
		}
		if strings.TrimSpace(ref.Path) == "" {
			errs = append(errs, violation(path+".path", "must locate the data within the source"))
		}
		// Every field of a reference reaches a report as inline text, and a
		// reference is assembled from plan-derived strings. The order is fixed
		// rather than a map's, because a tool whose output is a function of its
		// input must not describe one bundle two ways.
		for _, field := range [][2]string{
			{".source", ref.Source},
			{".resource_address", ref.ResourceAddress},
			{".path", ref.Path},
		} {
			if err := validateSingleLine(path+field[0], field[1]); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errs
}

// validateUnknown checks one unknown record.
func validateUnknown(path string, u Unknown) []error {
	var errs []error

	if !identifierPattern.MatchString(u.CheckID) {
		errs = append(errs, violation(path+".check_id", "must be a stable identifier matching %s, got %q", identifierPattern, u.CheckID))
	}
	if err := validateProse(path+".reason", u.Reason, "must explain the gap without quoting a sensitive value"); err != nil {
		errs = append(errs, err)
	}
	if u.ResourceAddress != nil {
		if strings.TrimSpace(*u.ResourceAddress) == "" {
			errs = append(errs, violation(path+".resource_address",
				"must be null rather than empty when no resource applies"))
		}
		if err := validateSingleLine(path+".resource_address", *u.ResourceAddress); err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, validateEvidence(path, u.Evidence)...)

	return errs
}

// validateDecisionConsistency enforces that the decision is supported by the
// records the bundle actually contains. The precedence BLOCK > UNKNOWN > WARN >
// PASS is enforced here, so a decision can never understate the evidence.
func (b Bundle) validateDecisionConsistency() []error {
	var errs []error

	var hasBlocking, blockingEvidenced, hasWarning bool
	for _, f := range b.Findings {
		switch f.Disposition {
		case DispositionBlock:
			hasBlocking = true
			if len(f.Evidence) > 0 {
				blockingEvidenced = true
			}
		case DispositionWarn:
			hasWarning = true
		}
	}

	hasRequiredUnknown := false
	for _, u := range b.Unknowns {
		if u.Required {
			hasRequiredUnknown = true
			break
		}
	}

	switch b.Decision {
	case DecisionBlock:
		if !hasBlocking {
			errs = append(errs, violation("decision", "BLOCK requires at least one finding whose disposition is BLOCK"))
		} else if !blockingEvidenced {
			errs = append(errs, violation("decision", "BLOCK requires a finding with disposition BLOCK that carries evidence"))
		}
	case DecisionWarn:
		if hasBlocking {
			errs = append(errs, violation("decision", "WARN must not contain a finding whose disposition is BLOCK"))
		}
		if !hasWarning {
			errs = append(errs, violation("decision", "WARN requires at least one finding whose disposition is WARN"))
		}
		if hasRequiredUnknown {
			errs = append(errs, violation("decision", "WARN must not contain a required unknown; a required unknown escalates the decision to UNKNOWN"))
		}
	case DecisionUnknown:
		if hasBlocking {
			errs = append(errs, violation("decision", "UNKNOWN must not contain a finding whose disposition is BLOCK"))
		}
		if !hasRequiredUnknown {
			errs = append(errs, violation("decision", "UNKNOWN requires at least one required unknown"))
		}
	case DecisionPass:
		if hasBlocking {
			errs = append(errs, violation("decision", "PASS must not contain a finding whose disposition is BLOCK"))
		}
		if hasWarning {
			errs = append(errs, violation("decision", "PASS must not contain a finding whose disposition is WARN"))
		}
		if hasRequiredUnknown {
			errs = append(errs, violation("decision", "PASS must not contain a required unknown"))
		}
	}

	return errs
}

// validateSingleLine rejects a line break in a field that reaches the report as
// inline text.
//
// The requirement is docs/EVIDENCE-BUNDLE.md's and it is structural: a break
// ends a paragraph, and a code span, and everything after it becomes document
// text. It was first written for the four prose fields, and every field added
// afterwards that carries user-controlled content — a resource address, a
// capability path, a scalar value, an evidence reference — needs the same
// guarantee for the same reason. Enforcing it at the contract means no renderer
// is the only thing standing between a plan value and a forged heading.
//
// The value is never quoted back: it may be a plan value, and an error message
// is output.
func validateSingleLine(path, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return violation(path, "must be a single line; a line break would let this field forge document structure")
	}
	return nil
}

// validateScalarText applies the same rule to a fact value. Only a string
// scalar can carry a break; a boolean or an integer has no room for one.
func validateScalarText(path string, value *Scalar) error {
	if value == nil {
		return nil
	}
	return validateSingleLine(path, value.Display())
}

// validateProse checks a single-line human-readable field. Prose is rendered
// into Markdown as document text, so a line break in it would let a claim or a
// reason forge headings, list items, or table rows in a report a human is
// expected to trust. Rejecting the break at the contract boundary keeps that
// guarantee independent of any one renderer.
func validateProse(path, value, requirement string) error {
	if strings.TrimSpace(value) == "" {
		return violation(path, "%s", requirement)
	}
	if strings.ContainsAny(value, "\r\n") {
		return violation(path, "must be a single line; line breaks are not permitted in rendered prose")
	}
	return nil
}

// isPlainNumber reports whether s is a decimal number written without a sign,
// surrounding space, or leading zero. Version components are compared as text
// across releases, so "1.007" and "1.7" must not both be spellings of the same
// version.
func isPlainNumber(s string) bool {
	if s == "" {
		return false
	}
	if len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
