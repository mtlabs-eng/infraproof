package declared_test

import (
	"fmt"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// The package is exercised through the mappers, which is where its behaviour
// matters, but it is also the one place the reading rule is written and it is
// shared by every cloud. A defect here is a defect in all three at once, so it
// is worth holding directly as well.

func change(t *testing.T, after string) terraformplan.ResourceChange {
	t.Helper()

	raw := fmt.Sprintf(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "r.b", "mode": "managed", "type": "r", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {%s}}}
	  ]
	}`, after)

	plan, err := terraformplan.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, raw)
	}
	if len(plan.ResourceChanges) != 1 {
		t.Fatalf("changes = %d, want 1", len(plan.ResourceChanges))
	}
	return plan.ResourceChanges[0]
}

func TestEnvironmentReadsAStatedDeclaration(t *testing.T) {
	fact := declared.Environment(
		change(t, `"tags": {"environment": "staging"}`), "tags", model.CloudAWS)

	if !fact.IsKnown() || fact.Get() != "staging" {
		t.Fatalf("fact = %v/%q", fact.State, fact.Get())
	}
	if len(fact.Sources) != 1 {
		t.Fatalf("sources = %v, want one", fact.Sources)
	}
	if got, want := fact.Sources[0].AttributePath, "tags.environment"; got != want {
		t.Errorf("attribute path = %q, want %q", got, want)
	}
	if fact.Sources[0].Cloud != model.CloudAWS {
		t.Errorf("cloud = %q", fact.Sources[0].Cloud)
	}
}

// TestEnvironmentReadsTheAttributeItWasGiven keeps the one provider-specific
// part of this package genuinely parameterized. Every cloud calls the same
// thing something else, and a reader that ignored its argument would work for
// whichever cloud it was written against and silently fail for the others.
func TestEnvironmentReadsTheAttributeItWasGiven(t *testing.T) {
	subject := change(t, `"tags": {"environment": "from-tags"}, "labels": {"environment": "from-labels"}`)

	for attribute, want := range map[string]string{"tags": "from-tags", "labels": "from-labels"} {
		t.Run(attribute, func(t *testing.T) {
			fact := declared.Environment(subject, attribute, model.CloudAWS)
			if !fact.IsKnown() || fact.Get() != want {
				t.Fatalf("fact = %v/%q, want %q", fact.State, fact.Get(), want)
			}
			if got := fact.Sources[0].AttributePath; got != attribute+".environment" {
				t.Errorf("attribute path = %q", got)
			}
		})
	}
}

// TestEveryWayOfNotSayingItIsNotKnown is the rule this package exists to
// enforce, held over every shape an unstated declaration takes. A fact that is
// Known here is compared with the contract; anything else is reported as
// evidence the run did not have, and the difference between those two is the
// difference between a verdict and a guess.
func TestEveryWayOfNotSayingItIsNotKnown(t *testing.T) {
	cases := map[string]struct {
		after string
		want  model.FactState
	}{
		"no attribute":              {`"name": "b"`, model.FactAbsent},
		"the attribute is a string": {`"tags": "environment"`, model.FactAbsent},
		"the attribute is a list":   {`"tags": ["environment"]`, model.FactAbsent},
		"the attribute is empty":    {`"tags": {}`, model.FactAbsent},
		"no matching key":           {`"tags": {"owner": "checkout"}`, model.FactAbsent},
		"the value is a list":       {`"tags": {"environment": ["staging"]}`, model.FactAbsent},
		"the value is a number":     {`"tags": {"environment": 1}`, model.FactAbsent},
		"the value is empty":        {`"tags": {"environment": ""}`, model.FactAbsent},
		"the value is whitespace":   {`"tags": {"environment": "   "}`, model.FactAbsent},
		"the attribute is not yet known": {
			`"tags": null}, "after_unknown": {"tags": true`, model.FactUnknown},
		"the attribute is sensitive": {
			`"tags": {"environment": "staging"}}, "after_sensitive": {"tags": true`, model.FactRedacted},
		"the value is not yet known": {
			`"tags": {"environment": null}}, "after_unknown": {"tags": {"environment": true}`,
			model.FactUnknown},
		"the value is sensitive": {
			`"tags": {"environment": "staging"}}, "after_sensitive": {"tags": {"environment": true}`,
			model.FactRedacted},
		"two declarations disagree": {
			`"tags": {"Environment": "staging", "environment": "production"}`, model.FactUnknown},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fact := declared.Environment(change(t, tc.after), "tags", model.CloudAWS)
			if fact.IsKnown() {
				t.Fatalf("an unstated declaration was read as %q", fact.Get())
			}
			if fact.State != tc.want {
				t.Errorf("state = %q, want %q", fact.State, tc.want)
			}
		})
	}
}

// TestEveryOutcomeCarriesProvenance keeps a fact locatable whatever it says. A
// reader told the environment could not be determined needs to know where the
// tool looked.
func TestEveryOutcomeCarriesProvenance(t *testing.T) {
	for _, after := range []string{
		`"name": "b"`,
		`"tags": {"environment": "staging"}`,
		`"tags": {"environment": ["staging"]}`,
		`"tags": null}, "after_unknown": {"tags": true`,
	} {
		fact := declared.Environment(change(t, after), "tags", model.CloudGCP)
		if len(fact.Sources) == 0 {
			t.Errorf("a fact from %s carries no provenance", after)
			continue
		}
		if fact.Sources[0].ResourceAddress != "r.b" {
			t.Errorf("resource address = %q", fact.Sources[0].ResourceAddress)
		}
	}
}
