package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// An attribute a provider marks Optional and Computed is emitted as unknown both
// when the author left it out, where the provider's documented default applies,
// and when it is set from something undetermined, where nothing does. The plan
// gives the two cases the same shape.
//
// Reading every such unknown as unreadable is what made every idiomatic GCP
// firewall undeterminable: `direction` is Optional and Computed, so a create plan
// never states it. Reading every one as the default would invent a fact about the
// interpolated case. The configuration is what separates them, and a plan that
// carries no configuration separates nothing -- so that answers no.
func TestADefaultAppliesOnlyWhenTheConfigurationIsThereToBeSilent(t *testing.T) {
	cases := map[string]struct {
		change terraformplan.ResourceChange
		want   bool
		why    string
	}{
		"the author omitted it": {
			change: terraformplan.ResourceChange{Configured: true, Stated: []string{"allow", "name"}},
			want:   true,
			why:    "a configured resource that does not write the argument left it to the provider",
		},
		"the author wrote it": {
			change: terraformplan.ResourceChange{Configured: true, Stated: []string{"direction", "name"}},
			want:   false,
			why:    "an argument the author wrote carries their value, whatever the plan resolved it to",
		},
		"the plan carries no configuration": {
			change: terraformplan.ResourceChange{Configured: false},
			want:   false,
			why:    "a sanitized plan does not record what was written, so the silence is not the author's",
		},
		"configured and writing nothing at all": {
			change: terraformplan.ResourceChange{Configured: true},
			want:   true,
			why:    "a resource with no arguments wrote no direction either",
		},
		// The guard against the shape that caused this: a plan with no
		// configuration block whose Stated was left populated by a caller must
		// not be read as an author's silence.
		"unconfigured but carrying arguments": {
			change: terraformplan.ResourceChange{Configured: false, Stated: []string{"name"}},
			want:   false,
			why:    "Configured is what makes Stated answerable; arguments without it say nothing",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := declared.Unwritten(c.change, "direction"); got != c.want {
				t.Fatalf("Unwritten = %v, want %v: %s", got, c.want, c.why)
			}
		})
	}
}
