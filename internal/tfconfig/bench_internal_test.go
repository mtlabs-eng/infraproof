package tfconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// BenchmarkAnnotateAtTheReadingBound measures the shape independent review
// found: a lookup happens once per finding and once per evidence reference, so a
// linear scan made the cost findings times declarations. At this build's own
// reading bound that measured nine seconds for four thousand findings.
//
// It is a benchmark rather than a test because a wall-clock assertion is a test
// that fails on a loaded machine. What it guards is reported in the commit that
// changed it, and it is here so the next reader can measure rather than believe.
func BenchmarkAnnotateAtTheReadingBound(b *testing.B) {
	// Sized to sit just inside the run's 8 MiB reading budget. Past it the
	// directory is discarded whole and the benchmark measures a refusal, which
	// is how the first version of this measurement came out sixty times too
	// fast.
	const (
		files        = 16
		perFile      = 9000
		findingCount = 4000
	)

	root := b.TempDir()
	for file := range files {
		var source strings.Builder
		for i := range perFile {
			fmt.Fprintf(&source, "resource \"terraform_data\" \"r%d_%d\" {\n  input = \"x\"\n}\n", file, i)
		}
		name := filepath.Join(root, fmt.Sprintf("f%02d.tf", file))
		if err := os.WriteFile(name, []byte(source.String()), 0o600); err != nil {
			b.Fatalf("write: %v", err)
		}
	}

	plan := terraformplan.Plan{FormatVersion: "1.2"}
	bundle := evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      evidence.DecisionBlock,
		Summary:       "A change the benchmark does not care about.",
		Subject: evidence.Subject{
			IntentSource:      "intent.json",
			IntentDigest:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			PlanFormatVersion: "1.2",
			PlanDigest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		Verification: []evidence.Verification{
			{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"},
		},
		Unknowns: []evidence.Unknown{},
	}
	for i := range findingCount {
		address := fmt.Sprintf("terraform_data.r%d_%d", i%files, i%perFile)
		plan.ResourceChanges = append(plan.ResourceChanges, terraformplan.ResourceChange{
			Address: address,
			Mode:    terraformplan.ModeManaged,
			Type:    "terraform_data",
			Name:    fmt.Sprintf("r%d_%d", i%files, i%perFile),
		})
		bundle.Findings = append(bundle.Findings, evidence.Finding{
			RuleID:      "STORAGE_PUBLIC",
			Severity:    evidence.SeverityCritical,
			Disposition: evidence.DispositionBlock,
			Claim:       "A claim the benchmark does not care about.",
			Resource: &evidence.Resource{
				Address:  address,
				Provider: "registry.terraform.io/hashicorp/aws",
				Cloud:    evidence.CloudAWS,
			},
			Evidence: []evidence.EvidenceRef{{
				Source:          "terraform_plan",
				ResourceAddress: address,
				Path:            "input",
			}},
			Remediation: "A remediation the benchmark does not care about.",
		})
	}

	// Proof that the work is being done rather than refused. Without it a budget
	// that fires reads as a fast implementation.
	located, err := Annotate(bundle, plan, root)
	if err != nil {
		b.Fatalf("Annotate: %v", err)
	}
	if located.Findings[0].Resource.Location == nil {
		b.Fatal("nothing was located, so this benchmark measures a refusal")
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := Annotate(bundle, plan, root); err != nil {
			b.Fatalf("Annotate: %v", err)
		}
	}
}
