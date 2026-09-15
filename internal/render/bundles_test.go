package render_test

import "github.com/mtlabs-eng/infraproof/internal/evidence"

// contractBundle is the bundle equivalent of the reviewed contract example in
// examples/expected-output.json. The parity test in json_test.go anchors the
// renderer to that reviewed document.
func contractBundle() evidence.Bundle {
	return evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      evidence.DecisionBlock,
		Summary:       "The requested private storage change enables public access.",
		Subject: evidence.Subject{
			IntentSource:      "intent.yaml",
			PlanFormatVersion: "1.x",
			PlanDigest:        "sha256:example",
		},
		Verification: []evidence.Verification{
			{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"},
			{Name: "live_state", Status: evidence.VerificationNotAvailable, Method: "none"},
		},
		Findings: []evidence.Finding{
			{
				RuleID:      "STORAGE_PUBLIC",
				Severity:    evidence.SeverityCritical,
				Disposition: evidence.DispositionBlock,
				Claim:       "Object storage permits public access.",
				Resource: &evidence.Resource{
					Address:  "aws_s3_bucket.assets",
					Provider: "registry.terraform.io/hashicorp/aws",
					Cloud:    evidence.CloudAWS,
				},
				Expected: &evidence.ExpectedFact{
					Path:  "object_storage.public_access",
					Value: evidence.Bool(false),
				},
				Observed: evidence.KnownFact("object_storage.public_access", evidence.Bool(true)),
				Evidence: []evidence.EvidenceRef{{
					Source:          "terraform_plan",
					ResourceAddress: "aws_s3_bucket.assets",
					Path:            "resource_changes[].change.after",
				}},
				Remediation: "Disable public access using the provider-supported controls.",
			},
		},
		Unknowns: []evidence.Unknown{{
			CheckID:  "LIVE_STATE_AVAILABLE",
			Required: false,
			Reason:   "InfraProof was run without a live-state collector.",
			Evidence: []evidence.EvidenceRef{},
		}},
	}
}

// passBundle is a clean result: no findings, no unknowns.
func passBundle() evidence.Bundle {
	return evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      evidence.DecisionPass,
		Summary:       "The change matches the declared intent.",
		Subject: evidence.Subject{
			IntentSource:      "intent.yaml",
			PlanFormatVersion: "1.x",
			PlanDigest:        "sha256:example",
		},
		Verification: []evidence.Verification{
			{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"},
		},
		Findings: []evidence.Finding{},
		Unknowns: []evidence.Unknown{},
	}
}

// redactedBundle exercises a sensitive observed fact, a redacted evidence
// reference, and a required unknown attached to a resource.
func redactedBundle() evidence.Bundle {
	address := "aws_s3_bucket.assets"
	return evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      evidence.DecisionUnknown,
		Summary:       "Public access could not be determined from the supplied plan.",
		Subject: evidence.Subject{
			IntentSource:      "intent.yaml",
			PlanFormatVersion: "1.x",
			PlanDigest:        "sha256:example",
		},
		Verification: []evidence.Verification{
			{Name: "terraform_plan", Status: evidence.VerificationPartial, Method: "terraform-plan-json"},
		},
		Findings: []evidence.Finding{{
			RuleID:      "STORAGE_POLICY_SENSITIVE",
			Severity:    evidence.SeverityMedium,
			Disposition: evidence.DispositionInfo,
			Claim:       "The bucket policy is marked sensitive and was not read.",
			Resource: &evidence.Resource{
				Address:  address,
				Provider: "registry.terraform.io/hashicorp/aws",
				Cloud:    evidence.CloudAWS,
			},
			Observed: evidence.RedactedFact("object_storage.policy_document"),
			Evidence: []evidence.EvidenceRef{{
				Source:          "terraform_plan",
				ResourceAddress: address,
				Path:            "resource_changes[].change.after.policy",
				Redacted:        true,
			}},
			Remediation: "Supply the policy through a non-sensitive attribute, or accept the UNKNOWN result.",
		}},
		Unknowns: []evidence.Unknown{{
			CheckID:         "STORAGE_PUBLIC_DETERMINABLE",
			Required:        true,
			Reason:          "Public access could not be determined from the supplied plan.",
			ResourceAddress: &address,
			Evidence: []evidence.EvidenceRef{{
				Source:          "terraform_plan",
				ResourceAddress: address,
				Path:            "resource_changes[].change.after",
			}},
		}},
	}
}
