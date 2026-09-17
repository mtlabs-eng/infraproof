package aws

import "testing"

// TestPolicyGrantsPublic covers the judgement at the centre of the AWS mapper.
// A bucket policy is free-form JSON written by a human, and reading it wrongly
// in either direction is expensive: a false positive trains people to ignore
// the tool, and a false negative is the failure it exists to prevent.
func TestPolicyGrantsPublic(t *testing.T) {
	cases := map[string]struct {
		document           string
		grants, determined bool
	}{
		"principal star": {
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`, true, true,
		},
		"principal aws star": {
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}`, true, true,
		},
		"principal aws list containing star": {
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:example:iam::role/app","*"]}}]}`, true, true,
		},
		"a single statement object rather than a list": {
			`{"Statement":{"Effect":"Allow","Principal":"*"}}`, true, true,
		},
		"a named principal is not everyone": {
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:example:iam::role/app"}}]}`, false, true,
		},
		"a service principal is not everyone": {
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"cloudfront.amazonaws.com"}}]}`, false, true,
		},
		"deny to everyone grants nothing": {
			`{"Statement":[{"Effect":"Deny","Principal":"*"}]}`, false, true,
		},
		"a condition makes a public statement undetermined": {
			`{"Statement":[{"Effect":"Allow","Principal":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-x"}}}]}`,
			false, false,
		},
		"a condition on a private statement decides nothing": {
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:example:iam::role/app"},"Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`,
			false, true,
		},
		"NotPrincipal is a shape this build does not read": {
			`{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"arn:example:iam::role/app"}}]}`, false, false,
		},
		"a public statement after a private one still counts": {
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:example:iam::role/app"}},{"Effect":"Allow","Principal":"*"}]}`,
			true, true,
		},
		"malformed json":      {`{"Statement":[`, false, false},
		"not a policy at all": {`"just a string"`, false, false},
		"empty document":      {``, false, false},
		"no statements":       {`{"Version":"2012-10-17"}`, false, false},
		"a statement that is neither object nor list": {`{"Statement":7}`, false, false},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			grants, determined := policyGrantsPublic(c.document)
			if grants != c.grants || determined != c.determined {
				t.Fatalf("grants=%v determined=%v, want grants=%v determined=%v",
					grants, determined, c.grants, c.determined)
			}
		})
	}
}

// TestPrincipalIsEveryone covers the spellings separately, because the policy
// language accepts several and missing one is a silent false negative.
func TestPrincipalIsEveryone(t *testing.T) {
	cases := map[string]bool{
		`"*"`:                          true,
		`{"AWS":"*"}`:                  true,
		`{"AWS":["*"]}`:                true,
		`{"AWS":["a","*"]}`:            true,
		`{"AWS":"arn:example:iam::x"}`: false,
		`{"AWS":["a","b"]}`:            false,
		`{"CanonicalUser":"*"}`:        false,
		`{"AWS":{"nested":"*"}}`:       false,
		`"arn:example:iam::x"`:         false,
		`7`:                            false,
		``:                             false,
	}

	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			if got := principalIsEveryone([]byte(raw)); got != want {
				t.Fatalf("principalIsEveryone(%s) = %v, want %v", raw, got, want)
			}
		})
	}
}

func TestInterpretsCoversEveryControlItReadsAndNothingElse(t *testing.T) {
	var mapper Mapper

	for _, resourceType := range []string{
		typeBucket, typePublicAccessBlock, typeBucketPolicy,
		typeBucketACL, typeOwnershipControls, typeAccountBlock,
	} {
		if !mapper.Interprets(resourceType) {
			t.Fatalf("%s should be interpreted", resourceType)
		}
	}
	for _, resourceType := range []string{"aws_instance", "azurerm_storage_account", "google_storage_bucket", ""} {
		if mapper.Interprets(resourceType) {
			t.Fatalf("%s should not be interpreted by the AWS storage mapper", resourceType)
		}
	}
	if mapper.IsSubject(typePublicAccessBlock) {
		t.Fatal("a control resource is not a subject in its own right")
	}
}

// TestConditionsThatRestrictNothing covers two readings of a policy that were
// wrong in opposite directions. An empty condition block restricts nothing, and
// treating it as a restriction suppressed a finding the plan supports. An
// unconditional deny to everyone overrides an allow, and reading past it
// reported a bucket public that is not.
func TestConditionsThatRestrictNothing(t *testing.T) {
	cases := map[string]struct {
		document           string
		grants, determined bool
	}{
		"an empty condition restricts nothing": {
			`{"Statement":[{"Effect":"Allow","Principal":"*","Condition":{}}]}`, true, true,
		},
		"a condition with entries restricts something": {
			`{"Statement":[{"Effect":"Allow","Principal":"*","Condition":{"StringEquals":{"a":"b"}}}]}`,
			false, false,
		},
		"an unconditional deny to everyone overrides": {
			`{"Statement":[{"Effect":"Allow","Principal":"*"},{"Effect":"Deny","Principal":"*"}]}`,
			false, false,
		},
		"a conditional deny does not settle it": {
			`{"Statement":[{"Effect":"Allow","Principal":"*"},` +
				`{"Effect":"Deny","Principal":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			true, true,
		},
		"a deny to someone else is irrelevant": {
			`{"Statement":[{"Effect":"Allow","Principal":"*"},` +
				`{"Effect":"Deny","Principal":{"AWS":"arn:example:iam::role/app"}}]}`,
			true, true,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			grants, determined := policyGrantsPublic(c.document)
			if grants != c.grants || determined != c.determined {
				t.Fatalf("grants=%v determined=%v, want grants=%v determined=%v",
					grants, determined, c.grants, c.determined)
			}
		})
	}
}
