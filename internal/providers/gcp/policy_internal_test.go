package gcp

import (
	"fmt"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// fieldValue builds a plan value the way a plan would, so these tests exercise
// the same states the parser produces rather than a hand-made approximation.
func fieldValue(t *testing.T, after, unknownMask, sensitiveMask string) terraformplan.Value {
	t.Helper()

	raw := []byte(fmt.Sprintf(`{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "a.b", "mode": "managed", "type": "a", "name": "b", "provider_name": "p",
	    "change": {"actions": ["create"], "before": null, "after": %s,
	               "after_unknown": %s, "after_sensitive": %s}
	  }]
	}`, after, unknownMask, sensitiveMask))

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return plan.ResourceChanges[0].After.Field("f")
}

func TestMemberIsEveryone(t *testing.T) {
	cases := map[string]struct {
		after, unknown, sensitive string
		want                      answer
	}{
		"allUsers":              {`{"f":"allUsers"}`, `{}`, `{}`, answerYes},
		"allAuthenticatedUsers": {`{"f":"allAuthenticatedUsers"}`, `{}`, `{}`, answerYes},
		"a named user":          {`{"f":"user:jane@example.com"}`, `{}`, `{}`, answerNo},
		"a service account":     {`{"f":"serviceAccount:app@example.iam"}`, `{}`, `{}`, answerNo},
		"not yet known":         {`{}`, `{"f":true}`, `{}`, answerUnknown},
		"sensitive":             {`{"f":"allUsers"}`, `{}`, `{"f":true}`, answerRedacted},
		"absent":                {`{}`, `{}`, `{}`, answerUnknown},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := memberIsEveryone(fieldValue(t, c.after, c.unknown, c.sensitive)); got != c.want {
				t.Fatalf("answer = %v, want %v", got, c.want)
			}
		})
	}
}

// TestMembersIncludeEveryone covers the list form. One public member anywhere
// in the list is enough, and an element nobody can read leaves the question
// open rather than closing it favourably.
func TestMembersIncludeEveryone(t *testing.T) {
	cases := map[string]struct {
		after, unknown, sensitive string
		want                      answer
	}{
		"only named members": {
			`{"f":["user:jane@example.com","group:eng@example.com"]}`, `{}`, `{}`, answerNo,
		},
		"a public member among named ones": {
			`{"f":["user:jane@example.com","allUsers"]}`, `{}`, `{}`, answerYes,
		},
		"allAuthenticatedUsers counts": {
			`{"f":["allAuthenticatedUsers"]}`, `{}`, `{}`, answerYes,
		},
		"an unreadable element leaves it open": {
			`{"f":["user:jane@example.com"]}`, `{"f":[false,true]}`, `{}`, answerUnknown,
		},
		"a sensitive element leaves it open": {
			`{"f":["user:jane@example.com","x"]}`, `{}`, `{"f":[false,true]}`, answerRedacted,
		},
		"a public member outranks an unreadable one": {
			`{"f":["allUsers"]}`, `{"f":[false,true]}`, `{}`, answerYes,
		},
		"the whole list is not yet known": {
			`{}`, `{"f":true}`, `{}`, answerUnknown,
		},
		"the whole list is sensitive": {
			`{"f":["allUsers"]}`, `{}`, `{"f":true}`, answerRedacted,
		},
		"not a list at all": {
			`{"f":"allUsers"}`, `{}`, `{}`, answerUnknown,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := membersIncludeEveryone(fieldValue(t, c.after, c.unknown, c.sensitive)); got != c.want {
				t.Fatalf("answer = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPolicyDataGrantsPublic(t *testing.T) {
	public := `{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]}]}`
	private := `{"bindings":[{"role":"roles/storage.admin","members":["user:jane@example.com"]}]}`
	secondBinding := `{"bindings":[{"role":"a","members":["user:x"]},{"role":"b","members":["allAuthenticatedUsers"]}]}`

	cases := map[string]struct {
		after, unknown, sensitive string
		want                      answer
	}{
		"a public binding":          {`{"f":` + quote(public) + `}`, `{}`, `{}`, answerYes},
		"only named members":        {`{"f":` + quote(private) + `}`, `{}`, `{}`, answerNo},
		"public in a later binding": {`{"f":` + quote(secondBinding) + `}`, `{}`, `{}`, answerYes},
		"no bindings at all":        {`{"f":"{}"}`, `{}`, `{}`, answerNo},
		"malformed document":        {`{"f":"{not json"}`, `{}`, `{}`, answerUnknown},
		"not yet known":             {`{}`, `{"f":true}`, `{}`, answerUnknown},
		"sensitive":                 {`{"f":` + quote(private) + `}`, `{}`, `{"f":true}`, answerRedacted},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := policyDataGrantsPublic(fieldValue(t, c.after, c.unknown, c.sensitive)); got != c.want {
				t.Fatalf("answer = %v, want %v", got, c.want)
			}
		})
	}
}

// quote renders a JSON document as a JSON string literal, which is how
// policy_data actually arrives.
func quote(document string) string {
	out := []rune{'"'}
	for _, r := range document {
		if r == '"' || r == '\\' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(append(out, '"'))
}

func TestInterpretsCoversEveryIAMShape(t *testing.T) {
	var mapper Mapper

	for _, resourceType := range []string{typeBucket, typeIAMMember, typeIAMBinding, typeIAMPolicy} {
		if !mapper.Interprets(resourceType) {
			t.Fatalf("%s should be interpreted", resourceType)
		}
	}
	for _, resourceType := range []string{"google_compute_instance", "aws_s3_bucket", ""} {
		if mapper.Interprets(resourceType) {
			t.Fatalf("%s should not be interpreted by the GCP storage mapper", resourceType)
		}
	}
	if mapper.IsSubject(typeIAMMember) {
		t.Fatal("an IAM member is not a subject in its own right")
	}
}
