package terraformplan

import (
	"reflect"
	"strings"
	"testing"
)

// canary is the literal every sensitive fixture uses for a value the parser
// must never retain.
const canary = "CANARY-SENSITIVE-VALUE-DO-NOT-LEAK"

// findCanary walks an arbitrary value, including unexported fields, and reports
// the path of the first string containing the canary. Reflection is used rather
// than a comparison against the public API so that a value hidden in an
// unexported field cannot pass unnoticed.
func findCanary(v reflect.Value, path, canary string) string {
	switch v.Kind() {
	case reflect.String:
		if strings.Contains(v.String(), canary) {
			return path
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if found := findCanary(v.Field(i), path+"."+v.Type().Field(i).Name, canary); found != "" {
				return found
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if found := findCanary(v.Index(i), path+"["+itoa(i)+"]", canary); found != "" {
				return found
			}
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			if found := findCanary(key, path+".<key>", canary); found != "" {
				return found
			}
			if found := findCanary(v.MapIndex(key), path+"["+key.String()+"]", canary); found != "" {
				return found
			}
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return findCanary(v.Elem(), path, canary)
		}
	}
	return ""
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}

// TestSensitiveValuesNeverEnterTheParsedPlan is the acceptance criterion in its
// strongest form: not "the renderer redacts" but "there is nothing to redact",
// checked over the entire structure including unexported fields.
func TestSensitiveValuesNeverEnterTheParsedPlan(t *testing.T) {
	for _, fixture := range []string{"nested-sensitive", "absent-fields"} {
		t.Run(fixture, func(t *testing.T) {
			raw := fixtureBytes(t, fixture)
			if !strings.Contains(string(raw), canary) {
				t.Fatalf("fixture %s no longer contains the canary; the test would pass vacuously", fixture)
			}

			plan, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if found := findCanary(reflect.ValueOf(plan), "plan", canary); found != "" {
				t.Fatalf("a sensitive value was retained at %s", found)
			}
		})
	}
}

func TestSensitiveLeafIsRedactedAndEmpty(t *testing.T) {
	after := onlyChange(t, "nested-sensitive").After

	secret := after.Field("tags").Field("secret")
	if secret.State() != StateRedacted {
		t.Fatalf("tags.secret state = %q, want %q", secret.State(), StateRedacted)
	}
	if !secret.Sensitive() {
		t.Fatal("tags.secret should report itself sensitive")
	}
	if secret.Text() != "" {
		t.Fatalf("tags.secret retained text %q", secret.Text())
	}
	if got := after.Field("tags").Field("owner").Text(); got != "platform" {
		t.Fatalf("a non-sensitive sibling was lost: tags.owner = %q", got)
	}
}

// TestSensitiveContainerRetainsNoChildren covers "after_sensitive": true at a
// container: the whole subtree is sensitive, so the parser must not descend
// into it at all.
func TestSensitiveContainerRetainsNoChildren(t *testing.T) {
	credentials := onlyChange(t, "nested-sensitive").After.Field("credentials")

	if credentials.State() != StateRedacted {
		t.Fatalf("credentials state = %q, want %q", credentials.State(), StateRedacted)
	}
	if credentials.Len() != 0 || credentials.Keys() != nil {
		t.Fatalf("a redacted container retained %d children", credentials.Len())
	}
	if credentials.Field("password").State() != StateAbsent {
		t.Fatal("a child of a redacted container must not be reachable")
	}
}

func TestSensitiveInsideArrayElement(t *testing.T) {
	rules := onlyChange(t, "nested-sensitive").After.Field("rules")

	if rules.Len() != 2 {
		t.Fatalf("rules length = %d, want 2", rules.Len())
	}
	for i := 0; i < rules.Len(); i++ {
		element := rules.At(i)
		if got := element.Field("token").State(); got != StateRedacted {
			t.Fatalf("rules[%d].token state = %q, want %q", i, got, StateRedacted)
		}
		if got := element.Field("name").Text(); got == "" {
			t.Fatalf("rules[%d].name was lost alongside its sensitive sibling", i)
		}
	}
}

func TestBeforeSensitiveIsHonoured(t *testing.T) {
	before := onlyChange(t, "nested-sensitive").Before

	if got := before.Field("previous_token").State(); got != StateRedacted {
		t.Fatalf("before.previous_token state = %q, want %q", got, StateRedacted)
	}
	if got := before.Field("bucket").Text(); got != "example-assets" {
		t.Fatalf("before.bucket = %q", got)
	}
}

// TestSensitiveAndUnknownReportBoth keeps the two facts separable: a leaf that
// Terraform marks both unknown and sensitive is redacted, and still reports
// that it is unknown.
func TestSensitiveAndUnknownReportBoth(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_db_instance.main",
	      "mode": "managed",
	      "type": "aws_db_instance",
	      "name": "main",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {
	        "actions": ["create"],
	        "before": null,
	        "after": {},
	        "after_unknown": {"password": true},
	        "after_sensitive": {"password": true}
	      }
	    }
	  ]
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	password := plan.ResourceChanges[0].After.Field("password")
	if password.State() != StateRedacted {
		t.Fatalf("state = %q, want %q", password.State(), StateRedacted)
	}
	if !password.Unknown() {
		t.Fatal("a redacted leaf that is also unknown must still report Unknown")
	}
	if !password.Sensitive() {
		t.Fatal("it must also report Sensitive")
	}
}
