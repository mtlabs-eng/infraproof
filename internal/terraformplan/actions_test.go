package terraformplan

import (
	"reflect"
	"testing"
)

// TestReplaceOrderingIsPreserved covers the acceptance criterion directly.
// ["delete","create"] and ["create","delete"] are different plans — the second
// is create_before_destroy — so collapsing either into a synthetic "replace"
// would discard the distinction a reviewer most needs.
func TestReplaceOrderingIsPreserved(t *testing.T) {
	deleteFirst := onlyChange(t, "replace-delete-create")
	createFirst := onlyChange(t, "replace-create-delete")

	if want := []Action{ActionDelete, ActionCreate}; !reflect.DeepEqual(deleteFirst.Actions, want) {
		t.Fatalf("actions = %v, want %v", deleteFirst.Actions, want)
	}
	if want := []Action{ActionCreate, ActionDelete}; !reflect.DeepEqual(createFirst.Actions, want) {
		t.Fatalf("actions = %v, want %v", createFirst.Actions, want)
	}
	if reflect.DeepEqual(deleteFirst.Actions, createFirst.Actions) {
		t.Fatal("the two replace orderings must not be equal")
	}

	for _, change := range []ResourceChange{deleteFirst, createFirst} {
		if !change.IsReplace() {
			t.Fatalf("%v should be recognized as a replace", change.Actions)
		}
		if !change.IsDestructive() {
			t.Fatalf("%v should be recognized as destructive", change.Actions)
		}
	}
	if deleteFirst.CreateBeforeDestroy() {
		t.Fatal("delete-then-create is not create_before_destroy")
	}
	if !createFirst.CreateBeforeDestroy() {
		t.Fatal("create-then-delete is create_before_destroy")
	}
}

func TestSingleActionShapes(t *testing.T) {
	cases := map[string]struct {
		actions     []Action
		replace     bool
		destructive bool
	}{
		"create":           {[]Action{ActionCreate}, false, false},
		"update":           {[]Action{ActionUpdate}, false, false},
		"delete":           {[]Action{ActionDelete}, false, true},
		"no-op":            {[]Action{ActionNoOp}, false, false},
		"data-source-read": {[]Action{ActionRead}, false, false},
	}

	for fixture, want := range cases {
		t.Run(fixture, func(t *testing.T) {
			change := onlyChange(t, fixture)
			if !reflect.DeepEqual(change.Actions, want.actions) {
				t.Fatalf("actions = %v, want %v", change.Actions, want.actions)
			}
			if change.IsReplace() != want.replace {
				t.Fatalf("IsReplace = %v, want %v", change.IsReplace(), want.replace)
			}
			if change.IsDestructive() != want.destructive {
				t.Fatalf("IsDestructive = %v, want %v", change.IsDestructive(), want.destructive)
			}
		})
	}
}

// TestUnrecognizedActionIsCarriedNotRejected keeps a future Terraform from
// breaking the parser outright. The action is preserved and reported invalid so
// the policy layer can refuse to conclude, rather than being silently dropped
// or treated as safe.
// The example verb was "forget" until Terraform 1.14 made it real, for a
// removed block. Carrying an actual action as the illustration of an unknown
// one would have tested nothing once this build learned it.
func TestUnrecognizedActionIsCarriedNotRejected(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets",
	      "mode": "managed",
	      "type": "aws_s3_bucket",
	      "name": "assets",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {"actions": ["evaporate"], "before": null, "after": {}}
	    }
	  ]
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("an unrecognized action must not fail the parse: %v", err)
	}
	change := plan.ResourceChanges[0]
	if want := []Action{Action("evaporate")}; !reflect.DeepEqual(change.Actions, want) {
		t.Fatalf("actions = %v, want %v", change.Actions, want)
	}
	if change.Actions[0].Valid() {
		t.Fatal("an unrecognized action must not report itself valid")
	}
	if change.IsDestructive() {
		t.Fatal("an unrecognized action must not be assumed destructive or safe")
	}
}

func TestEmptyActionsIsRejected(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets",
	      "mode": "managed",
	      "type": "aws_s3_bucket",
	      "name": "assets",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {"actions": [], "before": null, "after": {}}
	    }
	  ]
	}`)

	if _, err := Parse(raw); err == nil {
		t.Fatal("a change with no actions should be rejected")
	}
}
