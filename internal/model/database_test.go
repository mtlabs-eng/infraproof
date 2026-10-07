package model_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

// A database is reachable from the internet only when two independent things are
// both true: it has an endpoint outside the private network, and something
// admits every address to it. Neither alone is a finding -- an endpoint nobody is
// admitted to is not reachable, and an allow list in front of no endpoint reaches
// nothing.
//
// The capability keeps the two apart rather than collapsing them into one
// verdict, because a reader whose plan holds one half needs to be told which half
// is missing, and because the halves come from different places: the switch is on
// the database, and the allow list may be a security group that is a subject in
// its own right.
func TestTheZeroDatabaseCapabilityDecidesNothing(t *testing.T) {
	var capabilities model.DatabaseCapabilities

	if capabilities.PublicEndpoint.IsKnown() {
		t.Error("the zero value claims to know whether there is a public endpoint")
	}
	if capabilities.AdmitsAnyAddress.IsKnown() {
		t.Error("the zero value claims to know whether every address is admitted")
	}
	if capabilities.Port.IsKnown() {
		t.Error("the zero value claims to know the port")
	}
	if capabilities.GatedBy != nil {
		t.Error("the zero value names a resource that gates it")
	}
	if capabilities.Withdrawn {
		t.Error("the zero value reports a withdrawn determination")
	}
	// The property all three capabilities share, and the reason the zero value
	// matters: a fact nobody determined must never read as a reassurance.
	if capabilities.PublicEndpoint.Get() || capabilities.AdmitsAnyAddress.Get() {
		t.Error("an undetermined fact reads as true")
	}
}

// TestADatabaseIsItsOwnFamily keeps the three families apart. A resource filed
// under the wrong one is judged by rules written for something else, which is
// what FamilyOf exists to prevent.
func TestADatabaseIsItsOwnFamily(t *testing.T) {
	if model.FamilyDatabase == model.FamilyObjectStorage || model.FamilyDatabase == model.FamilyNetwork {
		t.Fatal("the database family is spelled the same as another")
	}
	if model.FamilyDatabase == model.FamilyUnknown || model.FamilyDatabase == "" {
		t.Fatal("the database family is spelled as the absence of one")
	}

	database := model.NormalizedResource{
		Family:   model.FamilyDatabase,
		Database: &model.DatabaseCapabilities{},
	}
	if database.ObjectStorage != nil || database.Network != nil {
		t.Error("a database carries another family's capabilities")
	}

	graph := model.Graph{Resources: []model.NormalizedResource{database}}
	if got := len(graph.OfFamily(model.FamilyDatabase)); got != 1 {
		t.Errorf("the graph holds %d database resources, want 1", got)
	}
	if got := len(graph.OfFamily(model.FamilyNetwork)); got != 0 {
		t.Errorf("a database answers a query for %d network resources", got)
	}
}
