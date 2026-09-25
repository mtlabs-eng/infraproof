package declared

// Binding is one governance relation a mapper declares: a resource of type
// From, naming a resource of type To in the argument Attribute, is bound to it.
//
// The relation is declared whole. Deciding it from one end was the defect two
// review rounds were spent on: a filter reading the type of whichever resource
// wrote the reference cannot tell "this control applies to that bucket" from
// "that bucket mentions this control", because the plan records both as a
// reference and the graph stores the edge symmetrically. Naming both types and
// the argument leaves nothing to infer.
//
// It lives here rather than beside the Binder interface because the mappers
// that declare relations cannot import the package that assembles them.
type Binding struct {
	// From is the type that makes the claim.
	From string
	// Attribute is the argument carrying it.
	Attribute string
	// To is the type claimed.
	To string
}
