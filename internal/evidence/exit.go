package evidence

// Process exit codes. They are part of the public CLI interface: a change to
// any of these values is a breaking change for every consumer that branches on
// them. Operational failures are deliberately separate from decisions.
const (
	// ExitPass reports a PASS decision.
	ExitPass = 0
	// ExitWarn reports a WARN decision.
	ExitWarn = 2
	// ExitBlock reports a BLOCK decision.
	ExitBlock = 3
	// ExitUnknown reports an UNKNOWN decision.
	ExitUnknown = 4
	// ExitInvalidInput reports unusable input or incorrect CLI usage. It is not
	// a verification decision.
	ExitInvalidInput = 10
	// ExitInternal reports an internal failure. It is not a verification
	// decision.
	ExitInternal = 11
)

// ExitCode maps a decision to its process exit code. It never terminates the
// process; only the command entry point does that. An unrecognized decision is
// an internal invariant violation rather than a verdict, so it maps to
// ExitInternal instead of silently reporting success.
func ExitCode(d Decision) int {
	switch d {
	case DecisionPass:
		return ExitPass
	case DecisionWarn:
		return ExitWarn
	case DecisionBlock:
		return ExitBlock
	case DecisionUnknown:
		return ExitUnknown
	default:
		return ExitInternal
	}
}
