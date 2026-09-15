package evidence

import "testing"

func TestExitCode(t *testing.T) {
	cases := map[Decision]int{
		DecisionPass:    0,
		DecisionWarn:    2,
		DecisionBlock:   3,
		DecisionUnknown: 4,
	}
	for decision, want := range cases {
		t.Run(string(decision), func(t *testing.T) {
			if got := ExitCode(decision); got != want {
				t.Fatalf("ExitCode(%q) = %d, want %d", decision, got, want)
			}
		})
	}
}

func TestExitCodeOfUnrecognizedDecisionIsInternalFailure(t *testing.T) {
	if got := ExitCode("MAYBE"); got != ExitInternal {
		t.Fatalf("ExitCode of an unrecognized decision = %d, want %d", got, ExitInternal)
	}
}

func TestOperationalExitCodes(t *testing.T) {
	if ExitInvalidInput != 10 {
		t.Fatalf("ExitInvalidInput = %d, want 10", ExitInvalidInput)
	}
	if ExitInternal != 11 {
		t.Fatalf("ExitInternal = %d, want 11", ExitInternal)
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	codes := map[string]int{
		"PASS":          ExitCode(DecisionPass),
		"WARN":          ExitCode(DecisionWarn),
		"BLOCK":         ExitCode(DecisionBlock),
		"UNKNOWN":       ExitCode(DecisionUnknown),
		"invalid input": ExitInvalidInput,
		"internal":      ExitInternal,
	}
	for name, code := range codes {
		if other, ok := seen[code]; ok {
			t.Fatalf("exit code %d is shared by %q and %q", code, other, name)
		}
		seen[code] = name
	}
}
