package main

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
)

func TestVersionSucceeds(t *testing.T) {
	var stdout, stderr strings.Builder

	if code := run([]string{"--version"}, &stdout, &stderr); code != evidence.ExitPass {
		t.Fatalf("exit code = %d, want %d", code, evidence.ExitPass)
	}
	if !strings.Contains(stdout.String(), "infraproof") {
		t.Fatalf("stdout %q does not identify the program", stdout.String())
	}
	if !strings.Contains(stdout.String(), evidence.SchemaVersion) {
		t.Fatalf("stdout %q does not report the Evidence Bundle schema version", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestHelpSucceeds(t *testing.T) {
	var stdout, stderr strings.Builder

	if code := run([]string{"--help"}, &stdout, &stderr); code != evidence.ExitPass {
		t.Fatalf("exit code = %d, want %d", code, evidence.ExitPass)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("stdout %q does not contain usage", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestUsageErrorsExitTen(t *testing.T) {
	cases := map[string][]string{
		"no arguments":       {},
		"unknown flag":       {"--bogus"},
		"unimplemented verb": {"check", "--intent", "intent.yaml"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder

			code := run(args, &stdout, &stderr)
			if code != evidence.ExitInvalidInput {
				t.Fatalf("exit code = %d, want %d", code, evidence.ExitInvalidInput)
			}
			if stderr.String() == "" {
				t.Fatal("a usage error must explain itself on stderr")
			}
			if stdout.String() != "" {
				t.Fatalf("stdout = %q, want empty on a usage error", stdout.String())
			}
		})
	}
}

// TestHelpDoesNotOverclaim keeps the usage text honest about the boundary of
// this build. It has verification now, and the earlier form of this test — that
// no verification was claimed — no longer describes anything true. What still
// needs holding is the other direction: the two limits a reader would otherwise
// discover only by being wrong about them.
func TestHelpDoesNotOverclaim(t *testing.T) {
	var stdout, stderr strings.Builder

	run([]string{"--help"}, &stdout, &stderr)
	help := stdout.String()

	if !strings.Contains(help, "check") {
		t.Fatal("help does not mention the verification command")
	}
	if !strings.Contains(strings.ToLower(help), "yaml") {
		t.Error("help does not say that the contract must be JSON")
	}
	if !strings.Contains(strings.ToLower(help), "network") {
		t.Error("help does not say that the command reaches no network")
	}
	if strings.Contains(strings.ToLower(help), "live state") {
		t.Error("help mentions live state, which no build has")
	}
}
