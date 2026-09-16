package terraformplan

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDigestCoversTheExactInputBytes pins the digest to the bytes the user
// supplied rather than to anything re-encoded, so it can correlate a report
// with a plan file without embedding the plan.
func TestDigestCoversTheExactInputBytes(t *testing.T) {
	raw := fixtureBytes(t, "create")

	sum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(sum[:])

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if plan.Digest != want {
		t.Fatalf("digest = %q, want %q", plan.Digest, want)
	}
	if len(plan.Digest) != len("sha256:")+64 {
		t.Fatalf("digest %q is not a 64-character hex digest", plan.Digest)
	}
	if strings.ToLower(plan.Digest) != plan.Digest {
		t.Fatalf("digest %q should be lowercase hex", plan.Digest)
	}
}

func TestDigestIsSensitiveToEveryByte(t *testing.T) {
	raw := fixtureBytes(t, "create")

	first, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	again, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if first.Digest != again.Digest {
		t.Fatal("identical bytes produced different digests")
	}

	withNewline, err := Parse(append(append([]byte(nil), raw...), '\n'))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if withNewline.Digest == first.Digest {
		t.Fatal("a trailing newline must change the digest")
	}
}

// TestDigestIsProducedForRejectedPlans keeps a rejected plan correlatable: the
// digest is computed before any decoding, so it exists even when parsing fails.
func TestDigestIsProducedForRejectedPlans(t *testing.T) {
	raw := fixtureBytes(t, "unsupported-version")

	plan, err := Parse(raw)
	if err == nil {
		t.Fatal("expected this fixture to be rejected")
	}
	sum := sha256.Sum256(raw)
	if want := "sha256:" + hex.EncodeToString(sum[:]); plan.Digest != want {
		t.Fatalf("digest of a rejected plan = %q, want %q", plan.Digest, want)
	}
}
