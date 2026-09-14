# Evidence Bundle contract

## Purpose

The Evidence Bundle is the canonical, machine-readable result of an InfraProof verification. Markdown and future integrations must be derived from this structure.

## Version 1 shape

```json
{
  "schema_version": "1.0",
  "decision": "BLOCK",
  "summary": "The requested private storage change enables public access.",
  "subject": {
    "intent_source": "intent.yaml",
    "plan_format_version": "1.x",
    "plan_digest": "sha256:<hex>"
  },
  "verification": [
    {
      "name": "terraform_plan",
      "status": "VERIFIED",
      "method": "terraform-plan-json"
    },
    {
      "name": "live_state",
      "status": "NOT_AVAILABLE",
      "method": "none"
    }
  ],
  "findings": [
    {
      "rule_id": "STORAGE_PUBLIC",
      "severity": "CRITICAL",
      "disposition": "BLOCK",
      "claim": "Object storage permits public access.",
      "resource": {
        "address": "aws_s3_bucket.assets",
        "provider": "registry.terraform.io/hashicorp/aws",
        "cloud": "aws"
      },
      "expected": {
        "path": "object_storage.public_access",
        "value": false
      },
      "observed": {
        "path": "object_storage.public_access",
        "state": "KNOWN",
        "value": true
      },
      "evidence": [
        {
          "source": "terraform_plan",
          "resource_address": "aws_s3_bucket.assets",
          "path": "resource_changes[].change.after",
          "redacted": false
        }
      ],
      "remediation": "Disable public access using the provider-supported controls."
    }
  ],
  "unknowns": [
    {
      "check_id": "LIVE_STATE_AVAILABLE",
      "required": false,
      "reason": "InfraProof was run without a live-state collector.",
      "resource_address": null,
      "evidence": []
    }
  ]
}
```

## Required invariants

- `schema_version`, `decision`, `subject`, and `verification` are required.
- Findings are ordered deterministically by severity, rule ID, and resource address.
- Unknowns are first-class records, not free-form warnings.
- A `BLOCK` bundle contains at least one finding with `disposition: BLOCK` and evidence.
- A `WARN` bundle contains no blocking finding and at least one finding with `disposition: WARN`.
- An `UNKNOWN` bundle contains no blocking finding and at least one unknown with `required: true`.
- A `PASS` bundle contains no `BLOCK` or `WARN` finding and no unknown with `required: true`.
- Raw sensitive values never appear.
- `plan_digest` is calculated over the exact input bytes and allows correlation without embedding the plan.
- Timestamps are omitted from canonical golden output unless supplied externally.

## Enumerations

Decision:

```text
PASS | WARN | BLOCK | UNKNOWN
```

Severity:

```text
INFO | LOW | MEDIUM | HIGH | CRITICAL
```

Disposition controls the decision effect independently of severity:

```text
INFO | WARN | BLOCK
```

Severity communicates impact. Disposition communicates enforcement. A high-severity observation can therefore remain informational under a particular contract, while a lower-severity but explicit intent violation can block.

Fact state:

```text
KNOWN | UNKNOWN | ABSENT | REDACTED
```

Verification status:

```text
VERIFIED | PARTIAL | NOT_AVAILABLE | FAILED
```

Unknown record:

```text
check_id: stable identifier
required: whether its absence prevents PASS
reason: safe human-readable explanation
resource_address: optional affected resource
evidence: zero or more non-sensitive source locations
```

## Exit codes

Planned initial contract:

```text
0  PASS
2  WARN
3  BLOCK
4  UNKNOWN
10 invalid input or CLI usage
11 internal failure
```

Exact codes are part of the public interface and require tests before release.

## Compatibility

- Minor `1.x` additions must be backward-compatible.
- Consumers must ignore unknown fields within the same major version.
- Breaking field or semantic changes require a new major version.
