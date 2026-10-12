# Evidence Bundle contract

## Purpose

The Evidence Bundle is the canonical, machine-readable result of an InfraProof verification. Markdown and future integrations must be derived from this structure.

## Version 1 shape

```json
{
  "schema_version": "1.3",
  "decision": "BLOCK",
  "summary": "The requested private storage change enables public access.",
  "subject": {
    "intent_source": "intent.yaml",
    "intent_digest": "sha256:<hex>",
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
        "cloud": "aws",
        "location": {
          "file": "main.tf",
          "line": 6
        }
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
          "redacted": false,
          "location": {
            "file": "main.tf",
            "line": 6
          }
        }
      ],
      "verification_steps": [
        { "fact": "contract.object_storage.exposure", "method": "intent-comparison" },
        { "fact": "object_storage.public_access", "method": "plan-stated-value" }
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

- `schema_version`, `decision`, `summary`, `subject`, and `verification` are required.
- `summary` states the conclusion. A bundle that does not state its own conclusion is not trustworthy output, so an empty summary is rejected.
- Findings are ordered deterministically by severity descending, then rule ID, then resource address. Remaining fields act as further tiebreaks so that the order is total: two records that differ in any field at all are ordered by content, never by the position a producer wrote them in.
- Unknowns are first-class records, not free-form warnings.
- A `BLOCK` bundle contains at least one finding with `disposition: BLOCK` and evidence.
- A `WARN` bundle contains no blocking finding, at least one finding with `disposition: WARN`, and no unknown with `required: true`. A required unknown escalates the decision to `UNKNOWN`, following the precedence `BLOCK > UNKNOWN > WARN > PASS`; a decision must never understate the evidence that is missing.
- An `UNKNOWN` bundle contains no blocking finding and at least one unknown with `required: true`.
- A `PASS` bundle contains no `BLOCK` or `WARN` finding and no unknown with `required: true`.
- Raw sensitive values never appear.
- Free-text prose is a single line. `summary`, `claim`, `remediation`, and `reason` must not contain a line break. Prose is rendered into documents whose structure is expressed by line breaks and leading characters, so a break in prose would let a claim forge a heading, a list item, or a table row in a report a human is expected to trust. Constraining it here rather than in one renderer keeps the guarantee for every present and future output format.
- A value marked `REDACTED`, `UNKNOWN`, or `ABSENT` carries no value. Only a `KNOWN` fact has a value at all, so an unavailable or sensitive field cannot be presented as one.
- A `location` is optional everywhere it appears, and says where a declaration is written: a path relative to the configuration directory the caller supplied, and a 1-based line. It is present only when a configuration directory was given and the declaration found there matches the address the finding is about. A plan carries no source positions, and nothing ties a plan to the files that produced it, so a location that was merely plausible is worse than none.
- A `location` is never load-bearing. No decision, disposition or exit code may depend on whether one was found, or a verdict would change when a file moved. Being unable to read a configuration directory that was asked for is a separate matter: that is an unreadable input like any other, reported as invalid input rather than as a verdict, and a producer must never emit a location it cannot spell to the rules below — doing so turned a `BLOCK` into an internal failure with no report at all.
- A `location` carries a path and a line and no text from the file. A `.tf` file holds secrets more often than a plan does.
- A location path is relative, uses forward slashes, has no parent segment, carries no control character, is no longer than 4096 bytes and is already in cleaned form. An absolute path — including a drive letter such as `C:/infra/main.tf` — would describe the machine the tool ran on rather than the change.
- Evidence records a location, never a value. An evidence reference has no value field, so raw source data cannot travel through evidence.
- `plan_digest` is calculated over the exact input bytes and allows correlation without embedding the plan.
- `intent_digest` is the same over the intent contract. A path names where a contract was read from, not which contract it was, so without it two different contracts at one path produce identical evidence.
- Both digests are `sha256:` followed by sixty-four lowercase hexadecimal characters, and a bundle carrying anything else is invalid.
- Timestamps are omitted from canonical golden output unless supplied externally.
- `verification_steps` is the verification method every finding owes: one step per fact the verdict rests on, each a fact path and how it was established. A bundle declaring `1.3` or later carries at least one on every finding, and one of them is the comparison with the contract: a `contract.` fact established by `intent-comparison`. A step carries no value. Steps are ordered by fact, then method, and take part in the total order of findings.
- A fact is established once. Two steps naming the same fact -- the same step twice, or one fact with two methods -- are invalid whatever version the bundle declares.
- A step's fact is two or more dot-separated segments, each a lower-case letter followed by lower-case letters, digits or underscores. Fact paths are constants of the build that wrote the bundle, never plan text, so anything else -- markup, a table cell, an invisible or bidirectional character -- is invalid.
- A verification method is never load-bearing. No decision, disposition or exit code depends on one.

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

Verification method:

```text
plan-stated-value | provider-default | prior-state | configuration-unrecorded | policy-document-interpreted | reference-resolved | documented-table | plan-action | intent-comparison
```

| method | means |
| --- | --- |
| `plan-stated-value` | the plan's configuration records that the author wrote the argument |
| `provider-default` | the configuration records the argument as unwritten, and the object is new: the value is the provider's documented default |
| `prior-state` | the configuration records the argument as unwritten, the change updates an existing object, and the value is the one Terraform carried from its prior state |
| `configuration-unrecorded` | the plan does not record whether the author wrote the argument |
| `policy-document-interpreted` | the value results from this build's reading of a JSON policy document |
| `reference-resolved` | the value is obtainable only by resolving a reference: the security groups a database reaches through `vpc_security_group_ids` |
| `documented-table` | the value comes from a closed, documented table in this build |
| `plan-action` | the value is the classification of the plan's actions |
| `intent-comparison` | the fact is the comparison with the intent contract |

- A step's fact is a capability path for a plan fact, and `contract.<field>` or `contract.<family>.<field>` for the comparison with the intent contract; both shapes are emitted (`contract.environment`, `contract.object_storage.exposure`).
- `policy-document-interpreted` is distinct from `plan-stated-value` because it rests on this build's reading of a policy grammar.
- The method follows what the configuration records, never the value: a provider writes its default into the plan as a known value, and Terraform carries an unwritten Computed value across an update, and both look exactly like a value somebody wrote.
- `plan-stated-value` is assigned only on a positive record: the argument appears in the configuration's expressions, or it is Required and the body holding it is recorded. It is never the answer for "cannot tell".
- The configuration records an argument as unwritten only where an absence is itself a record: a top-level attribute of a resource the configuration declares -- including an entry with no expressions, which is how Terraform records an empty body -- or an attribute inside a block the configuration records. A block, or anything inside an unrecorded block, is `configuration-unrecorded` when absent, because Terraform does not record a `dynamic` block. So is everything in a plan with no `configuration` section and every resource the configuration omits.
- One contradiction is settled the other way. An argument that is neither Computed nor a block is planned to its documented default whenever it is unwritten, so a configuration recording it as unwritten beside a value that is not its default records something Terraform cannot produce; the value was written, and is `plan-stated-value`.
- A fact resting on several inputs takes the method of the least established, in this order: `configuration-unrecorded`, `prior-state`, `provider-default`, any method this build derived, `plan-stated-value`. A grant proven several ways at once takes the best of its proofs. Where a grant rests on an interpreted policy document, the method stays `policy-document-interpreted` whatever the configuration methods of the gates beside it.
- `reference-resolved` is narrow. A grant written on its own ACL, IAM binding or firewall-rule resource is established by that resource's arguments; the reference joining it to a bucket or a server only locates where it applies, and does not relabel it.

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

- Minor `1.x` additions must be backward-compatible. `verification_steps` arrived in `1.3`: a bundle declaring an earlier minor version is valid without it, and one carrying it must carry it well-formed whatever version it declares -- every step's fact a well-formed path and its method in the closed set, and no fact established twice. The requirement of a contract step applies from `1.3`, which is when steps became required. `location` arrived in `1.2`, on `resource` and on each evidence reference; a bundle of any version is valid without it. `intent_digest` arrived in `1.1`: a bundle declaring an earlier minor version predates the field and is valid without it, and one carrying the field must carry a well-formed one whatever version it declares.
- Consumers must ignore unknown fields within the same major version.
- Breaking field or semantic changes require a new major version.

The bundle walked through above is kept as `docs/examples/evidence-bundle.json`, and `internal/render` renders against it so that this document and the code cannot drift apart.
