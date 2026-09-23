# InfraProof: BLOCK

The requested private storage change enables public access.

## Subject

- Intent source: `intent.yaml`
- Plan format version: `1.x`
- Plan digest: `sha256:example`

## Verification

| Check | Status | Method |
| --- | --- | --- |
| terraform_plan | VERIFIED | terraform-plan-json |
| live_state | NOT_AVAILABLE | none |

## Findings

### CRITICAL / BLOCK - STORAGE_PUBLIC

Object storage permits public access.

- Resource: `aws_s3_bucket.assets` (aws, `registry.terraform.io/hashicorp/aws`)
- Expected: `object_storage.public_access` = `false`
- Observed: `object_storage.public_access` = `true` (KNOWN)
- Evidence: terraform_plan `aws_s3_bucket.assets` `resource_changes[].change.after`
- Remediation: Disable public access using the provider-supported controls.

## Unknowns

| Check | Required | Reason | Resource | Evidence |
| --- | --- | --- | --- | --- |
| LIVE_STATE_AVAILABLE | no | InfraProof was run without a live-state collector. | - | - |
