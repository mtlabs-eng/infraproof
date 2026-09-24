# InfraProof: UNKNOWN

Public access could not be determined from the supplied plan.

## Subject

- Intent source: `intent.yaml`
- Intent digest: `sha256:0000000000000000000000000000000000000000000000000000000000000000`
- Plan format version: `1.x`
- Plan digest: `sha256:0000000000000000000000000000000000000000000000000000000000000000`

## Verification

| Check | Status | Method |
| --- | --- | --- |
| terraform_plan | PARTIAL | terraform-plan-json |

## Findings

### MEDIUM / INFO - STORAGE_POLICY_SENSITIVE

The bucket policy is marked sensitive and was not read.

- Resource: `aws_s3_bucket.assets` (aws, `registry.terraform.io/hashicorp/aws`)
- Observed: `object_storage.policy_document` (REDACTED)
- Evidence: terraform_plan `aws_s3_bucket.assets` `resource_changes[].change.after.policy` (redacted)
- Remediation: Supply the policy through a non-sensitive attribute, or accept the UNKNOWN result.

## Unknowns

| Check | Required | Reason | Resource | Evidence |
| --- | --- | --- | --- | --- |
| STORAGE_PUBLIC_DETERMINABLE | yes | Public access could not be determined from the supplied plan. | `aws_s3_bucket.assets` | terraform_plan `aws_s3_bucket.assets` `resource_changes[].change.after` |
