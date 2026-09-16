# Provenance

These plans were produced by Terraform 1.14.0 itself, not written by hand.

| Fixture | Produced from |
| --- | --- |
| `real-aws-for-each-terraform-1.14.json` | two `for_each` buckets, one locked down and one with a public-read ACL and no blocks |
| `real-aws-nested-blocks-terraform-1.14.json` | `count`, `for_each` over a resource, `depends_on`, and an `access_control_policy` block nested three deep |

Both came from throwaway configurations using the `aws` provider with
`skip_credentials_validation`, `skip_requesting_account_id` and
`skip_metadata_api_check`, so planning contacted no AWS endpoint. The
placeholder key strings those settings require were removed from the committed
files; no credential was involved at any point, and neither plan was applied.

They exist because the hand-written fixtures in the provider subpackages missed
three shapes that only real output revealed: a nested block is an array of
objects rather than an object, a control resource often names the resource it
controls through `for_each_expression` alone, and every instance of a repeated
resource shares one configuration address. The first made a canonical S3 stack
unreadable; the third reported a public bucket as provably private.
