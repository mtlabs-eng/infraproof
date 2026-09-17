# Provenance

These plans were produced by Terraform 1.14.0 itself, not written by hand.

| Fixture | Produced from |
| --- | --- |
| `real-aws-for-each-terraform-1.14.json` | two `for_each` buckets, one locked down and one with a public-read ACL and no blocks |
| `real-aws-nested-blocks-terraform-1.14.json` | `count`, `for_each` over a resource, `depends_on`, and an `access_control_policy` block nested three deep |
| `real-aws-keyed-reference-terraform-1.14.json` | two `for_each` buckets, each named by an unrepeated control that refers to one instance by key |
| `real-aws-bare-depends-on-terraform-1.14.json` | the same, plus `depends_on = [aws_s3_bucket.b]` on the control |
| `real-aws-ambiguous-reference-terraform-1.14.json` | the same, with the control reaching its bucket through `lookup(aws_s3_bucket.b, "a")` |

Both came from throwaway configurations using the `aws` provider with
`skip_credentials_validation`, `skip_requesting_account_id` and
`skip_metadata_api_check`, so planning contacted no AWS endpoint. The
placeholder key strings those settings require were removed from the committed
files; no credential was involved at any point, and neither plan was applied.

They exist because the hand-written fixtures in the provider subpackages missed
six shapes that only real output revealed: a nested block is an array of
objects rather than an object, a control resource often names the resource it
controls through `for_each_expression` alone, every instance of a repeated
resource shares one configuration address, a reference names the instance it
uses while the parser was discarding the key, an explicit `depends_on` reaches
the same resource without one, and a control can reach an instance dynamically
so that the plan records no key at all. The first made a canonical S3 stack
unreadable; the other four each reported a public bucket as provably private, by
four different routes.
