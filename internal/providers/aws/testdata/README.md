# Provenance

Every fixture in this directory is **hand-authored** from the current
`aws` provider schema, not produced by Terraform.

That is a real limitation. Milestone 02 showed that hand-written fixtures can
misrepresent a format, and milestone 03 showed it again: three shapes absent
from these files were only found by generating real plans, and one of them hid a
bucket reported as private while being public.

Real plans covering the shapes that matter — repeated resources, nested blocks,
meta-argument references — live in `internal/providers/testdata`. The `aws` provider does plan offline, so these
fixtures could be replaced by generated ones; the real plans already committed
cover the shapes that were getting it wrong.
