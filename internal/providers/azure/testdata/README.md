# Provenance

Every fixture in this directory is **hand-authored** from the current
`azure` provider schema, not produced by Terraform.

That is a real limitation. Milestone 02 showed that hand-written fixtures can
misrepresent a format, and milestone 03 showed it again: three shapes absent
from these files were only found by generating real plans, and one of them hid a
bucket reported as private while being public.

Real plans covering the shapes that matter — repeated resources, nested blocks,
meta-argument references — live in `internal/providers/testdata`. The `azurerm` provider refuses to plan without
authenticating, so these fixtures cannot be replaced by generated ones without
credentials, which CLAUDE.md forbids this project from handling. Of the three
clouds, this one rests most heavily on the schema being read correctly.
