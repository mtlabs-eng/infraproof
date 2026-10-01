# Configuration fixtures

## generated/

Written by hand and then run through Terraform v1.14.0, which produced
`plan.json` from these exact files: `terraform init -backend=false`,
`terraform plan -out`, `terraform show -json`. Every resource is
`terraform_data`, a builtin, so no provider was downloaded and nothing
contacted a network.

It is the one fixture where the plan and the configuration are genuinely the
same declaration seen twice, which is what makes it worth having: every
expectation in the locator's tests can be read off the files.

It carries the cases a scanner gets wrong:

- a heredoc containing what looks like a resource declaration (`tricky`),
- braces and quotes inside an interpolation inside a string (`braces`),
- a local module reached twice, once plainly and once through `for_each`,
- a module inside a module,
- the same type and name declared in two directories, which is legal and must
  stay two declarations.

## aws/

Hand-written, to match the addresses of the plan at
`internal/providers/aws/testdata/public-acl.json`. It exists because that plan
produces a real `STORAGE_PUBLIC` finding and this shows what a located one looks
like end to end. The plan was not generated from these files and no test claims
it was.
