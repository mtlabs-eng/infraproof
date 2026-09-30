# Two declarations of one address. Terraform refuses this file; a build reading
# files it cannot prove produced the plan may still be handed it, and two
# answers to one question is not an answer.

resource "terraform_data" "root" {
  input = "first"
}

resource "terraform_data" "root" {
  input = "second"
}
