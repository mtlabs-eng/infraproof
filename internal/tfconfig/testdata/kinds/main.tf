# A data source and a managed resource sharing a type and a name. They are two
# declarations, and only one of them is what the plan is about.

data "terraform_data" "root" {
  input = "read"
}

resource "terraform_data" "root" {
  input = "managed"
}
