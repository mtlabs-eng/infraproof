# The configuration root of the escaping fixtures. It declares a resource so
# that a module source which leaves this directory and comes back to it has
# something to find here, which is what makes the refusal visible.

resource "terraform_data" "x" {
  input = "root"
}

module "shared" {
  source = "../outside"
}
