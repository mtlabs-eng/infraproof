# Terraform's module loader skips a file whose name begins with a dot, so this
# file is not part of any configuration and no plan was ever made from it.
resource "terraform_data" "root" {
  input = "hidden"
}
