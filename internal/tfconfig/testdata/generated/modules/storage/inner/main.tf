# Same type and name as the module above declares. Scoping is per directory, so
# these are two declarations and not an ambiguity.
resource "terraform_data" "inner" {
  input = "inner"
}
