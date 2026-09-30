# Outside every configuration root a test gives the guard. Reading this file at
# all is the failure; its contents only make that visible.
resource "terraform_data" "x" {
  input = "outside"
}
