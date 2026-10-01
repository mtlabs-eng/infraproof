resource "terraform_data" "a" {
  triggers_replace = <<EOTÖ
EOT
input = "this line is inside a string"
EOTÖ
  input = "the real one"
}
