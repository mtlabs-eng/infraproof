terraform {
  required_version = ">= 1.4.0"
}

variable "tag" {
  type    = string
  default = "root"
}

# A declaration whose deciding attribute is written right here.
resource "terraform_data" "root" {
  input = var.tag
}

# A heredoc holding what looks like another declaration. A scanner that does not
# understand heredocs reports the decoy, or shifts every line after it.
resource "terraform_data" "tricky" {
  input = <<-EOT
    resource "terraform_data" "decoy" {
      input = "not a declaration"
    }
  EOT
}

# Braces and quotes inside an interpolation inside a string.
resource "terraform_data" "braces" {
  input = "${join("", ["{", "}"])} } {"
}

module "storage" {
  source = "./modules/storage"
}

module "keyed" {
  source   = "./modules/storage"
  for_each = toset(["eu"])
}
