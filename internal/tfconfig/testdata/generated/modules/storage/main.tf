resource "terraform_data" "inner" {
  input = "storage"
}

module "inner" {
  source = "./inner"
}
