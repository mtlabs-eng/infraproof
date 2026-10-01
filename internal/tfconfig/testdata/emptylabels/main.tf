# Labels Terraform would refuse. They are here because an address the plan does
# not carry reads as a resource with no type and no name, and a declaration with
# no type and no name would answer it.
resource "" "" {
  input = "nothing"
}
