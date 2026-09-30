# A local directory whose path happens to spell a registry address. Following a
# remote source as though it were a path lands here, which is how a location
# comes to be reported for a module whose files this build never read.
resource "terraform_data" "x" {
  input = "collision"
}
