# The configuration a reader would have written for the plan this repository
# already ships at internal/providers/aws/testdata/public-acl.json. Nothing
# proves it is the configuration that plan was made from, and nothing in this
# build claims so: the addresses match, which is all a location rests on.

resource "aws_s3_bucket" "assets" {
  bucket = "assets"

  tags = {
    owner = "platform"
  }
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read"
}
