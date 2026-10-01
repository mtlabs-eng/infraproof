# The configuration behind examples/tfplan.json, so that the documented
# --config run has something real to point at. The plan was not generated from
# this file and nothing in InfraProof claims it was: the addresses match, which
# is all a reported line rests on.

resource "aws_s3_bucket" "assets" {
  bucket = "example-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
