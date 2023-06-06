terraform {
  required_version = ">= 1.1.9"
  required_providers {
    aws = {
      version = "~> 4.11.0"
      source  = "hashicorp/aws"
    }
  }

  backend "local" {
    path = "./terraform.tfstate"
  }
}

provider "aws" {
  region = "eu-west-1"
}

locals {
  ec2_roles = ["arn:aws:iam::342962594065:role/MAC_TEST"]
}

resource "aws_s3_bucket" "artifact_repo" {
  bucket = "cdh-cli-bmw-artifact-repo"
}

resource "aws_s3_bucket_policy" "artifact_repo" {
  bucket = aws_s3_bucket.artifact_repo.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

resource "aws_s3_bucket_versioning" "artifact_repo" {
  bucket = aws_s3_bucket.artifact_repo.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_acl" "artifact_repo" {
  bucket = aws_s3_bucket.artifact_repo.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifact_repo" {
  bucket = aws_s3_bucket.artifact_repo.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifact_repo" {
  bucket                  = aws_s3_bucket.artifact_repo.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "whitelist" {
  source = "git::ssh://git@git.bmwgroup.net:7999/cdhx/cdh-whitelist.git?ref=96f9085defe4f5abfb95d46cb80bacec7b9688eb"

  stage  = "prod" # one of (dev|prod)
}

data "aws_iam_policy_document" "bucket_policy" {
  statement {
      actions = [
        "s3:GetObject",
        "s3:ListBucket"
      ]
      effect = "Allow"
      resources = ["arn:aws:s3:::cdh-cli-bmw-artifact-repo", "arn:aws:s3:::cdh-cli-bmw-artifact-repo/*"]

      condition {
        test     = "StringEquals"
        values   = module.whitelist.org_ids
        variable = "aws:PrincipalOrgID"
      }

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
  }
  statement {
    actions = ["s3:PutObject", "s3:PutObjectAcl"]
    effect = "Allow"
    resources = ["arn:aws:s3:::cdh-cli-bmw-artifact-repo/*"]
    principals {
      identifiers = local.ec2_roles
      type        = "AWS"
    }
  }
}
