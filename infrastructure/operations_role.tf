provider "aws" {
  alias = "us"
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

module "operations_role" {
  source = "git::ssh://git@git.bmwgroup.net:7999/cdhx/cdh-operations.git//modules/operations_role?ref=2cf699e796c50d64111e668e71fd70f9a8014ffd"
  admin_role_name = "CDHX-DevOps"
  auth_account_id = "402318116903"
  saml_provider_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:saml-provider/authorization.bmwgroup.net"
  providers = {
    aws.eu = aws
    aws.us = aws.us
  }
}