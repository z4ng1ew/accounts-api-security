terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

# Authored + validated only (terraform validate). Would be applied to the prod workload account.
provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
