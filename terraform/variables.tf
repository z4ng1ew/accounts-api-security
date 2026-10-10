variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "eks_oidc_provider_arn" {
  type    = string
  default = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.ap-south-1.amazonaws.com/id/EXAMPLE"
}

variable "eks_oidc_provider_url" {
  type    = string
  default = "oidc.eks.ap-south-1.amazonaws.com/id/EXAMPLE"
}

variable "github_repo" {
  type    = string
  default = "z4ng1ew/accounts-api-security"
}
