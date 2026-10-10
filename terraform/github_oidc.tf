# T4: CI gets AWS creds only from main + the protected prod-release environment. No static keys.
data "aws_iam_policy_document" "gha_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:environment:prod-release"]
    }
  }
}

resource "aws_iam_role" "gha_push" {
  name               = "gha-accounts-api-ecr-push"
  assume_role_policy = data.aws_iam_policy_document.gha_trust.json
}

data "aws_iam_policy_document" "gha_push" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # API does not support resource scoping
  }
  statement {
    actions = ["ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
    "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage"]
    resources = ["arn:aws:ecr:${var.region}:${data.aws_caller_identity.current.account_id}:repository/accounts-api"]
  }
}

resource "aws_iam_role_policy" "gha_push" {
  name   = "ecr-push-accounts-api"
  role   = aws_iam_role.gha_push.id
  policy = data.aws_iam_policy_document.gha_push.json
}

# ECR repo: immutable tags so a pushed digest/tag can't be overwritten (T1).
resource "aws_ecr_repository" "accounts_api" {
  name                 = "accounts-api"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.accounts_api.arn
  }
}
