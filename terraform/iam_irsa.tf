# T7: pod identity scoped to exactly one SA in one namespace, reading exactly two secrets.
data "aws_iam_policy_document" "irsa_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_provider_url}:sub"
      values   = ["system:serviceaccount:accounts:accounts-api"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "accounts_api" {
  name                 = "accounts-api-prod"
  assume_role_policy   = data.aws_iam_policy_document.irsa_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "accounts_api" {
  statement {
    sid       = "ReadOwnSecretsOnly"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_secretsmanager_secret.db.arn, aws_secretsmanager_secret.kyc.arn]
  }
}

resource "aws_iam_role_policy" "accounts_api" {
  name   = "accounts-api-secrets"
  role   = aws_iam_role.accounts_api.id
  policy = data.aws_iam_policy_document.accounts_api.json
}
