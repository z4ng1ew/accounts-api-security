# T7: customer-managed key for accounts-api secrets; only the IRSA role may decrypt.
resource "aws_kms_key" "accounts_api" {
  description             = "accounts-api secrets"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = ["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:TagResource"]
        Resource  = "*"
      },
      {
        Sid       = "AppDecryptViaSecretsManagerOnly"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.accounts_api.arn }
        Action    = ["kms:Decrypt"]
        Resource  = "*"
        Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } }
      }
    ]
  })
}

resource "aws_kms_alias" "accounts_api" {
  name          = "alias/accounts-api"
  target_key_id = aws_kms_key.accounts_api.key_id
}
