resource "aws_secretsmanager_secret" "db" {
  name       = "prod/accounts-api/db"
  kms_key_id = aws_kms_key.accounts_api.arn
  # Rotation via RDS-managed master password / rotation lambda — out of scope, see DECISIONS.md D7.
}

resource "aws_secretsmanager_secret" "kyc" {
  name       = "prod/accounts-api/kyc"
  kms_key_id = aws_kms_key.accounts_api.arn
}
