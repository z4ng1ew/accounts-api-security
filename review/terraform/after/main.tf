# Artefact (b) fixed. Test fixture: MUST PASS policies/conftest/terraform.
#
# DEFECTS, RANKED BY EXPLOITABILITY IN THIS ENVIRONMENT
#  1. publicly_accessible = true  +  SG 5432 from 0.0.0.0/0  (one finding, two halves)
#     The PII database answers on the internet. Mass scanners find open 5432 within hours; username is
#     the default `postgres`, so it is one password-spray or one leaked credential (T3) away from every
#     customer record. No foothold in AWS or the cluster needed. Either half alone is still serious:
#     public flag + any later SG mistake = exposure; open SG + any later subnet mistake = exposure.
#  2. CloudTrail: single-region, no global events, no log-file validation
#     Not an entry point, but it is what lets an attacker who got in (via #1, a leaked key, or the IAM
#     policy in (c)) operate unseen: activity in any other region is not recorded, IAM/STS (global)
#     calls such as CreateAccessKey are not recorded, and logs can be edited without detection.
#     For a regulated bank this also breaks the evidence trail examiners rely on (T10).
#  3. password = var.db_password
#     The master password lands in plaintext in Terraform state and plan output, readable by anyone with
#     state-bucket or CI-log access (far more people than DB admins), and is never rotated.       [T3]
#  4. backup_retention_period = 0  +  skip_final_snapshot = true  (+ no deletion protection)
#     Not how you get in, but it makes a destructive attacker (or a bad `terraform destroy`) final:
#     no point-in-time recovery, no snapshot on delete -> ransomware/deletion = permanent data loss.
#  5. storage_encrypted = false
#     Lowest exploitability inside AWS (needs snapshot sharing or physical media access), but unencrypted
#     snapshots can be shared to any account, and encryption-at-rest is a hard regulatory control.
#     Ranked last on exploitability, not on importance to the examiner.
#
# Fix summary: private, SG-to-SG only, AWS-managed rotating master secret, IAM auth, CMK encryption,
# 14-day PITR + final snapshot + deletion protection, multi-region org trail with validation and
# global events, KMS-encrypted.

resource "aws_db_instance" "accounts" {
  identifier          = "accounts-prod"
  engine              = "postgres"
  instance_class      = "db.r6g.large"
  username            = "accounts_admin"
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.db.id]

  manage_master_user_password   = true                      # stored + rotated in Secrets Manager, never in state
  master_user_secret_kms_key_id = aws_kms_key.rds.arn
  iam_database_authentication_enabled = true

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  backup_retention_period   = 14
  skip_final_snapshot       = false
  final_snapshot_identifier = "accounts-prod-final"
  deletion_protection       = true
  copy_tags_to_snapshot     = true
}

# Only the accounts-api pods' security group (EKS security groups for pods) may reach Postgres.
resource "aws_security_group_rule" "db_ingress" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.accounts_api_pods.id
  security_group_id        = aws_security_group.db.id
  description              = "accounts-api pods only"
}

resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id     # bucket: Object Lock + versioning, log-archive account
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  kms_key_id                    = aws_kms_key.trail.arn
}
