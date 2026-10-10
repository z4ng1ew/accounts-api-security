package main

import rego.v1

bad_rds := {"resource": {"aws_db_instance": {"db": {
	"publicly_accessible": true, "storage_encrypted": false, "skip_final_snapshot": true,
	"backup_retention_period": 0, "password": "x",
}}}}

good_rds := {"resource": {"aws_db_instance": {"db": {
	"publicly_accessible": false, "storage_encrypted": true, "skip_final_snapshot": false,
	"backup_retention_period": 14, "deletion_protection": true, "manage_master_user_password": true,
}}}}

test_bad_rds_denied if count(deny) == 6 with input as bad_rds

test_good_rds_allowed if count(deny) == 0 with input as good_rds

test_open_sg_denied if {
	count(deny) == 1 with input as {"resource": {"aws_security_group_rule": {"r": {
		"type": "ingress", "from_port": 5432, "cidr_blocks": ["0.0.0.0/0"]}}}}
}

test_alb_443_allowed if {
	count(deny) == 0 with input as {"resource": {"aws_security_group_rule": {"r": {
		"type": "ingress", "from_port": 443, "cidr_blocks": ["0.0.0.0/0"]}}}}
}

test_weak_trail_denied if {
	count(deny) == 3 with input as {"resource": {"aws_cloudtrail": {"t": {
		"is_multi_region_trail": false}}}}
}

original_iam := json.marshal({"Version": "2012-10-17", "Statement": [
	{"Effect": "Allow", "NotAction": ["iam:DeleteRole", "iam:DeleteUser"], "Resource": "*"},
	{"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "kms:Decrypt"], "Resource": "*"},
]})

test_original_iam_denied if {
	count(deny) == 3 with input as {"resource": {"aws_iam_role_policy": {"p": {"policy": original_iam}}}}
}

fixed_iam := json.marshal({"Version": "2012-10-17", "Statement": [{
	"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
	"Resource": ["arn:aws:secretsmanager:ap-south-1:123456789012:secret:prod/accounts-api/db-AbCdEf"],
}]})

test_fixed_iam_allowed if {
	count(deny) == 0 with input as {"resource": {"aws_iam_role_policy": {"p": {"policy": fixed_iam}}}}
}
