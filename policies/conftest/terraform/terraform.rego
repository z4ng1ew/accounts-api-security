# IaC policy preventing recurrence of the Section 4(b) and 4(c) defects.
# Run: conftest test --parser hcl2 -p policies/conftest/terraform <dir>/*.tf
# Why custom rules in addition to Checkov: these are the exact defects that reached prod, so we pin
# them as blocking with our own tests, independent of Checkov's default check set and its versioning.
package main

import rego.v1

rds := input.resource.aws_db_instance

# --- 4(b) RDS -------------------------------------------------------------------------------
deny contains msg if {
	some name, r in rds
	r.publicly_accessible == true
	msg := sprintf("RDS %s: publicly_accessible must be false (T6, defect b1)", [name])
}

deny contains msg if {
	some name, r in rds
	not r.storage_encrypted == true
	msg := sprintf("RDS %s: storage_encrypted must be true (defect b5)", [name])
}

deny contains msg if {
	some name, r in rds
	not r.backup_retention_period >= 7
	msg := sprintf("RDS %s: backup_retention_period must be >= 7 (defect b4)", [name])
}

deny contains msg if {
	some name, r in rds
	r.skip_final_snapshot == true
	msg := sprintf("RDS %s: skip_final_snapshot must be false (defect b4)", [name])
}

deny contains msg if {
	some name, r in rds
	not r.deletion_protection == true
	msg := sprintf("RDS %s: deletion_protection must be true (defect b4)", [name])
}

deny contains msg if {
	some name, r in rds
	r.password
	msg := sprintf("RDS %s: use manage_master_user_password, not a password argument (ends up in state; defect b3)", [name])
}

# --- 4(b) security groups: no internet-wide ingress except 443 on load balancers ------------
open_cidrs := {"0.0.0.0/0", "::/0"}

deny contains msg if {
	some name
	r := input.resource.aws_security_group_rule[name]
	r.type == "ingress"
	some cidr in array.concat(object.get(r, "cidr_blocks", []), object.get(r, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
	not r.from_port == 443
	msg := sprintf("SG rule %s: ingress from %s on port %v is not allowed (defect b1)", [name, cidr, r.from_port])
}

# --- 4(b) CloudTrail --------------------------------------------------------------------------
deny contains msg if {
	some name
	t := input.resource.aws_cloudtrail[name]
	some field in ["is_multi_region_trail", "enable_log_file_validation", "include_global_service_events"]
	not t[field] == true
	msg := sprintf("CloudTrail %s: %s must be true (defect b2)", [name, field])
}

# --- 4(c) IAM: no NotAction-allow, no wildcard action, no wildcard resource on sensitive APIs --
iam_docs contains doc if {
	some kind in ["aws_iam_policy", "aws_iam_role_policy"]
	some name
	doc := json.unmarshal(input.resource[kind][name].policy)
}

deny contains "IAM: Allow with NotAction grants everything not listed (defect c1)" if {
	some doc in iam_docs
	some s in doc.Statement
	s.Effect == "Allow"
	s.NotAction
}

deny contains "IAM: Allow with Action '*' is forbidden (defect c1)" if {
	some doc in iam_docs
	some s in doc.Statement
	s.Effect == "Allow"
	"*" in as_array(s.Action)
}

sensitive := {"secretsmanager:GetSecretValue", "kms:Decrypt", "ssm:GetParameter", "s3:GetObject"}

deny contains msg if {
	some doc in iam_docs
	some s in doc.Statement
	s.Effect == "Allow"
	some a in as_array(s.Action)
	a in sensitive
	"*" in as_array(s.Resource)
	msg := sprintf("IAM: %s on Resource '*' — scope to specific ARNs (defect c2)", [a])
}

as_array(x) := x if is_array(x)
as_array(x) := [x] if not is_array(x)
