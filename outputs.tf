output "name_prefix" {
  description = "Prefix applied to every resource name this kit creates."
  value       = local.name_prefix
}

output "account_id" {
  description = "AWS account the baseline was installed into."
  value       = local.account_id
}

output "tags" {
  description = "Tag set applied to every taggable resource this kit creates."
  value       = local.tags
}

###############################################################################
# Logging and audit
###############################################################################

output "audit_log_bucket_name" {
  description = "Bucket receiving CloudTrail and AWS Config data. Object-locked in COMPLIANCE mode."
  value       = aws_s3_bucket.audit.id
}

output "audit_log_bucket_arn" {
  description = "ARN of the audit log bucket."
  value       = aws_s3_bucket.audit.arn
}

output "audit_kms_key_arn" {
  description = "ARN of the customer-managed KMS key encrypting the audit bucket."
  value       = aws_kms_key.audit.arn
}

output "general_log_bucket_name" {
  description = "Bucket for ordinary application, load balancer and access logs. Encrypted, versioned and TLS-only, with no object lock."
  value       = local.general_log_bucket_name
}

output "cloudtrail_arn" {
  description = "ARN of the multi-region organization-independent CloudTrail."
  value       = aws_cloudtrail.this.arn
}

###############################################################################
# Detection
###############################################################################

output "guardduty_detector_id" {
  description = "GuardDuty detector ID, or null when GuardDuty is disabled."
  value       = module.guardduty.id
}

output "config_recorder_name" {
  description = "AWS Config recorder name, or null when Config is disabled."
  value       = one(module.config[*].recorder_name)
}

output "config_rule_names" {
  description = "Names of the AWS Config managed rules making up the conformance set."
  value       = sort([for rule in aws_config_config_rule.conformance : rule.name])
}

###############################################################################
# Access
###############################################################################

output "break_glass_role_arn" {
  description = "ARN of the break-glass administrator role. Assuming it requires MFA."
  value       = module.break_glass_role.arn
}

output "break_glass_trust_policy_json" {
  description = "Trust policy of the break-glass role. Hand this to a reviewer who asks how emergency administrator access is gated."
  value       = local.break_glass_assume_role_policy
}

output "organization_id" {
  description = "ID of the AWS Organization, or null when the account already belonged to one."
  value       = one(module.organization[*].id)
}

###############################################################################
# Network
###############################################################################

output "vpc_id" {
  description = "ID of the two-tier VPC."
  value       = module.vpc.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets, one per availability zone."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets, one per availability zone."
  value       = aws_subnet.private[*].id
}

output "workload_security_group_id" {
  description = "ID of the baseline workload security group: no ingress, unrestricted egress."
  value       = module.workload_security_group.id
}

###############################################################################
# Cost
###############################################################################

output "budget_sns_topic_arn" {
  description = "SNS topic carrying budget alerts. Subscribe AWS Chatbot to it to deliver them into Slack."
  value       = one(aws_sns_topic.budget[*].arn)
}
