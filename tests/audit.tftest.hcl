# Run with: terraform test
#
# Every run below is plan-only against a mocked AWS provider, so the whole suite
# is safe to run on a laptop with no credentials and in CI on a fork. It asserts
# on values the configuration decides, never on values AWS decides.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_availability_zones" {
    defaults = {
      names = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
    }
  }
}

variables {
  aws_region            = "eu-central-1"
  org_name              = "acme"
  environment           = "prod"
  audit_log_bucket_name = "acme-prod-audit-logs"
  monthly_budget_usd    = 500
  budget_alert_emails   = ["cloud-alerts@example.com"]
}

run "audit_bucket_is_immutable_and_encrypted" {
  command = plan

  assert {
    condition     = aws_s3_bucket.audit.object_lock_enabled == true
    error_message = "The audit bucket must have object lock enabled; it cannot be turned on after creation."
  }

  assert {
    condition = anytrue([
      for rule in aws_s3_bucket_object_lock_configuration.audit.rule :
      anytrue([for r in rule.default_retention : r.mode == "COMPLIANCE" && r.days == 365])
    ])
    error_message = "Audit logs must default to 365 days of COMPLIANCE-mode object lock retention."
  }

  assert {
    condition     = aws_s3_bucket_versioning.audit.versioning_configuration[0].status == "Enabled"
    error_message = "Object lock requires versioning; without it the lock configuration is rejected."
  }

  assert {
    condition = anytrue([
      for rule in aws_s3_bucket_server_side_encryption_configuration.audit.rule :
      anytrue([
        for sse in rule.apply_server_side_encryption_by_default :
        sse.sse_algorithm == "aws:kms"
      ])
    ])
    error_message = "The audit bucket must be encrypted with a customer-managed KMS key, not SSE-S3."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.audit.block_public_acls,
      aws_s3_bucket_public_access_block.audit.block_public_policy,
      aws_s3_bucket_public_access_block.audit.ignore_public_acls,
      aws_s3_bucket_public_access_block.audit.restrict_public_buckets,
    ])
    error_message = "The audit bucket must have every public access block setting enabled."
  }

  assert {
    condition     = aws_s3_bucket_ownership_controls.audit.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "Object ownership must be BucketOwnerEnforced so ACLs cannot grant access to anyone."
  }

  assert {
    condition     = aws_kms_key.audit.enable_key_rotation == true
    error_message = "The audit KMS key must rotate automatically."
  }
}

run "audit_bucket_policy_admits_only_the_log_producers" {
  command = plan

  assert {
    condition = anytrue([
      for s in jsondecode(aws_s3_bucket_policy.audit.policy).Statement :
      s.Effect == "Deny"
      && s.Action == "s3:*"
      && try(s.Condition.Bool["aws:SecureTransport"], null) == "false"
      && length(s.Resource) == 2
    ])
    error_message = "The audit bucket policy must deny every action over plaintext HTTP, on the bucket and its objects."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_s3_bucket_policy.audit.policy).Statement :
      try(s.Principal.Service, null) == "cloudtrail.amazonaws.com"
      && s.Action == "s3:PutObject"
      && try(s.Condition.StringEquals["s3:x-amz-acl"], null) == "bucket-owner-full-control"
      && try(s.Condition.StringEquals["aws:SourceAccount"], null) == "123456789012"
    ])
    error_message = "CloudTrail must be allowed to write, but only with bucket-owner-full-control and only from this account."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_s3_bucket_policy.audit.policy).Statement :
      try(s.Principal.Service, null) == "config.amazonaws.com" && s.Action == "s3:PutObject"
    ])
    error_message = "AWS Config must be allowed to deliver configuration snapshots."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.audit.policy).Statement :
      s.Effect == "Deny" || try(s.Principal.Service, "") != ""
    ])
    error_message = "No statement may grant access to an AWS account or IAM principal; only the two log-producing services."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.audit.policy).Statement :
      !can(regex("s3:Delete", jsonencode(s.Action))) || s.Effect == "Deny"
    ])
    error_message = "No statement may allow object deletion in the audit bucket."
  }
}

run "cloudtrail_is_multi_region_and_tamper_evident" {
  command = plan

  assert {
    condition     = aws_cloudtrail.this.is_multi_region_trail == true
    error_message = "A single-region trail misses activity in every other region, which is where it tends to happen."
  }

  assert {
    condition     = aws_cloudtrail.this.include_global_service_events == true
    error_message = "Global service events carry IAM and STS activity and must be included."
  }

  assert {
    condition     = aws_cloudtrail.this.enable_log_file_validation == true
    error_message = "Log file validation is what makes the trail evidence rather than a text file."
  }

  assert {
    condition     = aws_cloudtrail.this.enable_logging == true
    error_message = "A trail that exists but is not logging is worse than no trail: it looks compliant and records nothing."
  }

  assert {
    condition     = aws_cloudtrail.this.is_organization_trail == false
    error_message = "This kit installs a single-account baseline; organization trails belong to a multi-account layout it does not sell."
  }

  assert {
    condition     = aws_cloudtrail.this.s3_key_prefix == "cloudtrail"
    error_message = "The trail must write under the prefix the bucket policy grants, or delivery fails with AccessDenied."
  }
}

run "config_records_everything_and_runs_the_conformance_set" {
  command = plan

  assert {
    condition     = length(aws_config_config_rule.conformance) == 14
    error_message = "The conformance set must contain the 14 default managed rules."
  }

  assert {
    condition = alltrue([
      for name in ["root-account-mfa-enabled", "cloud-trail-enabled", "vpc-flow-logs-enabled", "encrypted-volumes"] :
      contains([for rule in aws_config_config_rule.conformance : rule.name], name)
    ])
    error_message = "The conformance set must include the root MFA, CloudTrail, flow log and volume encryption rules."
  }

  assert {
    condition = alltrue([
      for rule in aws_config_config_rule.conformance : rule.source[0].owner == "AWS"
    ])
    error_message = "Every rule in the conformance set must be an AWS managed rule; this kit ships no custom Lambda rules."
  }
}

run "everything_taggable_carries_the_account_tag_set" {
  command = plan

  assert {
    condition = alltrue([
      for key in ["Environment", "Owner", "ManagedBy", "Baseline"] :
      contains(keys(aws_s3_bucket.audit.tags), key)
    ])
    error_message = "The audit bucket must carry the full kit tag set."
  }

  assert {
    condition     = aws_kms_key.audit.tags["Baseline"] == "cloud-baseline-kit"
    error_message = "The Baseline tag is how an operator tells kit-managed resources from everything else."
  }

  assert {
    condition     = aws_subnet.private[0].tags["Tier"] == "private"
    error_message = "Subnets must be tagged with their tier so cost and network reports can split them."
  }
}

run "kit_tags_win_over_consumer_supplied_tags" {
  command = plan

  variables {
    additional_tags = {
      ManagedBy = "clickops"
      CostCode  = "cc-1234"
    }
  }

  assert {
    condition     = aws_s3_bucket.audit.tags["ManagedBy"] == "terraform"
    error_message = "A consumer tag must not be able to overwrite a kit-owned tag key."
  }

  assert {
    condition     = aws_s3_bucket.audit.tags["CostCode"] == "cc-1234"
    error_message = "Consumer tags that do not collide must be merged in."
  }
}

run "budget_alerts_on_both_actual_and_forecast_spend" {
  command = plan

  assert {
    condition     = aws_budgets_budget.monthly.limit_amount == "500.00"
    error_message = "The budget limit must be the configured monthly amount, formatted the way the Budgets API returns it."
  }

  assert {
    condition     = aws_budgets_budget.monthly.time_unit == "MONTHLY"
    error_message = "The budget must be monthly."
  }

  assert {
    condition = anytrue([
      for n in aws_budgets_budget.monthly.notification :
      n.notification_type == "ACTUAL" && n.threshold == 80 && contains(n.subscriber_email_addresses, "cloud-alerts@example.com")
    ])
    error_message = "There must be an actual-spend alert at 80 percent going to the configured addresses."
  }

  assert {
    condition = anytrue([
      for n in aws_budgets_budget.monthly.notification :
      n.notification_type == "FORECASTED" && n.threshold == 100
    ])
    error_message = "There must be a forecast alert at 100 percent, which is what gives warning before the money is spent."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_sns_topic_policy.budget[0].policy).Statement :
      try(s.Principal.Service, null) == "budgets.amazonaws.com" && s.Action == "SNS:Publish"
    ])
    error_message = "The budget SNS topic must allow the budgets service to publish, or the Slack path silently never fires."
  }
}

run "break_glass_role_cannot_be_entered_without_mfa" {
  command = plan

  assert {
    condition = alltrue([
      for s in jsondecode(output.break_glass_trust_policy_json).Statement :
      try(s.Condition.Bool["aws:MultiFactorAuthPresent"], null) == "true"
    ])
    error_message = "Every statement in the break-glass trust policy must require MFA."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(output.break_glass_trust_policy_json).Statement :
      contains(s.Principal.AWS, "arn:aws:iam::123456789012:root")
    ])
    error_message = "With no explicit trusted principals the role must fall back to the account root, not to a wildcard."
  }
}

run "detection_can_be_switched_off_wholesale" {
  command = plan

  variables {
    enable_config    = false
    enable_guardduty = false
  }

  assert {
    condition     = length(module.config) == 0
    error_message = "Disabling Config must remove the recorder, not merely stop it."
  }

  assert {
    condition     = length(aws_config_config_rule.conformance) == 0
    error_message = "Config rules without a recorder evaluate nothing and must not be created."
  }

  assert {
    condition     = length(aws_iam_policy.config_delivery) == 0
    error_message = "The Config delivery policy must not linger when Config is disabled."
  }

  assert {
    condition     = aws_cloudtrail.this.enable_logging == true
    error_message = "CloudTrail is not optional in this kit and must survive turning the detection services off."
  }
}
