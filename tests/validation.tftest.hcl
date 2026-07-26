# Input validation. Every case here is a mistake somebody actually makes on the
# first day of an install, and every one of them should fail at plan time rather
# than half-way through an apply against a live account.

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

run "rejects_a_region_that_is_not_a_region" {
  command = plan

  variables {
    aws_region = "eu-central"
  }

  expect_failures = [var.aws_region]
}

run "rejects_an_org_name_that_would_produce_ugly_resource_names" {
  command = plan

  variables {
    org_name = "Acme Corp"
  }

  expect_failures = [var.org_name]
}

run "rejects_a_bucket_name_too_long_to_suffix" {
  command = plan

  variables {
    # 51 characters: one over the cap that leaves room for "-general".
    audit_log_bucket_name = "acme-production-audit-logs-eu-central-1-abcdefghijk"
  }

  expect_failures = [var.audit_log_bucket_name]
}

run "rejects_a_vpc_range_too_small_to_split" {
  command = plan

  variables {
    vpc_cidr_block = "10.0.0.0/24"
  }

  expect_failures = [var.vpc_cidr_block]
}

run "rejects_a_single_availability_zone" {
  command = plan

  variables {
    availability_zone_count = 1
  }

  expect_failures = [var.availability_zone_count]
}

run "rejects_a_budget_nobody_is_told_about" {
  command = plan

  variables {
    budget_alert_emails = []
  }

  expect_failures = [var.budget_alert_emails]
}

run "rejects_a_malformed_alert_address" {
  command = plan

  variables {
    budget_alert_emails = ["cloud-alerts-at-example.com"]
  }

  expect_failures = [var.budget_alert_emails]
}

run "rejects_log_retention_short_enough_to_fail_a_questionnaire" {
  command = plan

  variables {
    audit_log_retention_days = 30
  }

  expect_failures = [var.audit_log_retention_days]
}

run "rejects_a_break_glass_session_longer_than_four_hours" {
  command = plan

  variables {
    break_glass_max_session_seconds = 28800
  }

  expect_failures = [var.break_glass_max_session_seconds]
}

run "rejects_duplicate_config_rules" {
  command = plan

  variables {
    config_managed_rules = ["CLOUD_TRAIL_ENABLED", "CLOUD_TRAIL_ENABLED"]
  }

  expect_failures = [var.config_managed_rules]
}

run "accepts_the_documented_example_inputs" {
  command = plan

  variables {
    aws_region              = "eu-central-1"
    org_name                = "acme"
    environment             = "prod"
    audit_log_bucket_name   = "acme-prod-audit-logs-eu-central-1"
    vpc_cidr_block          = "10.20.0.0/16"
    availability_zone_count = 2
    monthly_budget_usd      = 500
    budget_alert_emails     = ["cloud-alerts@example.com"]
    create_organization     = true
    organizational_units    = ["Security", "Workloads"]
  }

  assert {
    condition     = length(module.organization) == 1
    error_message = "create_organization must actually create the organization."
  }

  assert {
    condition     = aws_s3_bucket.audit.bucket == "acme-prod-audit-logs-eu-central-1"
    error_message = "The audit bucket must be named exactly as configured; S3 names are global and cannot be guessed at."
  }

  assert {
    condition     = output.general_log_bucket_name == "acme-prod-audit-logs-eu-central-1-general"
    error_message = "The general log bucket must be derived from the audit bucket name with a -general suffix."
  }
}
