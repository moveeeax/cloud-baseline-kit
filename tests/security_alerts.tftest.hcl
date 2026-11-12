# Security alerting: GuardDuty findings, root console sign-ins and break-glass
# assumption, all delivered to one SNS topic. Plan-only against a mocked
# provider, like the rest of the suite; every asserted value is one the
# configuration decides.

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

run "guardduty_findings_reach_the_alert_topic" {
  command = plan

  assert {
    condition     = aws_sns_topic.security_alerts[0].name == "acme-prod-security-alerts"
    error_message = "The security alert topic must be named <prefix>-security-alerts."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_event_rule.guardduty_findings[0].event_pattern).source == ["aws.guardduty"]
      && jsondecode(aws_cloudwatch_event_rule.guardduty_findings[0].event_pattern)["detail-type"] == ["GuardDuty Finding"]
    )
    error_message = "The GuardDuty rule must match GuardDuty Finding events and nothing else."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.guardduty_findings[0].event_pattern).detail.severity == [{ numeric = [">=", 7] }]
    error_message = "By default only findings of severity 7 (High) and above may alert."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_target.guardduty_findings[0].input_transformer[0].input_template).source == "custom"
    error_message = "The alert must be shaped as a Chatbot custom notification, or Chatbot drops it."
  }

  assert {
    condition     = aws_cloudwatch_event_target.guardduty_findings[0].input_transformer[0].input_paths.severity == "$.detail.severity"
    error_message = "The alert text must carry the finding severity."
  }

  assert {
    condition     = can(regex("<severity>", aws_cloudwatch_event_target.guardduty_findings[0].input_transformer[0].input_template))
    error_message = "The template placeholders must survive unescaped, or EventBridge has nothing to substitute."
  }
}

run "alert_topic_admits_only_eventbridge_from_this_account" {
  command = plan

  assert {
    condition = anytrue([
      for s in jsondecode(aws_sns_topic_policy.security_alerts[0].policy).Statement :
      try(s.Principal.Service, null) == "events.amazonaws.com"
      && s.Action == "SNS:Publish"
      && s.Resource == "arn:aws:sns:eu-central-1:123456789012:acme-prod-security-alerts"
      && try(s.Condition.StringEquals["aws:SourceAccount"], null) == "123456789012"
    ])
    error_message = "EventBridge must be allowed to publish to the topic, but only from this account."
  }

  assert {
    condition     = length(jsondecode(aws_sns_topic_policy.security_alerts[0].policy).Statement) == 1
    error_message = "The topic policy must grant nothing beyond EventBridge publishing."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_kms_key.security_alerts[0].policy).Statement :
      try(s.Principal.Service, null) == "events.amazonaws.com"
      && contains(s.Action, "kms:Decrypt")
      && contains(s.Action, "kms:GenerateDataKey*")
    ])
    error_message = "EventBridge must be able to use the topic key, or publishing to the encrypted topic fails."
  }

  assert {
    condition     = aws_kms_key.security_alerts[0].enable_key_rotation == true
    error_message = "The security alert KMS key must rotate automatically."
  }
}

run "alert_emails_fall_back_to_the_budget_recipients" {
  command = plan

  assert {
    condition     = sort(keys(aws_sns_topic_subscription.security_alert_email)) == tolist(["cloud-alerts@example.com"])
    error_message = "With no security_alert_emails set, the budget recipients must be subscribed."
  }

  assert {
    condition     = aws_sns_topic_subscription.security_alert_email["cloud-alerts@example.com"].protocol == "email"
    error_message = "Security alert subscriptions must be email subscriptions."
  }
}

run "explicit_alert_emails_replace_the_fallback" {
  command = plan

  variables {
    security_alert_emails = ["security@example.com", "cto@example.com"]
  }

  assert {
    condition     = sort(keys(aws_sns_topic_subscription.security_alert_email)) == tolist(["cto@example.com", "security@example.com"])
    error_message = "Explicit security_alert_emails must be subscribed instead of the budget recipients."
  }
}

run "minimum_severity_is_configurable" {
  command = plan

  variables {
    guardduty_alert_min_severity = 4
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.guardduty_findings[0].event_pattern).detail.severity == [{ numeric = [">=", 4] }]
    error_message = "guardduty_alert_min_severity must set the numeric threshold of the rule."
  }
}

run "root_sign_in_and_break_glass_assumption_alert" {
  command = plan

  assert {
    condition = (
      jsondecode(aws_cloudwatch_event_rule.privileged_access["root-console-login"].event_pattern).detail.userIdentity.type == ["Root"]
      && jsondecode(aws_cloudwatch_event_rule.privileged_access["root-console-login"].event_pattern).detail.eventName == ["ConsoleLogin"]
      && jsondecode(aws_cloudwatch_event_rule.privileged_access["root-console-login"].event_pattern).source == ["aws.signin"]
    )
    error_message = "There must be a rule matching console sign-ins by the root user."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.privileged_access["break-glass-assume"].event_pattern).detail.requestParameters.roleArn == ["arn:aws:iam::123456789012:role/acme-prod-break-glass"]
    error_message = "The break-glass rule must match AssumeRole on exactly the break-glass role."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.privileged_access["break-glass-assume"].event_pattern).detail.eventName == ["AssumeRole"]
    error_message = "The break-glass rule must match AssumeRole calls."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.privileged_access["break-glass-assume"].state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
    error_message = "AssumeRole is a read-only management event; a plain ENABLED rule never sees it."
  }

  assert {
    condition = alltrue([
      for t in aws_cloudwatch_event_target.privileged_access :
      jsondecode(t.input_transformer[0].input_template).source == "custom"
    ])
    error_message = "Privileged-access alerts must be Chatbot custom notifications too."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.privileged_access["break-glass-assume"].name) <= 64 && length(aws_cloudwatch_event_rule.privileged_access["root-console-login"].name) <= 64
    error_message = "EventBridge rule names are capped at 64 characters."
  }
}

run "sign_in_and_global_sts_regions_forward_to_the_home_region" {
  command = plan

  assert {
    condition = sort(keys(aws_cloudwatch_event_rule.privileged_access_forward)) == tolist([
      "us-east-1/break-glass-assume",
      "us-east-1/root-console-login",
      "us-east-2/root-console-login",
      "us-west-2/root-console-login",
    ])
    error_message = "Root sign-ins must be forwarded from us-east-1, us-east-2 and us-west-2, and global STS calls from us-east-1."
  }

  assert {
    condition = alltrue([
      for key, rule in aws_cloudwatch_event_rule.privileged_access_forward :
      rule.region == split("/", key)[0]
    ])
    error_message = "Each forwarding rule must live in the region it forwards from."
  }

  assert {
    condition = alltrue([
      for t in aws_cloudwatch_event_target.privileged_access_forward :
      t.arn == "arn:aws:events:eu-central-1:123456789012:event-bus/default"
    ])
    error_message = "Forwarded events must land on the home region's default bus."
  }

  assert {
    condition     = jsondecode(aws_iam_policy.event_forwarding[0].policy).Statement[0].Resource == "arn:aws:events:eu-central-1:123456789012:event-bus/default"
    error_message = "The forwarding role may put events onto the home bus and nowhere else."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.privileged_access_forward["us-east-1/break-glass-assume"].state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
    error_message = "The AssumeRole forwarder must also receive read-only management events."
  }
}

run "home_region_in_us_east_1_does_not_forward_to_itself" {
  command = plan

  variables {
    aws_region = "us-east-1"
  }

  assert {
    condition = sort(keys(aws_cloudwatch_event_rule.privileged_access_forward)) == tolist([
      "us-east-2/root-console-login",
      "us-west-2/root-console-login",
    ])
    error_message = "With us-east-1 as the home region, only us-east-2 and us-west-2 need forwarding."
  }
}

run "privileged_access_alerts_can_be_switched_off" {
  command = plan

  variables {
    alert_on_privileged_access = false
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.privileged_access) == 0 && length(aws_cloudwatch_event_rule.privileged_access_forward) == 0
    error_message = "Turning privileged-access alerts off must remove the rules and their forwarders."
  }

  assert {
    condition     = length(module.event_forwarding_role) == 0 && length(aws_iam_policy.event_forwarding) == 0
    error_message = "The forwarding role must not linger without forwarders."
  }

  assert {
    condition     = length(aws_sns_topic.security_alerts) == 1
    error_message = "The topic must stay while GuardDuty findings still use it."
  }
}

run "no_topic_when_nothing_alerts" {
  command = plan

  variables {
    enable_guardduty           = false
    alert_on_privileged_access = false
  }

  assert {
    condition     = length(aws_sns_topic.security_alerts) == 0 && length(aws_kms_key.security_alerts) == 0
    error_message = "With every alert source off, the topic and its key must not be created."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.guardduty_findings) == 0
    error_message = "The GuardDuty rule must go with the detector."
  }

  assert {
    condition     = output.security_alerts_topic_arn == null
    error_message = "The topic output must be null when no topic exists."
  }
}
