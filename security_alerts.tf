###############################################################################
# Security alerting.
#
# GuardDuty and CloudTrail record things; nothing in the rest of the kit tells a
# human about them. Everything here ends in one SNS topic, so email and AWS
# Chatbot see the same alerts:
#
#   - GuardDuty findings at or above guardduty_alert_min_severity.
#   - Root user console sign-ins, successful or not.
#   - AssumeRole calls on the break-glass role, successful or not.
#
# Messages are shaped as Chatbot custom notifications. Chatbot only renders
# events it recognises, and a transformed event is no longer one of those, so
# the template uses the custom notification schema instead. Email subscribers
# get the same JSON, which carries a one-line description.
#
# Sign-in and STS events are not always recorded in the home region. CloudTrail
# records root console sign-ins in us-east-1, us-east-2 or us-west-2, and calls
# to the global STS endpoint in us-east-1, and EventBridge only sees an event in
# the region where it was recorded. Rules in those regions forward the matching
# events to the home region's default bus, where the alerting rules live.
###############################################################################

resource "aws_kms_key" "security_alerts" {
  count = local.security_alerts_enabled ? 1 : 0

  description             = "${local.name_prefix} security alert topic encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # EventBridge cannot publish to a topic encrypted with the AWS managed SNS key,
  # because that key's policy cannot be changed to admit it. Hence a key of our
  # own, with EventBridge allowed to generate data keys and decrypt.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "EventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
      },
    ]
  })

  tags = local.tags
}

resource "aws_kms_alias" "security_alerts" {
  count = local.security_alerts_enabled ? 1 : 0

  name          = "alias/${local.name_prefix}-security-alerts"
  target_key_id = aws_kms_key.security_alerts[0].key_id
}

resource "aws_sns_topic" "security_alerts" {
  count = local.security_alerts_enabled ? 1 : 0

  name              = local.security_alerts_topic_name
  kms_master_key_id = aws_kms_key.security_alerts[0].arn

  tags = local.tags
}

resource "aws_sns_topic_policy" "security_alerts" {
  count = local.security_alerts_enabled ? 1 : 0

  arn = aws_sns_topic.security_alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgeToPublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = local.security_alerts_topic_arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
    ]
  })
}

resource "aws_sns_topic_subscription" "security_alert_email" {
  for_each = local.security_alerts_enabled ? toset(local.security_alert_emails) : toset([])

  topic_arn = aws_sns_topic.security_alerts[0].arn
  protocol  = "email"
  endpoint  = each.value
}

###############################################################################
# GuardDuty findings.
###############################################################################

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${local.name_prefix}-guardduty-findings"
  description = "GuardDuty findings of severity ${var.guardduty_alert_min_severity} or higher, to the security alert topic."

  event_pattern = local.guardduty_findings_pattern

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "security-alerts"
  arn       = aws_sns_topic.security_alerts[0].arn

  input_transformer {
    input_paths = {
      id       = "$.detail.id"
      type     = "$.detail.type"
      title    = "$.detail.title"
      severity = "$.detail.severity"
      account  = "$.detail.accountId"
      region   = "$.detail.region"
    }

    input_template = local.guardduty_alert_template
  }

  depends_on = [aws_sns_topic_policy.security_alerts]
}

###############################################################################
# Privileged access: root console sign-in and break-glass assumption.
###############################################################################

resource "aws_cloudwatch_event_rule" "privileged_access" {
  for_each = var.alert_on_privileged_access ? local.privileged_access_events : {}

  name        = "${local.name_prefix}-${each.key}"
  description = each.value.description

  event_pattern = each.value.pattern
  state         = each.value.state

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "privileged_access" {
  for_each = var.alert_on_privileged_access ? local.privileged_access_events : {}

  rule      = aws_cloudwatch_event_rule.privileged_access[each.key].name
  target_id = "security-alerts"
  arn       = aws_sns_topic.security_alerts[0].arn

  input_transformer {
    input_paths    = each.value.input_paths
    input_template = each.value.template
  }

  depends_on = [aws_sns_topic_policy.security_alerts]
}

###############################################################################
# Forwarding from the regions where sign-in and global STS events land.
###############################################################################

resource "aws_iam_policy" "event_forwarding" {
  count = length(local.privileged_access_forwarders) > 0 ? 1 : 0

  name        = local.event_forwarding_policy_name
  description = "Lets EventBridge rules in other regions put privileged-access events onto the home region's default event bus."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PutOntoHomeBus"
        Effect   = "Allow"
        Action   = "events:PutEvents"
        Resource = local.home_event_bus_arn
      },
    ]
  })

  tags = local.tags
}

module "event_forwarding_role" {
  source = "git::https://github.com/moveeeax/terraform-aws-iam.git?ref=672f4a2bfcacf5825987195ef5991ed3c99c9aeb"

  count = length(local.privileged_access_forwarders) > 0 ? 1 : 0

  name        = "${local.name_prefix}-event-forwarding"
  description = "Assumed by EventBridge to forward root sign-in and break-glass events to ${var.aws_region}."

  managed_policy_arns = [local.event_forwarding_policy_arn]

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
    ]
  })

  tags = local.tags

  # Same reason as the Config role: the policy ARN is derived, not referenced.
  depends_on = [aws_iam_policy.event_forwarding]
}

resource "aws_cloudwatch_event_rule" "privileged_access_forward" {
  for_each = local.privileged_access_forwarders

  region = each.value.region

  name        = "${local.name_prefix}-fwd-${each.value.event}"
  description = "Forwards ${each.value.event} events recorded in ${each.value.region} to ${var.aws_region}."

  event_pattern = local.privileged_access_events[each.value.event].pattern
  state         = local.privileged_access_events[each.value.event].state

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "privileged_access_forward" {
  for_each = local.privileged_access_forwarders

  region = each.value.region

  rule      = aws_cloudwatch_event_rule.privileged_access_forward[each.key].name
  target_id = "home-region-bus"
  arn       = local.home_event_bus_arn
  role_arn  = module.event_forwarding_role[0].arn
}
