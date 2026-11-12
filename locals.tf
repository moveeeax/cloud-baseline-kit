data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name_prefix = "${var.org_name}-${var.environment}"

  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Kit-owned tag keys win over additional_tags so that a typo in a consumer's
  # tfvars cannot quietly detach a resource from the account's tagging scheme.
  tags = merge(var.additional_tags, {
    Environment = var.environment
    Owner       = var.owner
    ManagedBy   = "terraform"
    Baseline    = "cloud-baseline-kit"
  })

  # The general-purpose log bucket. Kept separate from the audit bucket so that
  # application logs, which people delete, never share a lifecycle or an object
  # lock policy with CloudTrail data, which they must not.
  general_log_bucket_name = "${var.audit_log_bucket_name}-general"

  availability_zones = slice(data.aws_availability_zones.available.names, 0, var.availability_zone_count)

  # cidrsubnet with 8 newbits always yields 256 candidate subnets, whatever the
  # VPC prefix length is, so index 128 is a valid private-tier offset for a /16
  # and for a /22 alike.
  subnet_newbits       = 8
  private_subnet_index = 128

  audit_bucket_arn = "arn:${local.partition}:s3:::${var.audit_log_bucket_name}"

  # Composed by hand rather than read off aws_iam_policy.config_delivery[0].arn.
  # terraform-aws-iam attaches policies with for_each over the ARN list, and an
  # ARN that is unknown until apply makes that for_each unplannable. Deriving it
  # keeps `terraform plan` working on a fresh account.
  config_delivery_policy_name = "${var.org_name}-${var.environment}-config-delivery"
  config_delivery_policy_arn  = "arn:${local.partition}:iam::${local.account_id}:policy/${local.config_delivery_policy_name}"

  cloudtrail_key_prefix = "cloudtrail"
  config_key_prefix     = "config"

  # AWS Config writes to AWSLogs/<account>/Config/*; CloudTrail to
  # AWSLogs/<account>/CloudTrail/*. Both sit under the prefix we hand them.
  cloudtrail_object_arn = "${local.audit_bucket_arn}/${local.cloudtrail_key_prefix}/AWSLogs/${local.account_id}/*"
  config_object_arn     = "${local.audit_bucket_arn}/${local.config_key_prefix}/AWSLogs/${local.account_id}/Config/*"

  break_glass_principals = length(var.break_glass_trusted_principals) > 0 ? var.break_glass_trusted_principals : ["arn:${local.partition}:iam::${local.account_id}:root"]

  # Kept out of main.tf and exposed as an output: a security reviewer asking
  # "how is emergency admin access gated" should be able to read the answer
  # from `terraform output` rather than from the source.
  break_glass_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AssumeWithMfa"
        Effect    = "Allow"
        Principal = { AWS = local.break_glass_principals }
        Action    = "sts:AssumeRole"
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = tostring(var.break_glass_max_session_seconds)
          }
        }
      },
    ]
  })

  # Derived for the same reason as the Config delivery policy ARN: keeping it
  # known at plan time means the budget and its topic policy are both fully
  # visible in `terraform plan` before anyone approves an apply.
  budget_sns_topic_name = "${var.org_name}-${var.environment}-budget-alerts"
  budget_sns_topic_arn  = "arn:${local.partition}:sns:${var.aws_region}:${local.account_id}:${local.budget_sns_topic_name}"

  budget_sns_topic_arns = concat(
    var.create_budget_sns_topic ? [local.budget_sns_topic_arn] : [],
    var.extra_budget_sns_topic_arns,
  )

  # Break-glass role ARN derived for the same reason: the privileged-access
  # event pattern has to be readable in `terraform plan`. The role sits on the
  # default "/" path of terraform-aws-iam.
  break_glass_role_arn = "arn:${local.partition}:iam::${local.account_id}:role/${local.name_prefix}-break-glass"

  security_alerts_enabled = var.enable_guardduty || var.alert_on_privileged_access

  # Falls back to the budget recipients so that security alerts reach someone
  # on the first apply even when nobody thought to set a separate list.
  security_alert_emails = length(var.security_alert_emails) > 0 ? var.security_alert_emails : var.budget_alert_emails

  security_alerts_topic_name = "${var.org_name}-${var.environment}-security-alerts"
  security_alerts_topic_arn  = "arn:${local.partition}:sns:${var.aws_region}:${local.account_id}:${local.security_alerts_topic_name}"

  guardduty_findings_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.guardduty_alert_min_severity] }]
    }
  })

  # Input transformer templates are written out rather than built with
  # jsonencode, which would escape the <placeholder> angle brackets and leave
  # EventBridge nothing to substitute. Each is an AWS Chatbot custom
  # notification: version "1.0", source "custom", and a content description.
  guardduty_alert_template = trimspace(<<-EOT
    {"version":"1.0","source":"custom","id":"<id>","content":{"title":"GuardDuty finding, severity <severity>","description":"<type> in account <account>, region <region>: <title> (finding <id>)"}}
  EOT
  )

  # Keyed by the rule name suffix. Failed attempts match too: a failed root
  # sign-in or a denied AssumeRole on the break-glass role is as much news as a
  # successful one.
  privileged_access_events = {
    "root-console-login" = {
      description = "Root user console sign-ins, successful or failed, to the security alert topic."
      pattern = jsonencode({
        source        = ["aws.signin"]
        "detail-type" = ["AWS Console Sign In via CloudTrail"]
        detail = {
          eventName    = ["ConsoleLogin"]
          userIdentity = { type = ["Root"] }
        }
      })
      # ConsoleLogin is not a read-only event, so the plain ENABLED state sees it.
      state = "ENABLED"
      input_paths = {
        account = "$.detail.recipientAccountId"
        result  = "$.detail.responseElements.ConsoleLogin"
        mfa     = "$.detail.additionalEventData.MFAUsed"
        ip      = "$.detail.sourceIPAddress"
        time    = "$.detail.eventTime"
      }
      template = trimspace(<<-EOT
        {"version":"1.0","source":"custom","content":{"title":"Root user console sign-in","description":"Root user console sign-in in account <account>: <result>, MFA used: <mfa>, from <ip> at <time>."}}
      EOT
      )
    }

    "break-glass-assume" = {
      description = "AssumeRole calls on the break-glass administrator role, to the security alert topic."
      pattern = jsonencode({
        source        = ["aws.sts"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource       = ["sts.amazonaws.com"]
          eventName         = ["AssumeRole"]
          requestParameters = { roleArn = [local.break_glass_role_arn] }
        }
      })
      # AssumeRole is a read-only management event, and EventBridge only matches
      # those against rules in this state.
      state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
      input_paths = {
        account = "$.detail.recipientAccountId"
        caller  = "$.detail.userIdentity.arn"
        ip      = "$.detail.sourceIPAddress"
        time    = "$.detail.eventTime"
      }
      template = trimspace(<<-EOT
        {"version":"1.0","source":"custom","content":{"title":"Break-glass role assumption","description":"AssumeRole on the break-glass role in account <account> by <caller> from <ip> at <time>. Check CloudTrail for whether it succeeded."}}
      EOT
      )
    }
  }

  # Regions CloudTrail records root sign-ins (us-east-1, us-east-2, us-west-2)
  # and global-endpoint STS calls (us-east-1) in. They exist only in the
  # commercial partition; the home region is skipped because its own rules
  # already see the events.
  privileged_access_source_regions = local.partition == "aws" ? setsubtract(["us-east-1", "us-east-2", "us-west-2"], [var.aws_region]) : toset([])

  privileged_access_forwarders = var.alert_on_privileged_access ? merge(
    {
      for region in local.privileged_access_source_regions :
      "${region}/root-console-login" => { region = region, event = "root-console-login" }
    },
    {
      for region in setintersection(local.privileged_access_source_regions, ["us-east-1"]) :
      "${region}/break-glass-assume" => { region = region, event = "break-glass-assume" }
    },
  ) : {}

  home_event_bus_arn = "arn:${local.partition}:events:${var.aws_region}:${local.account_id}:event-bus/default"

  event_forwarding_policy_name = "${var.org_name}-${var.environment}-event-forwarding"
  event_forwarding_policy_arn  = "arn:${local.partition}:iam::${local.account_id}:policy/${local.event_forwarding_policy_name}"
}
