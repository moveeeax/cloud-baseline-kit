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
}
