###############################################################################
# Account-wide baseline: IAM password policy, account S3 public access block,
# EBS encryption by default, and the general-purpose log bucket.
###############################################################################

module "baseline" {
  source = "git::https://github.com/moveeeax/terraform-aws-baseline.git?ref=33265c6cccb4745c6d70a69350a550ba38912b77"

  log_bucket_name               = local.general_log_bucket_name
  log_bucket_versioning_enabled = true
  log_bucket_force_destroy      = false

  enable_s3_account_public_access_block = true
  enable_ebs_encryption_by_default      = true

  minimum_password_length        = var.minimum_password_length
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  allow_users_to_change_password = true

  tags = local.tags
}

###############################################################################
# Organization.
#
# Single account, all features enabled, trusted access wired for the services
# this baseline turns on. Multi-account layouts, OU factories and Control Tower
# are deliberately out of scope: if the buyer needs those they need Landing Zone
# Accelerator, and this kit should say so rather than half-implement it.
###############################################################################

module "organization" {
  source = "git::https://github.com/moveeeax/terraform-aws-organizations.git?ref=22ce8fa333a2f371ef2857398ed8855eb8bf1b9b"

  count = var.create_organization ? 1 : 0

  feature_set = "ALL"

  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "sso.amazonaws.com",
  ]

  enabled_policy_types = ["SERVICE_CONTROL_POLICY", "TAG_POLICY"]
  organizational_units = var.organizational_units

  tags = local.tags
}

###############################################################################
# Break-glass administrator role.
#
# Nobody should hold standing AdministratorAccess. This role does, and it can
# only be entered with MFA presented in the last hour. Every assumption of it
# lands in CloudTrail, which is why the trail is not optional in this kit.
###############################################################################

module "break_glass_role" {
  source = "git::https://github.com/moveeeax/terraform-aws-iam.git?ref=d2fee3afbc2cb5e1d5075c8d96caa7e39d8bfb9e"

  name                 = "${local.name_prefix}-break-glass"
  description          = "Emergency administrator access. MFA required, sessions capped, every use audited."
  max_session_duration = var.break_glass_max_session_seconds
  managed_policy_arns  = ["arn:${local.partition}:iam::aws:policy/AdministratorAccess"]

  assume_role_policy = local.break_glass_assume_role_policy

  tags = local.tags
}

###############################################################################
# AWS Config: recorder, delivery channel and a small conformance set.
###############################################################################

resource "aws_iam_policy" "config_delivery" {
  count = var.enable_config ? 1 : 0

  name        = local.config_delivery_policy_name
  description = "Lets AWS Config write configuration snapshots into the audit bucket and use its KMS key."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteSnapshots"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = local.config_object_arn
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      {
        Sid      = "ReadBucketAcl"
        Effect   = "Allow"
        Action   = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource = local.audit_bucket_arn
      },
      {
        Sid      = "UseAuditKey"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = aws_kms_key.audit.arn
      },
    ]
  })

  tags = local.tags
}

module "config_role" {
  source = "git::https://github.com/moveeeax/terraform-aws-iam.git?ref=d2fee3afbc2cb5e1d5075c8d96caa7e39d8bfb9e"

  count = var.enable_config ? 1 : 0

  name        = "${local.name_prefix}-config"
  description = "Service role AWS Config uses to record and deliver configuration data."

  managed_policy_arns = [
    "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole",
    local.config_delivery_policy_arn,
  ]

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
    ]
  })

  tags = local.tags

  # The delivery policy ARN is derived rather than referenced, so the dependency
  # has to be declared explicitly or the attachment can race the policy.
  depends_on = [aws_iam_policy.config_delivery]
}

module "config" {
  source = "git::https://github.com/moveeeax/terraform-aws-config.git?ref=b4838d40d7c0307e47e89e4d3799815e62c91943"

  count = var.enable_config ? 1 : 0

  name           = "${local.name_prefix}-recorder"
  role_arn       = module.config_role[0].arn
  s3_bucket_name = aws_s3_bucket.audit.id
  s3_key_prefix  = local.config_key_prefix
  s3_kms_key_arn = aws_kms_key.audit.arn

  all_supported                 = true
  include_global_resource_types = true
  delivery_frequency            = "TwentyFour_Hours"
  enable_recorder               = true

  depends_on = [aws_s3_bucket_policy.audit]
}

resource "aws_config_config_rule" "conformance" {
  for_each = var.enable_config ? toset(var.config_managed_rules) : toset([])

  name = lower(replace(each.value, "_", "-"))

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  tags = local.tags

  depends_on = [module.config]
}

###############################################################################
# GuardDuty.
###############################################################################

module "guardduty" {
  source = "git::https://github.com/moveeeax/terraform-aws-guardduty.git?ref=2ea4883ad4b674ed4012abef2fb30aad17339d93"

  enable                       = var.enable_guardduty
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  enable_s3_protection     = true
  enable_rds_protection    = true
  enable_lambda_protection = true

  # Off by default: both cost real money and neither is meaningful in an account
  # that does not yet run EKS or EC2 workloads. Turn them on when it does.
  enable_kubernetes_protection = false
  enable_malware_protection    = false

  tags = local.tags
}
