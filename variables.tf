###############################################################################
# Identity of the account
###############################################################################

variable "aws_region" {
  description = "Region the baseline is installed into. Everything regional lives here; CloudTrail, IAM and the S3 account public access block are global regardless."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must look like an AWS region code, for example eu-central-1."
  }
}

variable "org_name" {
  description = "Short slug identifying the company. Used as the first segment of every resource name, so keep it lowercase and stable."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,20}[a-z0-9]$", var.org_name))
    error_message = "org_name must be 3-22 characters of lowercase letters, digits and hyphens, and may not start or end with a hyphen."
  }
}

variable "environment" {
  description = "Environment label for this account. One account, one environment: this kit does not model several environments inside one account."
  type        = string
  default     = "prod"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,14}$", var.environment))
    error_message = "environment must be 1-15 characters of lowercase letters, digits and hyphens."
  }
}

variable "owner" {
  description = "Value of the Owner tag applied to everything this kit creates. A team name or a distribution list, not a person who might leave."
  type        = string
  default     = "platform"
}

variable "additional_tags" {
  description = "Extra tags merged into the tag set applied to every resource. Keys defined by the kit (Environment, Owner, ManagedBy, Baseline) win on conflict."
  type        = map(string)
  default     = {}
}

###############################################################################
# Audit log storage
###############################################################################

variable "audit_log_bucket_name" {
  description = "Globally unique name of the bucket that receives CloudTrail and AWS Config data. A second bucket named '<this>-general' is created for ordinary application and load balancer logs."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,48}[a-z0-9]$", var.audit_log_bucket_name))
    error_message = "audit_log_bucket_name must be 3-50 characters of lowercase letters, digits, dots and hyphens. The 50 character cap leaves room for the '-general' suffix of the second bucket."
  }
}

variable "audit_log_retention_days" {
  description = "Days before an object in the audit bucket is expired. Object lock retention is applied on top, so an object cannot actually be deleted before audit_log_lock_days have passed."
  type        = number
  default     = 730

  validation {
    condition     = var.audit_log_retention_days >= 90
    error_message = "audit_log_retention_days must be at least 90; anything shorter fails the first security questionnaire that asks about log retention."
  }
}

variable "audit_log_lock_days" {
  description = "Days of S3 Object Lock retention applied to every object written to the audit bucket, in COMPLIANCE mode. Nobody, including the account root, can delete or overwrite an object before this elapses."
  type        = number
  default     = 365

  validation {
    condition     = var.audit_log_lock_days >= 1
    error_message = "audit_log_lock_days must be at least 1."
  }
}

###############################################################################
# Organization
###############################################################################

variable "create_organization" {
  description = "Whether to create an AWS Organization in this account. Set to false when the account already belongs to one; destroying this resource deletes the whole organization."
  type        = bool
  default     = false
}

variable "organizational_units" {
  description = "Organizational units created directly under the root. Only used when create_organization is true."
  type        = list(string)
  default     = ["Security", "Workloads"]
}

###############################################################################
# Network
###############################################################################

variable "vpc_cidr_block" {
  description = "IPv4 CIDR block of the two-tier VPC. Subnets are carved out of it with an 8-bit offset, so a /16 yields /24 subnets."
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr_block))
    error_message = "vpc_cidr_block must be a valid IPv4 CIDR block, for example 10.0.0.0/16."
  }

  validation {
    condition     = can(regex("/(1[6-9]|2[0-2])$", var.vpc_cidr_block))
    error_message = "vpc_cidr_block must have a prefix length between /16 and /22. Anything smaller leaves no usable room once it is split across availability zones."
  }
}

variable "availability_zone_count" {
  description = "Number of availability zones to spread the public and private subnet tiers across."
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 2 && var.availability_zone_count <= 4
    error_message = "availability_zone_count must be between 2 and 4. One zone is not a baseline, and more than four is a design decision this kit does not make for you."
  }
}

variable "enable_nat_gateway" {
  description = "Whether private subnets get outbound internet access through a NAT gateway. Turning this off leaves the private tier genuinely private and saves the NAT hourly charge."
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Whether to place one NAT gateway in the first availability zone instead of one per zone. One gateway is cheaper; one per zone survives a zone failure."
  type        = bool
  default     = true
}

###############################################################################
# Detection and configuration recording
###############################################################################

variable "enable_guardduty" {
  description = "Whether to enable the GuardDuty detector in this region."
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Whether to enable the AWS Config recorder, delivery channel and managed rule set."
  type        = bool
  default     = true
}

variable "config_managed_rules" {
  description = "AWS Config managed rule identifiers making up the conformance set. Kept deliberately small: every rule here answers a question that appears on real security questionnaires."
  type        = list(string)
  default = [
    "ROOT_ACCOUNT_MFA_ENABLED",
    "IAM_USER_MFA_ENABLED",
    "IAM_PASSWORD_POLICY",
    "IAM_USER_NO_POLICIES_CHECK",
    "CLOUD_TRAIL_ENABLED",
    "CLOUDTRAIL_LOG_FILE_VALIDATION_ENABLED",
    "GUARDDUTY_ENABLED_CENTRALIZED",
    "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
    "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
    "ENCRYPTED_VOLUMES",
    "EC2_EBS_ENCRYPTION_BY_DEFAULT",
    "VPC_DEFAULT_SECURITY_GROUP_CLOSED",
    "VPC_FLOW_LOGS_ENABLED",
  ]

  validation {
    condition     = length(var.config_managed_rules) == length(distinct(var.config_managed_rules))
    error_message = "config_managed_rules must not contain duplicates."
  }
}

variable "guardduty_alert_min_severity" {
  description = "Lowest GuardDuty finding severity sent to the security alert topic. GuardDuty rates findings 7.0-8.9 High and 9.0-10.0 Critical, so the default of 7 alerts on High and Critical and leaves Low and Medium in the console."
  type        = number
  default     = 7

  validation {
    condition     = var.guardduty_alert_min_severity >= 1 && var.guardduty_alert_min_severity <= 10
    error_message = "guardduty_alert_min_severity must be between 1 and 10, the range GuardDuty assigns."
  }
}

variable "alert_on_privileged_access" {
  description = "Whether root user console sign-ins and AssumeRole calls on the break-glass role are sent to the security alert topic."
  type        = bool
  default     = true
}

variable "security_alert_emails" {
  description = "Email addresses subscribed to the security alert topic. Empty means the budget_alert_emails addresses. AWS sends each address a subscription confirmation, and nothing is delivered to it until that is clicked."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for address in var.security_alert_emails : can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", address))])
    error_message = "Every entry in security_alert_emails must look like an email address."
  }
}

###############################################################################
# Access
###############################################################################

variable "break_glass_trusted_principals" {
  description = "IAM principal ARNs allowed to assume the break-glass administrator role. Empty means the account root, which in practice means anyone the account grants sts:AssumeRole to. MFA is required either way."
  type        = list(string)
  default     = []
}

variable "break_glass_max_session_seconds" {
  description = "Maximum session length of the break-glass role. Short on purpose: the role exists for incidents, not for daily work."
  type        = number
  default     = 3600

  validation {
    condition     = var.break_glass_max_session_seconds >= 900 && var.break_glass_max_session_seconds <= 14400
    error_message = "break_glass_max_session_seconds must be between 900 and 14400 seconds."
  }
}

variable "minimum_password_length" {
  description = "Minimum length of IAM user console passwords."
  type        = number
  default     = 14
}

###############################################################################
# Cost
###############################################################################

variable "monthly_budget_usd" {
  description = "Monthly cost budget for the account, in USD. Alerts fire at 80 percent of actual spend and at 100 percent of forecast spend."
  type        = number

  validation {
    condition     = var.monthly_budget_usd > 0
    error_message = "monthly_budget_usd must be greater than zero."
  }
}

variable "budget_alert_emails" {
  description = "Email addresses that receive budget alerts. AWS sends each address a subscription confirmation."
  type        = list(string)

  validation {
    condition     = length(var.budget_alert_emails) > 0
    error_message = "budget_alert_emails must contain at least one address; a budget nobody is told about is not a control."
  }

  validation {
    condition     = alltrue([for address in var.budget_alert_emails : can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", address))])
    error_message = "Every entry in budget_alert_emails must look like an email address."
  }
}

variable "create_budget_sns_topic" {
  description = "Whether to create an SNS topic for budget alerts. Subscribe AWS Chatbot to the topic to land the alerts in Slack; the topic policy already allows the budgets service to publish."
  type        = bool
  default     = true
}

variable "extra_budget_sns_topic_arns" {
  description = "Existing SNS topic ARNs that should also receive budget notifications, in addition to the topic this kit creates."
  type        = list(string)
  default     = []
}
