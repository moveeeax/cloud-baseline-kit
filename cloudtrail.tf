###############################################################################
# CloudTrail.
#
# Multi-region, global service events included, log file validation on, and
# delivered encrypted into the object-locked audit bucket. This is the single
# control that makes every other control in the kit provable after the fact:
# without it, "who turned GuardDuty off" has no answer.
#
# Not an organization trail. Organization trails belong to a multi-account
# layout, which this kit explicitly does not sell.
###############################################################################

resource "aws_cloudtrail" "this" {
  name = "${local.name_prefix}-trail"

  s3_bucket_name = aws_s3_bucket.audit.id
  s3_key_prefix  = local.cloudtrail_key_prefix
  kms_key_id     = aws_kms_key.audit.arn

  is_multi_region_trail         = true
  is_organization_trail         = false
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  # Management events only. Data events on S3 and Lambda are where CloudTrail
  # bills get frightening, and an empty day-one account generates nothing worth
  # the money. Turn them on per-bucket once there is something in them.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = local.tags

  depends_on = [
    aws_s3_bucket_policy.audit,
    aws_kms_key.audit,
  ]
}
