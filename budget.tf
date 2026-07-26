###############################################################################
# Cost guardrail.
#
# Two notifications, on purpose. The actual-spend alert at 80 percent tells you
# the month is running hot. The forecast alert at 100 percent tells you that on
# current trajectory you will blow the budget, usually a week or more before you
# do. One without the other is either too late or too noisy.
###############################################################################

resource "aws_sns_topic" "budget" {
  count = var.create_budget_sns_topic ? 1 : 0

  name = local.budget_sns_topic_name

  tags = local.tags
}

resource "aws_sns_topic_policy" "budget" {
  count = var.create_budget_sns_topic ? 1 : 0

  arn = aws_sns_topic.budget[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowBudgetsToPublish"
        Effect    = "Allow"
        Principal = { Service = "budgets.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = local.budget_sns_topic_arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
    ]
  })
}

resource "aws_budgets_budget" "monthly" {
  name         = "${local.name_prefix}-monthly"
  budget_type  = "COST"
  time_unit    = "MONTHLY"
  limit_amount = format("%.2f", var.monthly_budget_usd)
  limit_unit   = "USD"

  cost_types {
    include_credit             = false
    include_refund             = false
    include_upfront            = true
    include_recurring          = true
    include_other_subscription = true
    include_subscription       = true
    include_support            = true
    include_tax                = true
    include_discount           = true
    use_amortized              = false
    use_blended                = false
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
    subscriber_sns_topic_arns  = local.budget_sns_topic_arns
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.budget_alert_emails
    subscriber_sns_topic_arns  = local.budget_sns_topic_arns
  }

  tags = local.tags

  # The topic ARN handed to the notifications is derived rather than referenced,
  # so the dependency on the topic itself has to be spelled out.
  depends_on = [aws_sns_topic_policy.budget]
}
