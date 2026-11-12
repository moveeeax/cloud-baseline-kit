terraform {
  # The root module itself only needs 1.5 for optional object attributes, but
  # the test suite under tests/ uses `mock_provider`, which landed in 1.7.
  # Requiring 1.7 here means `terraform test` cannot fail for a reason that has
  # nothing to do with the baseline.
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 6.0 added the per-resource `region` argument, which the security alert
      # forwarding rules use to sit in us-east-1, us-east-2 and us-west-2 without
      # a provider alias per region.
      version = ">= 6.0, < 7.0"
    }
  }
}
