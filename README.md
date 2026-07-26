# cloud-baseline-kit

A day-one AWS account, as one Terraform root module and one `terraform apply`.

CloudTrail into an encrypted, object-locked log bucket. AWS Config with a small
conformance set. GuardDuty. An IAM password policy and an MFA-gated break-glass
role. A two-tier VPC. A budget that tells you before the money is gone. Every
resource tagged and named the same way.

The point is not the Terraform — plenty of that exists. The point is that a
non-infra founder can run this on an empty account, hand
[`docs/what-was-created-and-why.md`](docs/what-was-created-and-why.md) to
whoever is asking the security questions, and get on with their week.

**AWS only. One account. No compliance claims.** See
[what is deliberately not here](docs/what-was-created-and-why.md#what-is-deliberately-not-here)
before you assume it does something.

---

## What it installs

| Area | What you get |
| --- | --- |
| Audit | Multi-region CloudTrail with log file validation, delivered to an S3 bucket with COMPLIANCE-mode object lock and a customer-managed KMS key |
| Configuration | AWS Config recorder and delivery channel, plus 14 managed rules chosen to answer real questionnaire questions |
| Detection | GuardDuty with S3, RDS and Lambda protection |
| Identity | 14-character password policy with rotation and reuse prevention, MFA-gated break-glass admin role, account-wide S3 public access block, EBS encryption by default |
| Network | Two-tier VPC across two AZs, emptied default security group, flow logs, S3 gateway endpoint, one shared NAT gateway |
| Organization | Optional AWS Organization with all features, SCPs and tag policies enabled, and the OUs you name |
| Cost | Monthly budget alerting at 80% actual and 100% forecast, to email and to an SNS topic Chatbot can turn into Slack messages |

Composed from these modules, each pinned to a commit:
[`terraform-aws-baseline`](https://github.com/moveeeax/terraform-aws-baseline),
[`terraform-aws-organizations`](https://github.com/moveeeax/terraform-aws-organizations),
[`terraform-aws-config`](https://github.com/moveeeax/terraform-aws-config),
[`terraform-aws-guardduty`](https://github.com/moveeeax/terraform-aws-guardduty),
[`terraform-aws-iam`](https://github.com/moveeeax/terraform-aws-iam),
[`terraform-aws-vpc`](https://github.com/moveeeax/terraform-aws-vpc),
[`terraform-aws-security-group`](https://github.com/moveeeax/terraform-aws-security-group).

## Requirements

- Terraform >= 1.7 (the test suite uses `mock_provider`)
- AWS provider >= 5.40, < 7.0
- An AWS account, and credentials for it, **only when you get to `apply`**

## Try it without an AWS account

This runs end to end on a laptop with no AWS credentials configured. It
downloads the child modules from GitHub and the AWS provider from the registry,
then plans the whole baseline against a mocked provider and checks 26
assertions about what it produced.

```console
$ git clone https://github.com/moveeeax/cloud-baseline-kit.git
$ cd cloud-baseline-kit

$ terraform init -backend=false
Terraform has been successfully initialized!

$ terraform validate
Success! The configuration is valid.

$ terraform test
tests/audit.tftest.hcl... in progress
  run "audit_bucket_is_immutable_and_encrypted"... pass
  run "audit_bucket_policy_admits_only_the_log_producers"... pass
  run "cloudtrail_is_multi_region_and_tamper_evident"... pass
  run "config_records_everything_and_runs_the_conformance_set"... pass
  run "everything_taggable_carries_the_account_tag_set"... pass
  run "kit_tags_win_over_consumer_supplied_tags"... pass
  run "budget_alerts_on_both_actual_and_forecast_spend"... pass
  run "break_glass_role_cannot_be_entered_without_mfa"... pass
  run "detection_can_be_switched_off_wholesale"... pass
tests/audit.tftest.hcl... pass
tests/network.tftest.hcl... in progress
  run "two_tiers_across_two_zones_by_default"... pass
  run "public_tier_routes_to_the_internet_gateway_and_private_does_not"... pass
  run "single_nat_gateway_is_the_default_and_shared_by_every_zone"... pass
  run "one_nat_gateway_per_zone_when_asked"... pass
  run "private_tier_has_no_egress_path_when_nat_is_disabled"... pass
  run "names_carry_the_account_prefix_and_the_zone"... pass
tests/network.tftest.hcl... pass
tests/validation.tftest.hcl... in progress
  run "rejects_a_region_that_is_not_a_region"... pass
  ...
tests/validation.tftest.hcl... pass

Success! 26 passed, 0 failed.
```

Nothing above talks to AWS, costs anything, or needs a credential.

## Install it into a real account

```console
$ cp terraform.tfvars.example terraform.tfvars
$ $EDITOR terraform.tfvars          # 11 settings to fill in
$ export AWS_PROFILE=your-profile   # or however you get credentials
$ terraform init
$ terraform plan -out baseline.tfplan
$ terraform apply baseline.tfplan
```

`terraform.tfvars.example` in full:

```hcl
aws_region            = "eu-central-1"
org_name              = "acme"
environment           = "prod"
owner                 = "platform-team"
audit_log_bucket_name = "acme-prod-audit-logs-eu-central-1"

vpc_cidr_block          = "10.20.0.0/16"
availability_zone_count = 2

monthly_budget_usd  = 500
budget_alert_emails = ["cloud-alerts@example.com"]

create_organization  = true
organizational_units = ["Security", "Workloads"]
```

Everything else has a defensible default; see [`variables.tf`](variables.tf),
where each one says what it does and why the default is what it is.

State is deliberately not configured. Add a `backend` block, or run it through
whatever already manages state for you.

### Before you apply

- **`create_organization`** must be `false` if the account already belongs to an
  AWS Organization. Destroying that resource calls `DeleteOrganization`, which
  is irreversible.
- **`audit_log_bucket_name`** is globally unique across all of AWS and cannot be
  renamed later without recreating the bucket. Include the company and region.
- **Object lock is permanent.** The audit bucket is created with COMPLIANCE-mode
  object lock, which cannot be turned on after creation and cannot be shortened
  or bypassed afterwards — not by an administrator, not by the account root.
  `terraform destroy` will not be able to empty that bucket until the retention
  period expires. That is the entire point of it, but know it going in.
- **The NAT gateway is the expensive line**, roughly $32/month before data
  charges. Set `enable_nat_gateway = false` if nothing in the private tier needs
  outbound access yet.

## Outputs

`terraform output` gives you the VPC and subnet IDs, both bucket names, the KMS
key ARN, the CloudTrail ARN, the GuardDuty detector, the Config rule names, the
break-glass role ARN and its trust policy, and the budget SNS topic ARN to point
AWS Chatbot at.

## Development

```console
$ terraform fmt -check -recursive -diff
$ terraform init -backend=false
$ terraform validate
$ tflint --init && tflint --recursive
$ terraform test
```

CI runs exactly these five on every push and pull request. No job needs an AWS
credential, so the whole pipeline works on a fork.

The test suite is plan-only against `mock_provider "aws"`, so assertions may
only reference values the configuration decides, never values AWS returns. If an
assertion fails with "Unknown condition value", that is what happened: derive
the value in `locals.tf` and expose it, rather than reaching for a computed
attribute.

## Status

The module composes, validates, lints and passes its test suite. It has **not
yet been applied to a live AWS account** — that is the next milestone, and until
two clean apply/destroy cycles have happened it should be treated as unproven
against the real AWS APIs.
