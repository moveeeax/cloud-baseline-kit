# What was created in your AWS account, and why

This document describes everything `cloud-baseline-kit` puts into an AWS
account. It is written to be handed straight to a security reviewer, a customer
asking a due-diligence question, or an engineer who joins in six months and
wants to know why a thing exists.

It is a description of controls. It is **not** a compliance certification, an
audit report, or a claim that the account meets SOC 2, ISO 27001 or any other
framework. Those require an auditor. This is the groundwork that makes talking
to one cheaper.

Names below use the prefix `<org>-<environment>`, for example `acme-prod`.

---

## 1. Audit logging

### `<org>-<environment>-trail` — AWS CloudTrail

A multi-region trail with global service events included and log file validation
turned on. It records every API call made in the account: who called it, from
where, with which credentials, and whether it succeeded.

**Why it matters.** Every other control in this document is only meaningful if
you can tell afterwards whether someone turned it off. CloudTrail is that
record. Multi-region matters because activity nobody intends tends to appear in
regions nobody uses. Log file validation produces a signed digest, so a deleted
or edited log file is detectable rather than invisible.

### `<audit bucket>` — S3 bucket

Where CloudTrail and AWS Config deliver. It is:

- **Encrypted** with a customer-managed KMS key (`alias/<org>-<env>-audit`) that
  rotates annually.
- **Versioned**, so an overwrite does not destroy the previous object.
- **Object-locked in COMPLIANCE mode** for 365 days by default. In COMPLIANCE
  mode no principal in the account can shorten the retention or delete a locked
  object — not an administrator, not the account root, not AWS Support.
- **Private**, with all four S3 public access block settings on and object
  ownership set to `BucketOwnerEnforced`, which disables ACLs entirely.
- **TLS-only**: the bucket policy denies every action where
  `aws:SecureTransport` is false.

The bucket policy grants exactly two things: CloudTrail and AWS Config may write
under their own prefixes, and only with `bucket-owner-full-control`, and only
when the call originates from this account. No IAM principal is granted access
by the bucket policy, and nothing is granted `s3:Delete*`.

**Why it matters.** The common failure mode after an incident is that the
attacker deleted the logs. Object lock in COMPLIANCE mode is the control that
makes that impossible rather than merely discouraged. This is usually the single
answer that ends a questionnaire section.

### `<audit bucket>-general` — S3 bucket

A second, ordinary log bucket: encrypted, versioned, private and TLS-only, but
with **no** object lock. Application logs, load balancer logs and access logs
belong here.

**Why it matters.** Logs people are supposed to delete must not share a bucket
with logs nobody may delete. Putting a noisy application log stream into an
object-locked bucket means paying storage for it for a year with no way to stop.

---

## 2. Configuration recording and the conformance set

### `<org>-<environment>-recorder` — AWS Config

Records the configuration of every supported resource type in the region,
including global resources such as IAM, and delivers a snapshot to the audit
bucket every 24 hours.

**Why it matters.** CloudTrail answers "what did someone do". Config answers
"what does this account look like right now, and what did it look like last
Tuesday". Questions such as "was that security group open on the day of the
incident" are answerable with Config and guesswork without it.

### 14 AWS Config managed rules

| Rule | The question it answers |
| --- | --- |
| `root-account-mfa-enabled` | Is the root account protected by MFA? |
| `iam-user-mfa-enabled` | Does every IAM user have MFA? |
| `iam-password-policy` | Does the password policy meet the configured strength? |
| `iam-user-no-policies-check` | Are permissions attached to groups and roles rather than directly to users? |
| `cloud-trail-enabled` | Is CloudTrail on? |
| `cloudtrail-log-file-validation-enabled` | Are the logs tamper-evident? |
| `guardduty-enabled-centralized` | Is threat detection on? |
| `s3-bucket-public-read-prohibited` | Can anyone on the internet read a bucket? |
| `s3-bucket-public-write-prohibited` | Can anyone on the internet write to a bucket? |
| `s3-bucket-server-side-encryption-enabled` | Is every bucket encrypted at rest? |
| `encrypted-volumes` | Is every EBS volume encrypted? |
| `ec2-ebs-encryption-by-default` | Will new volumes be encrypted without anyone remembering? |
| `vpc-default-security-group-closed` | Is the default security group empty? |
| `vpc-flow-logs-enabled` | Is network traffic being recorded? |

The set is deliberately small. Every rule here maps to a question that appears
on real security questionnaires, and each one is either passing or failing with
no interpretation required. A 200-rule conformance pack produces a wall of
findings that nobody triages, which is worse than fourteen that get fixed.

---

## 3. Threat detection

### GuardDuty detector

Enabled with S3 data event monitoring, RDS login monitoring and Lambda network
monitoring. Findings publish every 15 minutes.

EKS audit log monitoring and EBS malware protection are **off**. Both cost real
money and neither produces meaningful findings in an account that does not yet
run EKS or EC2 workloads. Turn them on when the account has something for them
to look at.

**Why it matters.** GuardDuty is the only control here that looks for an
attacker rather than a misconfiguration: credential use from an unusual
location, communication with known-bad infrastructure, cryptomining behaviour.

### `<org>-<environment>-security-alerts` — SNS topic and alert rules

An SNS topic, encrypted with its own customer-managed KMS key
(`alias/<org>-<env>-security-alerts`), that only EventBridge in this account may
publish to. The configured security contacts are subscribed by email, and AWS
Chatbot can be subscribed to deliver the same alerts into Slack. Three
EventBridge rules feed it:

- `<org>-<environment>-guardduty-findings`: every GuardDuty finding of severity
  7 or higher (High and Critical) by default. Low and Medium findings stay in
  the GuardDuty console.
- `<org>-<environment>-root-console-login`: every console sign-in by the root
  user, successful or failed.
- `<org>-<environment>-break-glass-assume`: every `AssumeRole` call on the
  break-glass role, successful or denied.

CloudTrail records root sign-ins in us-east-1, us-east-2 or us-west-2, and
global STS calls in us-east-1, regardless of where the account otherwise runs.
Rules named `<org>-<environment>-fwd-*` in those regions forward the matching
events to the home region through the `<org>-<environment>-event-forwarding`
role, which may put events onto the home region's default event bus and do
nothing else.

**Why it matters.** Detection that nobody is told about is an entry in a
console that someone may open next month. The root user should essentially
never sign in, and the break-glass role exists for incidents, so each of those
events is worth a human looking at the same day.

---

## 4. Identity

### Account password policy

Minimum 14 characters, upper and lower case, a digit and a symbol required,
90-day expiry, the last 24 passwords may not be reused, users may change their
own password.

### `<org>-<environment>-break-glass` — IAM role

Holds `AdministratorAccess`. Can only be assumed with MFA presented within the
configured session window (one hour by default), and sessions are capped at that
same window.

**Why it matters.** Nobody should hold standing administrator rights. This role
is how you get them when something is genuinely broken, and every use of it
lands in CloudTrail with a name attached and raises a security alert. An
account where three people have permanent admin has no such record.

### `<org>-<environment>-config` — IAM role

The service role AWS Config assumes. Carries the AWS-managed `AWS_ConfigRole`
plus a narrow customer-managed policy allowing it to write into the audit
bucket prefix and to use the audit KMS key — nothing else.

### Account-wide S3 public access block

Blocks public access at the account level, above any individual bucket policy.

**Why it matters.** It converts "we must remember never to make a bucket public"
into "we cannot make a bucket public by accident".

### EBS encryption by default

New EBS volumes in the region are encrypted whether or not the person creating
them asks for it.

---

## 5. Network

### `<org>-<environment>-vpc` — a two-tier VPC

- One **public** subnet per availability zone (two by default), with a route to
  an internet gateway. `map_public_ip_on_launch` is **off**: sitting in a public
  subnet does not automatically hand an instance a public address.
- One **private** subnet per availability zone, with no route to the internet
  gateway.
- One NAT gateway by default, shared by all zones, giving the private tier
  outbound access without inbound reachability. Set `single_nat_gateway = false`
  for one per zone: more expensive, survives a zone failure.
- One route table per private subnet, even with a shared NAT gateway, so moving
  to one gateway per zone later is a variable change rather than a rebuild.
- An **S3 gateway endpoint** on every private route table, so traffic to S3 from
  the private tier does not traverse the NAT gateway. Cheaper, and one fewer
  path to the public internet.
- **VPC flow logs** for all traffic to a dedicated CloudWatch log group, 90-day
  retention.
- The **default security group is emptied** of every ingress and egress rule.

### `<org>-<environment>-workload` — security group

No ingress at all, unrestricted egress. A starting point for workloads.

**Why it matters.** A resource launched without a specified security group joins
the VPC default group, which by default permits unrestricted traffic between its
members. Emptying it and providing a named alternative means nothing inherits
access by accident.

---

## 6. Organization

### AWS Organization (optional, off by default)

Created with all features enabled, service control policies and tag policies
enabled at the root, trusted access granted to CloudTrail, Config, GuardDuty and
IAM Identity Center, and the organizational units you asked for — `Security` and
`Workloads` by default.

**Why it matters.** It costs nothing today and it is what lets you add a second
account later without redoing the first one.

> **Careful.** Destroying this resource calls `DeleteOrganization`, which is
> irreversible. If the account already belongs to an organization, leave
> `create_organization = false`.

### Tagging

Every taggable resource carries `Environment`, `Owner`, `ManagedBy = terraform`
and `Baseline = cloud-baseline-kit`. Your own tags can be merged in through
`additional_tags`; the four keys above cannot be overwritten by them.

**Why it matters.** `Baseline = cloud-baseline-kit` is how anyone can tell in
one console filter which resources are managed by this kit and which were
created by hand afterwards.

---

## 7. Cost

### `<org>-<environment>-monthly` — AWS Budget

One monthly cost budget with two alerts: at **80% of actual** spend, and at
**100% of forecast** spend. Both go to the configured email addresses and to an
SNS topic.

**Why it matters.** The actual-spend alert tells you the month is running hot.
The forecast alert usually fires a week or more before the money is gone. One
without the other is either too late or too noisy to act on.

### `<org>-<environment>-budget-alerts` — SNS topic

Carries the budget notifications, with a topic policy allowing the AWS Budgets
service to publish. Subscribe AWS Chatbot to it to deliver the alerts into a
Slack channel.

---

## What is deliberately not here

Being explicit about the edges is part of the deliverable.

- **Multi-account layouts, Control Tower, an OU factory, account vending.** If
  you need those, you need AWS Landing Zone Accelerator or Control Tower, and
  this kit is the wrong tool. It installs one account well.
- **An organization-wide CloudTrail.** The trail covers this account. Making it
  an organization trail is a multi-account decision.
- **CloudTrail data events.** Management events only. S3 and Lambda data events
  are where CloudTrail bills become alarming and an empty account generates
  nothing worth paying for. Enable them per-bucket once there is data to watch.
- **IAM Identity Center (SSO) permission sets.** Who gets access to what is a
  decision about your company, not a baseline.
- **Compliance framework mapping.** No SOC 2, ISO 27001 or PCI control mapping
  is claimed anywhere in this repository. Those are an auditor's job.
- **Anything in a second cloud.** AWS only.

---

## Costs you will actually see

Approximate, `eu-central-1`, an account with no workloads yet:

| Item | Rough monthly cost |
| --- | --- |
| NAT gateway (one) | ~$32 plus data processing |
| AWS Config recorder | a few dollars; scales with the number of resources and rule evaluations |
| GuardDuty | a few dollars on an empty account; scales with CloudTrail and S3 event volume |
| CloudTrail (first trail, management events) | free |
| S3 storage for logs | cents at first |
| KMS keys (audit logs, security alert topic) | $1 per key per month plus request charges |
| VPC flow logs to CloudWatch | scales with traffic; near zero on an idle account |

The NAT gateway is the largest single line. Set `enable_nat_gateway = false` if
nothing in the private tier needs outbound access yet; the S3 gateway endpoint
keeps working either way.
