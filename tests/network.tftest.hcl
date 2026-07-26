mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_availability_zones" {
    defaults = {
      names = ["eu-central-1a", "eu-central-1b", "eu-central-1c", "eu-central-1d"]
    }
  }
}

variables {
  aws_region            = "eu-central-1"
  org_name              = "acme"
  environment           = "prod"
  audit_log_bucket_name = "acme-prod-audit-logs"
  monthly_budget_usd    = 500
  budget_alert_emails   = ["cloud-alerts@example.com"]
  vpc_cidr_block        = "10.20.0.0/16"
}

run "two_tiers_across_two_zones_by_default" {
  command = plan

  assert {
    condition     = length(aws_subnet.public) == 2 && length(aws_subnet.private) == 2
    error_message = "The default layout must be two public and two private subnets."
  }

  assert {
    condition     = aws_subnet.public[0].cidr_block == "10.20.0.0/24" && aws_subnet.public[1].cidr_block == "10.20.1.0/24"
    error_message = "Public subnets must be carved from the bottom of the VPC range."
  }

  assert {
    condition     = aws_subnet.private[0].cidr_block == "10.20.128.0/24" && aws_subnet.private[1].cidr_block == "10.20.129.0/24"
    error_message = "Private subnets must start halfway up the VPC range, leaving room to grow either tier."
  }

  assert {
    condition = length(distinct([
      for s in concat(aws_subnet.public, aws_subnet.private) : s.cidr_block
    ])) == 4
    error_message = "No two subnets may share a CIDR block."
  }

  assert {
    condition = alltrue([
      for s in concat(aws_subnet.public, aws_subnet.private) : s.map_public_ip_on_launch == false
    ])
    error_message = "No subnet may hand out public IPs automatically; that has to be an explicit decision per instance."
  }

  assert {
    condition     = aws_subnet.public[0].availability_zone == "eu-central-1a" && aws_subnet.public[1].availability_zone == "eu-central-1b"
    error_message = "Subnets must be spread across distinct availability zones in order."
  }
}

run "public_tier_routes_to_the_internet_gateway_and_private_does_not" {
  command = plan

  assert {
    condition     = aws_route.public_default.destination_cidr_block == "0.0.0.0/0"
    error_message = "The public route table must carry a default route."
  }

  assert {
    condition     = aws_route.public_default.nat_gateway_id == null
    error_message = "The public default route must go to the internet gateway, never through NAT."
  }

  assert {
    condition     = length(aws_route_table.private) == 2
    error_message = "There must be one private route table per zone, so switching to one NAT gateway per zone is a variable flip."
  }

  assert {
    condition = alltrue([
      for r in aws_route.private_default : r.gateway_id == null
    ])
    error_message = "A private subnet with a route to the internet gateway is not a private subnet."
  }

  assert {
    condition     = length(aws_route_table_association.private) == 2 && length(aws_route_table_association.public) == 2
    error_message = "Every subnet must be associated with a route table; unassociated subnets silently inherit the main table."
  }

  assert {
    condition     = aws_vpc_endpoint.s3.service_name == "com.amazonaws.eu-central-1.s3"
    error_message = "The S3 gateway endpoint must be built for the region the baseline is installed into."
  }

  assert {
    condition     = aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway"
    error_message = "The S3 endpoint must be a gateway endpoint; an interface endpoint bills per hour and per gigabyte for the same traffic."
  }
}

run "single_nat_gateway_is_the_default_and_shared_by_every_zone" {
  command = plan

  assert {
    condition     = length(aws_nat_gateway.this) == 1 && length(aws_eip.nat) == 1
    error_message = "The default must be one NAT gateway; one per zone triples the hourly charge for an empty account."
  }

  assert {
    condition     = length(aws_route.private_default) == 2
    error_message = "Both private route tables must still get a default route through the shared NAT gateway."
  }
}

run "one_nat_gateway_per_zone_when_asked" {
  command = plan

  variables {
    availability_zone_count = 3
    single_nat_gateway      = false
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 3 && length(aws_eip.nat) == 3
    error_message = "Turning off single_nat_gateway must create one gateway per zone."
  }

  assert {
    condition = alltrue([
      for i, ngw in aws_nat_gateway.this : ngw.tags["Name"] == "acme-prod-nat-${i}"
    ])
    error_message = "Each NAT gateway must be named after the index of the zone it serves."
  }

  assert {
    condition     = aws_subnet.private[2].cidr_block == "10.20.130.0/24"
    error_message = "Adding a third zone must extend the private range rather than renumber the existing subnets."
  }
}

run "private_tier_has_no_egress_path_when_nat_is_disabled" {
  command = plan

  variables {
    enable_nat_gateway = false
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 0 && length(aws_eip.nat) == 0
    error_message = "Disabling NAT must remove the gateways and their elastic IPs."
  }

  assert {
    condition     = length(aws_route.private_default) == 0
    error_message = "With no NAT gateway there must be no default route out of the private tier."
  }

  assert {
    condition     = aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway"
    error_message = "The S3 endpoint is how a NAT-less private tier still reaches the log buckets and must survive disabling NAT."
  }
}

run "names_carry_the_account_prefix_and_the_zone" {
  command = plan

  assert {
    condition     = module.workload_security_group.name == "acme-prod-workload"
    error_message = "The baseline workload security group must be named from the account prefix."
  }

  assert {
    condition     = aws_subnet.public[1].tags["Name"] == "acme-prod-public-eu-central-1b"
    error_message = "Subnet names must include the zone; an operator reading the console should not have to click into a subnet to find out where it is."
  }

  assert {
    condition     = aws_route_table.private[0].tags["Name"] == "acme-prod-private-eu-central-1a"
    error_message = "Per-zone route tables must be named after their zone."
  }

  assert {
    condition     = aws_internet_gateway.this.tags["Name"] == "acme-prod-igw"
    error_message = "The internet gateway must carry the account prefix."
  }
}
