###############################################################################
# Two-tier VPC.
#
# The module owns the VPC itself: DNS, the stripped default security group and
# flow logs. The subnet/route/NAT layout is composed here, because that layout
# is the part every customer wants to argue about and it should be readable in
# one file rather than buried behind twenty module inputs.
###############################################################################

module "vpc" {
  source = "git::https://github.com/moveeeax/terraform-aws-vpc.git?ref=fb1db2b82a32b807005de9f82fb15bd2da30dbee"

  name       = "${local.name_prefix}-vpc"
  cidr_block = var.vpc_cidr_block

  enable_dns_support            = true
  enable_dns_hostnames          = true
  manage_default_security_group = true

  enable_flow_log                   = true
  flow_log_traffic_type             = "ALL"
  flow_log_retention_in_days        = 90
  flow_log_max_aggregation_interval = 600

  tags = local.tags
}

resource "aws_subnet" "public" {
  count = var.availability_zone_count

  vpc_id            = module.vpc.id
  availability_zone = local.availability_zones[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr_block, local.subnet_newbits, count.index)

  # Public means "has a route to the internet gateway", not "hands out public
  # IPs to anything launched into it". Anything that genuinely needs a public
  # address should ask for one.
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${local.name_prefix}-public-${local.availability_zones[count.index]}"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  count = var.availability_zone_count

  vpc_id            = module.vpc.id
  availability_zone = local.availability_zones[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr_block, local.subnet_newbits, local.private_subnet_index + count.index)

  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${local.name_prefix}-private-${local.availability_zones[count.index]}"
    Tier = "private"
  })
}

resource "aws_internet_gateway" "this" {
  vpc_id = module.vpc.id

  tags = merge(local.tags, { Name = "${local.name_prefix}-igw" })
}

resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : var.availability_zone_count) : 0

  domain = "vpc"

  tags = merge(local.tags, { Name = "${local.name_prefix}-nat-${count.index}" })
}

resource "aws_nat_gateway" "this" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : var.availability_zone_count) : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(local.tags, { Name = "${local.name_prefix}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = module.vpc.id

  tags = merge(local.tags, { Name = "${local.name_prefix}-public" })
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count = var.availability_zone_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# One private route table per zone even with a single NAT gateway, so that
# moving to one gateway per zone later is a variable flip rather than a
# route table rebuild.
resource "aws_route_table" "private" {
  count = var.availability_zone_count

  vpc_id = module.vpc.id

  tags = merge(local.tags, {
    Name = "${local.name_prefix}-private-${local.availability_zones[count.index]}"
  })
}

resource "aws_route" "private_default" {
  count = var.enable_nat_gateway ? var.availability_zone_count : 0

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[var.single_nat_gateway ? 0 : count.index].id
}

resource "aws_route_table_association" "private" {
  count = var.availability_zone_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Gateway endpoint for S3: keeps bucket traffic from the private tier off the
# NAT gateway, which is both cheaper and one less path to the public internet.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = module.vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id

  tags = merge(local.tags, { Name = "${local.name_prefix}-s3" })
}

###############################################################################
# A starting security group for workloads: no ingress, all egress. Consumers
# clone it or reference it; the point is that nothing in the account starts life
# attached to the VPC default group.
###############################################################################

module "workload_security_group" {
  source = "git::https://github.com/moveeeax/terraform-aws-security-group.git?ref=2324d2b02b65135e76a759d9f88bc5cdb73261da"

  name        = "${local.name_prefix}-workload"
  description = "Baseline workload security group: no ingress, unrestricted egress."
  vpc_id      = module.vpc.id

  ingress_rules = []

  tags = local.tags
}
