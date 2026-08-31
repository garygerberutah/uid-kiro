# ---------------------------------------------------------------------------
# Read-only network inventory for the Lambda functions.
#
# The State of Utah organization owns the VPC, subnets, endpoints, security
# groups, routes and gateways. This module deliberately contains data sources
# only: application Terraform may verify and consume those objects, but it may
# never place them under this state's lifecycle.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

data "aws_vpc" "this" {
  id = var.vpc_id

  lifecycle {
    postcondition {
      condition     = self.cidr_block == var.vpc_ipv4_cidr
      error_message = "Existing VPC ${var.vpc_id} has primary IPv4 CIDR ${self.cidr_block}, not the reviewed ${var.vpc_ipv4_cidr}; do not select or create a replacement network."
    }

    postcondition {
      condition = (
        length(self.cidr_block_associations) == 1 &&
        alltrue([
          for association in self.cidr_block_associations :
          association.cidr_block == var.vpc_ipv4_cidr &&
          association.state == "associated"
        ]) &&
        length(self.ipv6_cidr_block_associations) == 0
      )
      error_message = "Existing VPC ${var.vpc_id} must have exactly one associated IPv4 CIDR, the reviewed ${var.vpc_ipv4_cidr}, and no IPv6 CIDR associations; do not accept or create secondary or dual-stack local routing."
    }
  }
}

data "aws_subnets" "lambda" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }

  filter {
    name   = "subnet-id"
    values = var.private_subnet_ids
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  lifecycle {
    postcondition {
      condition     = toset(self.ids) == toset(var.private_subnet_ids)
      error_message = "Every private_subnet_id must already exist in VPC ${var.vpc_id}; request missing or incorrect network inventory from the State network owner."
    }
  }
}

locals {
  # Look up every security group the application depends on, including groups
  # whose rules must already be configured by the network owner. Combining the
  # ids avoids duplicate data reads when one group serves more than one path.
  referenced_security_group_ids = setunion(
    var.lambda_security_group_ids,
    var.existing_interface_endpoint_security_group_ids,
    toset(compact([
      var.database_security_group_id,
      var.snap_database_security_group_id,
      var.oracle_database_security_group_id,
    ])),
  )
}

data "aws_security_group" "referenced" {
  for_each = local.referenced_security_group_ids

  id = each.value

  lifecycle {
    postcondition {
      condition     = self.vpc_id == var.vpc_id
      error_message = "Existing security group ${each.value} is not in VPC ${var.vpc_id}; application Terraform cannot create or repair a replacement."
    }
  }
}
