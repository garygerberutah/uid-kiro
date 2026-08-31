# ---------------------------------------------------------------------------
# RDS Proxy for the portal database.
#
# Deliberately not part of modules/api_environment. That stack consumes a proxy through the
# db_proxy_host variable rather than owning one, so the pool survives a destroy
# of the API stack and an API apply never touches the database tier. The proxy
# authenticates with its named secret; clients use the corresponding database
# credential rather than IAM database authentication.
#
# VPC infrastructure is owned by the State of Utah network team. This module
# may attach owner-provided subnets and security groups to the proxy, but it
# must never create or manage either the groups or their rules.
#
# Hundreds of Lambda executions opening their own PostgreSQL connections will
# exhaust Aurora's max_connections; a few JVM pools on Beanstalk did not. That
# asymmetry is the whole reason this exists.
# ---------------------------------------------------------------------------

terraform {
  # removed blocks are part of the non-destructive network state handoff.
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

# These declarations intentionally hand the old network objects out of this
# state without deleting them. The network owner can inventory or retire them;
# application credentials must not mutate them during this migration.
removed {
  from = aws_security_group.this

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_vpc_security_group_ingress_rule.client

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_vpc_security_group_egress_rule.database

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_vpc_security_group_ingress_rule.database_from_proxy

  lifecycle {
    destroy = false
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name}-role"
  description        = "Lets ${var.name} read its database credential secret"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "secret" {
  statement {
    sid       = "ReadCredential"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.secret_arn]
  }

  # Without this the proxy reaches "available" and then fails every connection
  # with a credential error that does not mention KMS.
  dynamic "statement" {
    for_each = var.secret_kms_key_arn == "" ? [] : [var.secret_kms_key_arn]
    content {
      sid       = "DecryptCredential"
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role_policy" "secret" {
  name   = "read-credential"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.secret.json
}

resource "aws_db_proxy" "this" {
  name                   = var.name
  engine_family          = "POSTGRESQL"
  role_arn               = aws_iam_role.this.arn
  vpc_subnet_ids         = var.subnet_ids
  vpc_security_group_ids = var.proxy_security_group_ids
  require_tls            = true
  idle_client_timeout    = var.idle_client_timeout
  debug_logging          = false

  auth {
    auth_scheme               = "SECRETS"
    secret_arn                = var.secret_arn
    iam_auth                  = "DISABLED"
    client_password_auth_type = var.client_password_auth_type
  }

  tags = var.tags
}

resource "aws_db_proxy_default_target_group" "this" {
  db_proxy_name = aws_db_proxy.this.name

  connection_pool_config {
    max_connections_percent      = var.max_connections_percent
    max_idle_connections_percent = var.max_idle_connections_percent
    connection_borrow_timeout    = var.connection_borrow_timeout
  }
}

# Target health is deliberately not asserted here. RDS leaves target_arn null
# for both TRACKED_CLUSTER and RDS_INSTANCE targets, so any check on it fails
# permanently, and the instance target sits in PENDING_PROXY_CAPACITY for
# minutes after creation regardless. Verify out of band:
#
#   aws rds describe-db-proxy-targets --db-proxy-name <name> \
#     --query "Targets[?Type=='RDS_INSTANCE'].TargetHealth"
resource "aws_db_proxy_target" "this" {
  db_cluster_identifier = var.db_cluster_identifier
  db_proxy_name         = aws_db_proxy.this.name
  target_group_name     = aws_db_proxy_default_target_group.this.name
}
