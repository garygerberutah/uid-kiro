# ---------------------------------------------------------------------------
# Execution roles for the Lambda functions.
#
# Roles are generated from explicit capability profiles supplied by the stack.
# A route that only queries PostgreSQL must not inherit S3 delete or Lambda
# invoke permissions, and a public health function must not read any secret.
# Keeping the profile on the manifest entry makes that boundary reviewable next
# to the handler and prevents a new public route silently inheriting a broad
# shared "api" role.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

locals {
  roles           = toset(keys(var.role_profiles))
  name_tag_prefix = lookup(var.tags, "Name", "")

  # Resource instance keys come only from the manifest-derived capability map.
  # Policy documents can contain bucket, key, function, or queue ARNs that are
  # unknown during a first plan, so their result maps must never determine the
  # for_each shape of the corresponding IAM policy resources.
  secret_profiles = {
    for profile, capabilities in var.role_profiles : profile => capabilities
    if length(capabilities.secret_arns) > 0
  }
  secret_kms_profiles = {
    for profile, capabilities in var.role_profiles : profile => capabilities
    if length(capabilities.secret_kms_key_arns) > 0
  }
  encrypted_data_profiles = {
    for profile, capabilities in var.role_profiles : profile => capabilities
    if length(capabilities.data_kms_actions) > 0 && length(capabilities.data_kms_key_arns) > 0
  }
  bucket_profiles = {
    for profile, capabilities in var.role_profiles : profile => capabilities
    if length(capabilities.s3_statements) > 0
  }
  invoke_profiles = {
    for profile, capabilities in var.role_profiles : profile => capabilities
    if length(capabilities.invokable_function_arns) > 0
  }
  dead_letter_profiles = {
    for profile, capabilities in var.role_profiles : profile => capabilities
    if capabilities.write_dead_letter
  }
}

resource "aws_iam_role" "this" {
  for_each = local.roles

  name               = "${var.name_prefix}-${each.value}"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags = merge(
    var.tags,
    { Profile = each.value },
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-${each.value}" },
  )
}

# The AWS-managed basic policy grants writes to every Lambda log group in the
# account. All groups in this stack are created explicitly, so the execution
# roles need only streams and events under this application's prefix.
data "aws_iam_policy_document" "logs" {
  statement {
    sid     = "WriteApplicationLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.name_prefix}-*:log-stream:*",
    ]
  }
}

resource "aws_iam_role_policy" "logs" {
  for_each = aws_iam_role.this

  name   = "write-application-logs"
  role   = each.value.id
  policy = data.aws_iam_policy_document.logs.json
}

# Required for any function with a vpc_config: Lambda manages elastic network
# interfaces in the selected subnets. The AWS-managed VPC policy also grants
# account-wide CloudWatch Logs writes; a custom policy keeps the scoped log
# policy above meaningful. Only profiles explicitly marked for VPC access get
# these EC2 actions; the shared stack marks every profile used by its 49
# VPC-attached functions, including the otherwise resource-empty public role.
data "aws_iam_policy_document" "vpc" {
  statement {
    sid    = "ManageLambdaNetworkInterfaces"
    effect = "Allow"
    actions = [
      "ec2:AssignPrivateIpAddresses",
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:UnassignPrivateIpAddresses",
    ]
    # EC2 does not support resource-level constraints for all of these Lambda
    # ENI operations. Restricting which roles get this policy is the boundary.
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "vpc" {
  for_each = {
    for profile, role in aws_iam_role.this : profile => role
    if var.role_profiles[profile].vpc_access
  }

  name   = "manage-lambda-network-interfaces"
  role   = each.value.id
  policy = data.aws_iam_policy_document.vpc.json
}

resource "aws_iam_role_policy_attachment" "xray" {
  for_each   = aws_iam_role.this
  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# --- secrets ---------------------------------------------------------------

data "aws_iam_policy_document" "secrets" {
  for_each = local.secret_profiles

  statement {
    sid     = "ReadNamedSecrets"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    # Enumerated, not "secretsmanager:*" on "*". These functions read a known,
    # short list of secrets; anything else is a bug or a compromise.
    resources = each.value.secret_arns
  }
}

resource "aws_iam_role_policy" "secrets" {
  for_each = local.secret_profiles

  name   = "read-secrets"
  role   = aws_iam_role.this[each.key].id
  policy = data.aws_iam_policy_document.secrets[each.key].json
}

# Secrets may use keys unrelated to the application data/environment key.
# Model them separately so reading one credential does not imply permission to
# encrypt S3 data, and so each profile receives only the key for its secrets.
data "aws_iam_policy_document" "secret_kms" {
  for_each = local.secret_kms_profiles

  statement {
    sid       = "DecryptNamedSecrets"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = each.value.secret_kms_key_arns
  }
}

resource "aws_iam_role_policy" "secret_kms" {
  for_each = local.secret_kms_profiles

  name   = "decrypt-secret-values"
  role   = aws_iam_role.this[each.key].id
  policy = data.aws_iam_policy_document.secret_kms[each.key].json
}

# S3 KMS actions follow the operation profile too: a poll endpoint needs
# Decrypt, a report writer needs GenerateDataKey, and a retention worker
# deleting object keys needs no KMS permission at all. Lambda's execution role
# does not need this key merely because Lambda encrypts its environment/code at
# rest; the Lambda service grant handles that separately.
data "aws_iam_policy_document" "encrypted_data" {
  for_each = local.encrypted_data_profiles

  statement {
    sid       = "UseEncryptedApplicationData"
    effect    = "Allow"
    actions   = each.value.data_kms_actions
    resources = each.value.data_kms_key_arns
  }
}

resource "aws_iam_role_policy" "encrypted_data" {
  for_each = local.encrypted_data_profiles

  name   = "use-encrypted-application-data"
  role   = aws_iam_role.this[each.key].id
  policy = data.aws_iam_policy_document.encrypted_data[each.key].json
}

# --- S3 --------------------------------------------------------------------

data "aws_iam_policy_document" "buckets" {
  for_each = local.bucket_profiles

  dynamic "statement" {
    for_each = {
      for index, permission in each.value.s3_statements : tostring(index) => permission
    }
    content {
      sid       = "S3Access${statement.key}"
      effect    = "Allow"
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }
}

resource "aws_iam_role_policy" "buckets" {
  for_each = local.bucket_profiles

  name   = "sife-buckets"
  role   = aws_iam_role.this[each.key].id
  policy = data.aws_iam_policy_document.buckets[each.key].json
}

# --- downstream invocation -------------------------------------------------

data "aws_iam_policy_document" "invoke" {
  for_each = local.invoke_profiles

  statement {
    sid       = "InvokeWorkers"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = each.value.invokable_function_arns
  }
}

resource "aws_iam_role_policy" "invoke" {
  for_each = local.invoke_profiles

  name   = "invoke-workers"
  role   = aws_iam_role.this[each.key].id
  policy = data.aws_iam_policy_document.invoke[each.key].json
}

# Lambda's dead_letter_config names a queue but does not grant permission to
# write it. Only worker-profile functions are invoked asynchronously; sync API
# functions intentionally receive no DLQ config and need no queue permission.
data "aws_iam_policy_document" "dead_letter" {
  for_each = local.dead_letter_profiles

  statement {
    sid       = "WriteDeadLetterQueue"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [var.dead_letter_queue_arn]
  }
}

resource "aws_iam_role_policy" "dead_letter" {
  for_each = local.dead_letter_profiles

  name   = "write-dead-letter-queue"
  role   = aws_iam_role.this[each.key].id
  policy = data.aws_iam_policy_document.dead_letter[each.key].json
}
