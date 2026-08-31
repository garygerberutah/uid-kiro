# ---------------------------------------------------------------------------
# One API Gateway HTTP API, built from services/api/routes/routes.yaml.
#
# Nothing about routing is written twice. The locals below reshape the decoded
# manifest into maps keyed by route id, and every resource is a for_each over
# one of those maps. Adding a route to the YAML adds it here; deleting it from
# the YAML deletes it here. There is no list of routes in this file to forget
# to update.
#
# HTTP API (v2) rather than REST API (v1) because this migration needs none of
# what v1 adds -- request validation, API keys, direct WAF association, private
# integrations -- and v2 costs roughly a third as much per million requests
# with materially lower latency.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

locals {
  api_def         = var.manifest.apis[var.api_key]
  api_name        = var.api_name != "" ? var.api_name : var.name
  name_tag_prefix = lookup(var.tags, "Name", "")

  # Routes that API Gateway should actually expose. Entries with method NONE
  # exist only so Terraform provisions their function (the async workers).
  routed = {
    for r in local.api_def.routes :
    r.id => r
    if try(r.method, "NONE") != "NONE" && try(r.path, null) != null
  }

  # Every routed endpoint is an independently managed Python Lambda. Keeping a
  # second integration path here would let the gateway drift from the manifest
  # and recreate the container/proxy architecture this migration removes.
  python_routes   = local.routed
  deployed_routes = local.python_routes

  # Lambda resource policies can be narrower than the whole API. Replace each
  # path parameter with an ARN wildcard, while retaining the route's literal
  # method and path segments (for example /actuator/features/*).
  permission_paths = {
    for id, route in local.python_routes :
    id => replace(route.path, "/\\{[^}]+\\}/", "*")
  }

  # Routes this API will actually deploy. NONE entries are managed workers and
  # are the only manifest functions omitted from the gateway.
  deployed_route_count = length(local.deployed_routes)

  # A hostname is only worth publishing if something answers on it. Pointing
  # DNS at an API with no routes replaces whatever was serving that name with a
  # uniform 404, and the apply reports success.
  publish_domain       = var.domain_name != "" && local.deployed_route_count > 0
  manage_domain        = local.publish_domain && var.domain_ownership == "managed"
  read_external_domain = local.publish_domain && var.domain_ownership == "external"

  # Routes needing the authorizer. A route with auth "none" is public and must
  # not carry one -- attaching an authorizer to /health would make the health
  # check depend on the database.
  authorized_routes = { for id, r in local.routed : id => r if try(r.auth, "none") != "none" }

  cors           = try(local.api_def.cors, {})
  allowed_origin = try(local.cors.allow_origins_by_env[var.env_name], [])
}

resource "aws_apigatewayv2_api" "this" {
  name          = local.api_name
  description   = var.description != "" ? var.description : try(local.api_def.description, "")
  protocol_type = "HTTP"

  # The default execute-api hostname is an alternate public entry point and
  # managed CORS responses do not reach the Lambda Host guard. This stack is
  # custom-domain-only; the lifecycle precondition below deliberately blocks a
  # plan until the edge owner supplies a real mapping.
  disable_execute_api_endpoint = true

  # CORS is handled by the gateway, not by a filter in application code. The
  # Spring CorsFilter allowed "*" for origins, methods and headers with
  # allowCredentials=true -- a combination browsers reject outright and which
  # would be a wildcard trust if they did not. Origins here are an explicit
  # per-environment list from the manifest.
  # Browser and licensee paths now share this one API-wide CORS policy. The
  # manifest therefore carries the union of methods and headers needed by both
  # route families rather than pretending HTTP APIs support per-route CORS.
  dynamic "cors_configuration" {
    for_each = length(local.allowed_origin) == 0 ? [] : [local.cors]
    content {
      allow_origins     = local.allowed_origin
      allow_methods     = try(cors_configuration.value.allow_methods, ["GET", "POST", "OPTIONS"])
      allow_headers     = try(cors_configuration.value.allow_headers, ["authorization", "content-type"])
      expose_headers    = try(cors_configuration.value.expose_headers, [])
      allow_credentials = try(cors_configuration.value.allow_credentials, false)
      max_age           = try(cors_configuration.value.max_age, 0)
    }
  }

  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-api-gateway" },
  )

  lifecycle {
    # The sole gateway is the state survivor. A rename is an in-place update;
    # any replacement or deletion needs an explicit, separately reviewed code
    # change instead of being hidden inside an ordinary route deployment.
    prevent_destroy = true

    precondition {
      condition     = var.domain_name != ""
      error_message = "A host-gated API requires a custom domain. Configure the API custom-origin hostname and edge forwarding before planning; the default execute-api endpoint is disabled."
    }

    precondition {
      condition     = length(keys(var.manifest.apis)) == 1 && contains(keys(var.manifest.apis), var.api_key)
      error_message = "The HTTP API module must receive exactly one manifest API; one module instance owns every HTTP route."
    }

    precondition {
      condition = (
        length(setsubtract(toset(keys(local.python_routes)), toset(keys(var.integrations)))) == 0 &&
        length(setsubtract(toset(keys(var.integrations)), toset(keys(local.python_routes)))) == 0 &&
        length(setsubtract(toset(keys(local.python_routes)), toset(keys(var.integration_function_names)))) == 0 &&
        length(setsubtract(toset(keys(var.integration_function_names)), toset(keys(local.python_routes)))) == 0
      )
      error_message = "Every routed Lambda must have exactly one integration and function-name entry on this API."
    }
  }
}

# --- access logging --------------------------------------------------------

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigateway/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-api-gateway-logs" },
  )
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true

  # route_settings names concrete routes. API Gateway rejects stage creation
  # if those routes have not reached the service yet, but the route keys alone
  # do not give Terraform a graph edge to aws_apigatewayv2_route.python.
  depends_on = [aws_apigatewayv2_route.python]

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access.arn
    # JSON so Logs Insights can query it. `authorizerError` and `integrationErrorMessage`
    # are the two fields that turn "the API returned 500" into a diagnosis.
    format = jsonencode({
      requestId               = "$context.requestId"
      requestTime             = "$context.requestTime"
      httpMethod              = "$context.httpMethod"
      routeKey                = "$context.routeKey"
      path                    = "$context.path"
      status                  = "$context.status"
      responseLength          = "$context.responseLength"
      integrationLatency      = "$context.integrationLatency"
      responseLatency         = "$context.responseLatency"
      sourceIp                = "$context.identity.sourceIp"
      userAgent               = "$context.identity.userAgent"
      domainName              = "$context.domainName"
      utahId                  = "$context.authorizer.utahId"
      authorizerError         = "$context.authorizer.error"
      integrationErrorMessage = "$context.integrationErrorMessage"
      errorMessage            = "$context.error.message"
    })
  }

  default_route_settings {
    throttling_burst_limit   = var.throttle_burst
    throttling_rate_limit    = var.throttle_rate
    detailed_metrics_enabled = true
  }

  # Aggregate capacity protection. The licensee handler separately preserves
  # its per-Utah-ID 60/minute rule; a stage throttle is not an authorization
  # quota. Former licensee routes receive explicit settings on the shared stage.
  dynamic "route_settings" {
    for_each = var.route_throttles
    content {
      route_key                = "${local.routed[route_settings.key].method} ${local.routed[route_settings.key].path}"
      throttling_burst_limit   = route_settings.value.burst
      throttling_rate_limit    = route_settings.value.rate
      detailed_metrics_enabled = true
    }
  }

  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-api-gateway-default-stage" },
  )
}

# --- authorizer ------------------------------------------------------------

resource "aws_apigatewayv2_authorizer" "this" {
  api_id                            = aws_apigatewayv2_api.this.id
  name                              = local.api_def.authorizer.id
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = var.authorizer.invoke_arn
  authorizer_payload_format_version = "2.0"

  # The simple response ({"isAuthorized": bool, "context": {...}}) rather than
  # an IAM policy document. The authorizer enforces the route role before
  # returning this context; the target Lambda independently repeats that check.
  enable_simple_responses = true

  identity_sources = local.api_def.authorizer.identity_sources

  # The Ping role authorizer sets this to zero so an allow decision cannot
  # outlive JWT exp or stale database roles. The module still follows the
  # manifest if a future identity-only authorizer can safely use a non-zero TTL.
  authorizer_result_ttl_in_seconds = try(local.api_def.authorizer.ttl, 300)
}

resource "aws_lambda_permission" "authorizer" {
  statement_id   = "AllowInvokeFrom-${var.name}-authorizer"
  action         = "lambda:InvokeFunction"
  function_name  = var.authorizer.function_name
  qualifier      = "live"
  principal      = "apigateway.amazonaws.com"
  source_account = var.account_id
  source_arn     = "${aws_apigatewayv2_api.this.execution_arn}/authorizers/${aws_apigatewayv2_authorizer.this.id}"
}

# --- integrations ----------------------------------------------------------

resource "aws_apigatewayv2_integration" "python" {
  for_each = local.python_routes

  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.integrations[each.key]
  payload_format_version = "2.0"

  # Capped at 30s by API Gateway regardless of what the function allows, so a
  # longer Lambda timeout only helps routes that return 202 and finish later.
  timeout_milliseconds = min(try(each.value.timeout, 29), 29) * 1000
}

# --- routes ----------------------------------------------------------------

resource "aws_apigatewayv2_route" "python" {
  for_each = local.python_routes

  api_id    = aws_apigatewayv2_api.this.id
  route_key = "${each.value.method} ${each.value.path}"
  target    = "integrations/${aws_apigatewayv2_integration.python[each.key].id}"

  authorization_type = contains(keys(local.authorized_routes), each.key) ? "CUSTOM" : "NONE"
  authorizer_id      = contains(keys(local.authorized_routes), each.key) ? aws_apigatewayv2_authorizer.this.id : null
}

# --- invoke permissions ----------------------------------------------------

# Scoped to this API, method and route path. A function reachable from one
# route is not implicitly invokable by a second route in the same API.
resource "aws_lambda_permission" "python" {
  for_each = local.python_routes

  statement_id   = "AllowInvokeFrom-${var.name}-${each.key}"
  action         = "lambda:InvokeFunction"
  function_name  = var.integration_function_names[each.key]
  qualifier      = "live"
  principal      = "apigateway.amazonaws.com"
  source_account = var.account_id
  source_arn     = "${aws_apigatewayv2_api.this.execution_arn}/*/${each.value.method}${local.permission_paths[each.key]}"
}

# --- custom domain ---------------------------------------------------------

# The API resource's lifecycle precondition requires a domain, and the
# manifest preconditions require the complete route set. There is no
# execute-api-only or empty-domain deployment mode.

resource "aws_apigatewayv2_domain_name" "this" {
  count       = local.manage_domain ? 1 : 0
  domain_name = var.domain_name

  domain_name_configuration {
    certificate_arn = var.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  lifecycle {
    precondition {
      condition     = can(regex("^arn:aws:acm:${var.region}:${var.account_id}:certificate/[0-9a-f-]+$", var.certificate_arn))
      error_message = "${var.name}: certificate_arn must be an ACM certificate ARN owned by ${var.account_id} in ${var.region} whenever domain_name is configured."
    }
  }

  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-api-gateway-domain" },
  )
}

data "aws_api_gateway_domain_name" "external" {
  count       = local.read_external_domain ? 1 : 0
  domain_name = var.domain_name

  lifecycle {
    postcondition {
      condition = (
        length(self.endpoint_configuration) == 1 &&
        toset(one(self.endpoint_configuration).types) == toset(["REGIONAL"]) &&
        self.security_policy == "TLS_1_2" &&
        self.regional_certificate_arn == var.certificate_arn
      )
      error_message = "${var.name}: the externally owned API Gateway domain must already use the reviewed REGIONAL/TLS_1_2 configuration and exact regional ACM certificate before Terraform may map this API to it. Terraform will not repair the domain."
    }
  }
}

resource "aws_apigatewayv2_api_mapping" "this" {
  count       = local.publish_domain ? 1 : 0
  api_id      = aws_apigatewayv2_api.this.id
  domain_name = var.domain_name
  stage       = aws_apigatewayv2_stage.default.id

  depends_on = [
    aws_apigatewayv2_domain_name.this,
    data.aws_api_gateway_domain_name.external,
  ]
}

# DNS is State-owned. Historical states may contain this address; forget it
# without deleting or changing the live record. The custom-domain target is an
# output for the DNS owner, never an instruction for application Terraform.
removed {
  from = aws_route53_record.this

  lifecycle {
    destroy = false
  }
}

# --- alarms ----------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "gateway_5xx" {
  alarm_name          = "${var.name}-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 5
  period              = 300
  statistic           = "Sum"
  namespace           = "AWS/ApiGateway"
  metric_name         = "5xx"
  treat_missing_data  = "notBreaching"
  dimensions          = { ApiId = aws_apigatewayv2_api.this.id }
  alarm_description   = "${var.name} is returning server errors."
  alarm_actions       = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-api-gateway-5xx" },
  )
}

# 4xx is expected traffic (401s and 403s are the authorizer doing its job), so
# this threshold is a rate, not a count: it catches a broken deploy that starts
# rejecting everyone, not a user mistyping a URL.
resource "aws_cloudwatch_metric_alarm" "gateway_4xx_rate" {
  alarm_name          = "${var.name}-4xx-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  threshold           = 0.5
  treat_missing_data  = "notBreaching"
  alarm_description   = "More than half of requests to ${var.name} are being rejected."
  alarm_actions       = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-api-gateway-4xx-rate" },
  )

  metric_query {
    id          = "rate"
    expression  = "IF(total > 20, errors / total, 0)"
    label       = "4xx rate"
    return_data = true
  }

  metric_query {
    id = "errors"
    metric {
      namespace   = "AWS/ApiGateway"
      metric_name = "4xx"
      period      = 300
      stat        = "Sum"
      dimensions  = { ApiId = aws_apigatewayv2_api.this.id }
    }
  }

  metric_query {
    id = "total"
    metric {
      namespace   = "AWS/ApiGateway"
      metric_name = "Count"
      period      = 300
      stat        = "Sum"
      dimensions  = { ApiId = aws_apigatewayv2_api.this.id }
    }
  }
}
