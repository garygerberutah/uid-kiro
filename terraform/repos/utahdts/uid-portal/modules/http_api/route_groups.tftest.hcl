mock_provider "aws" {
  override_during = plan
  mock_resource "aws_apigatewayv2_api" {
    defaults = {
      id            = "abc1234567"
      execution_arn = "arn:aws:execute-api:us-west-2:705157108110:abc1234567"
    }
  }
  mock_resource "aws_apigatewayv2_integration" {
    defaults = { id = "integ01" }
  }
  mock_resource "aws_apigatewayv2_authorizer" {
    defaults = { id = "auth01" }
  }
  mock_data "aws_api_gateway_domain_name" {
    defaults = {
      security_policy          = "TLS_1_2"
      regional_certificate_arn = "arn:aws:acm:us-west-2:705157108110:certificate/synthetic"
      endpoint_configuration   = [{ types = ["REGIONAL"] }]
    }
  }
}

variables {
  name       = "uid-portal-at"
  api_key    = "portal"
  env_name   = "at"
  region     = "us-west-2"
  account_id = "705157108110"
  authorizer = {
    invoke_arn    = "arn:aws:apigateway:us-west-2:lambda:path/2015-03-31/functions/authorizer/invocations"
    function_name = "uid-portal-at-portal_jwt"
  }
  manifest = {
    apis = {
      portal = {
        description = "synthetic"
        cors        = { allow_origins_by_env = { at = ["https://insureu.uid-dev.utah.gov"] } }
        authorizer  = { id = "portal_jwt", identity_sources = ["$request.header.Authorization"], ttl = 0 }
        routes = [
          { id = "health", method = "GET", path = "/health", auth = "none" },
          { id = "worker", method = "NONE", path = null, auth = "none" },
          {
            id          = "forms_example_filer"
            auth        = "jwt"
            roles       = ["ROLE_AUTHENTICATED"]
            concurrency = 10
            routes = [
              { method = "GET", path = "/portal/forms/example", action = "list" },
              { method = "post", path = "/portal/forms/example", action = "create" },
              { method = "GET", path = "/portal/forms/example/{id}", action = "get" },
            ]
          },
        ]
      }
    }
  }
  integrations = {
    health                      = "arn:health"
    forms_example_filer__list   = "arn:filer"
    forms_example_filer__create = "arn:filer"
    forms_example_filer__get    = "arn:filer"
  }
  integration_function_names = {
    health                      = "uid-portal-at-health"
    forms_example_filer__list   = "uid-portal-at-forms_example_filer"
    forms_example_filer__create = "uid-portal-at-forms_example_filer"
    forms_example_filer__get    = "uid-portal-at-forms_example_filer"
  }
  domain_name      = "api.uid-dev.utah.gov"
  domain_ownership = "external"
  certificate_arn  = "arn:aws:acm:us-west-2:705157108110:certificate/synthetic"
}

run "a_group_becomes_one_route_per_method_and_path" {
  command = plan
  assert {
    condition = { for key, route in aws_apigatewayv2_route.python : key => route.route_key } == {
      health                      = "GET /health"
      forms_example_filer__list   = "GET /portal/forms/example"
      forms_example_filer__create = "POST /portal/forms/example"
      forms_example_filer__get    = "GET /portal/forms/example/{id}"
    }
    error_message = "A single route keeps its id; a group yields one route per action."
  }
  assert {
    condition = alltrue([
      for key, permission in aws_lambda_permission.python :
      permission.function_name == "uid-portal-at-forms_example_filer" if startswith(key, "forms_example_filer__")
    ]) && length(distinct([for key, integration in aws_apigatewayv2_integration.python : integration.integration_uri if startswith(key, "forms_example_filer__")])) == 1
    error_message = "Every route of a group must integrate with and permit the one grouped function."
  }
  assert {
    condition     = aws_lambda_permission.python["forms_example_filer__get"].source_arn == "arn:aws:execute-api:us-west-2:705157108110:abc1234567/*/GET/portal/forms/example/*" && aws_lambda_permission.python["forms_example_filer__get"].statement_id == "AllowInvokeFrom-uid-portal-at-forms_example_filer__get"
    error_message = "Each grouped route keeps its own method and path scoped invoke permission."
  }
  assert {
    condition     = alltrue([for key, route in aws_apigatewayv2_route.python : route.authorization_type == (key == "health" ? "NONE" : "CUSTOM")])
    error_message = "A group's authentication applies to every one of its routes and to no other."
  }
}

run "a_group_route_missing_its_integration_is_refused" {
  command = plan
  variables {
    integrations = {
      health                    = "arn:health"
      forms_example_filer__list = "arn:filer"
    }
  }
  expect_failures = [aws_apigatewayv2_api.this]
}
