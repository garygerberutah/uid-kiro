# Declarative and idempotent: when live inventory finds one reviewed survivor,
# Terraform plans its adoption at the stable address instead of a create; the
# reviewed saved plan performs that import on apply. An empty id is valid only
# when the shared live-inventory guard also finds zero APIs.
import {
  for_each = toset(compact([var.api_gateway_survivor_id]))

  to = module.stack.module.portal_api.aws_apigatewayv2_api.this
  id = each.value
}
