# The proxy survived the historical state loss. Keep these configuration-driven
# imports: they are idempotent after the reviewed recovery plan records the
# existing app-owned resources in this root's remote state.
import {
  to = module.proxy.aws_db_proxy.this
  id = "uid-dev-portal-proxy"
}

import {
  to = module.proxy.aws_db_proxy_default_target_group.this
  id = "uid-dev-portal-proxy"
}

import {
  to = module.proxy.aws_db_proxy_target.this
  id = "uid-dev-portal-proxy/default/TRACKED_CLUSTER/uid-dev-postgresqlv2"
}
