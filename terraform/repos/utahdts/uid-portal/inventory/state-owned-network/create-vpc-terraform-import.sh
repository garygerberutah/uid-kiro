#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
BLOCKED: this repository does not own the State of Utah VPC.

The former import generator has been retired because its output could place
organization-owned VPCs, subnets, routes, gateways and NAT gateways under this
application state's lifecycle. Use read-only AWS inventory commands when
collecting evidence, and send every requested network change to the State
network owner.
EOF
exit 1
