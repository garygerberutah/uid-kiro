# Dev RDS Proxy ownership

This root owns the RDS Proxy and its IAM role, not the shared VPC network. It
only attaches existing State-network subnets and security groups supplied in
`main.tf`; security-group rules are owned outside this repository.

The first reviewed plan after the network-boundary change should show the old
proxy SG and SG-rule addresses as `forget` only (`removed` blocks use
`destroy = false`). It may update the proxy to attach the existing
`sg-0637efea445216701`. It must not create, update, replace or delete any
network resource.

`imports.tf` declaratively adopts the surviving app-owned proxy, its implicit
default target group and its Aurora cluster target. The first recovery plan
must show those exact three resources as imports, never creates. Keep the
import blocks after recovery; they are idempotent when the same addresses and
identifiers are already in state.

Use a saved plan and the repository boundary check:

```bash
TF_ROOT="aws/terraform/repos/utahdts/uid-portal/stacks/db-proxy/dev"
umask 077
python3 aws/terraform/repos/utahdts/uid-portal/scripts/check-state-owned-boundary.py \
  --terraform-root "$TF_ROOT"
terraform -chdir="$TF_ROOT" init -input=false
PLAN_FILE="proxy-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%dT%H%M%SZ)-$$.tfplan"
test ! -e "$TF_ROOT/$PLAN_FILE"
terraform -chdir="$TF_ROOT" plan -input=false -out="$PLAN_FILE"
terraform -chdir="$TF_ROOT" show -json "$PLAN_FILE" |
  python3 aws/terraform/repos/utahdts/uid-portal/scripts/check-state-owned-boundary.py \
    --terraform-root "$TF_ROOT" \
    --plan-json -
terraform -chdir="$TF_ROOT" show "$PLAN_FILE"
```

Only apply that exact saved plan after reviewing it; never run bare
`terraform apply`, which silently makes a different automatic plan:

```bash
terraform -chdir="$TF_ROOT" apply "$PLAN_FILE"
```

If the existing group does not supply the required PostgreSQL path, stop and
send the evidence to the State network owner; do not add a rule here.

Every pre-hardening saved plan is invalid and may contain cleartext secrets.
In particular, never read or apply the ignored legacy `proxy.tfplan` or
`infra/terraform/envs/dev/dev.tfplan`; neither was moved into this submodule.
Only the operator may quarantine one
by restricting it to mode 0600 and moving it outside the working tree, or
securely delete it after satisfying retention requirements.
