# Terraform state and operating rules

The API environment roots are thin wrappers over `modules/api_environment`.
Routing comes only from the parent service repository's
`services/api/routes/routes.yaml`; environment roots forward values and must
not develop their own architecture.

## Database boundary

The portal application uses database `insureu`, schema `uid_portal`, in every
environment. The separate Vertafore SnapProxy source keeps database `postgres`,
schema `snapproxy`. Repository SBOM evidence uses its own database `sbom`,
schema `sbom`; these Terraform roots neither provision nor migrate any of those
State-owned databases.

An initial AT apply on 2026-08-17 was interrupted after partially creating the
stack. The remote AT state is therefore not empty; follow the interrupted-apply
recovery procedure and F-84 before making another plan or apply.

## State layout

| Root | Backend/state | Purpose |
|---|---|---|
| `envs/dev` | `s3://uid-portal-tfstate/apigw/dev/terraform.tfstate` | historical dev stack; reconcile before AT becomes the one nonprod API owner |
| `envs/at` | `s3://uid-portal-tfstate/apigw/at/terraform.tfstate` | intended `uid-dev-api-gateway` owner in the same account as dev |
| `envs/prod` | `s3://uid-portal-tfstate-281669077180/apigw/prod/terraform.tfstate` | production API stack in its own account |
| `stacks/db-proxy/dev` | `s3://uid-portal-tfstate/apigw/dev/db-proxy/terraform.tfstate` | long-lived dev RDS Proxy |
| `inventory/state-owned-network/aws-vpc-base` | no deployable state; never plan/apply | historical dev network inventory only |

`stacks/cdn-headers/unassigned` is an independently stateful, currently
unassigned single-resource configuration. It creates a CloudFront
response-headers policy but cannot attach it because the existing distributions
are not owned here. Do not plan it until its environment and backend are
explicitly decided.

Dev and AT intentionally share the existing state bucket because they share
account `705157108110`, while their keys remain distinct. They must not both
continue to own an API: inventory both states and live APIs, then migrate or
retire the dev-owned objects before AT satisfies the one-gateway rule.
Production uses an account-specific globally unique bucket. The production
bucket must be created, versioned and blocked from public access before the
first init; the commands and exact name are in its `backend.tf`.

Authenticated inventory on 2026-08-19 found no live REST or HTTP APIs in the
shared account. AT state nevertheless still tracks absent HTTP API
`ernb8dntcl` at
`module.stack.module.portal_api.aws_apigatewayv2_api.this`. Legacy dev state
still tracks the absent custom domains `licensee-api.uid-dev.utah.gov` and
`portal-api.uid-dev.utah.gov` at
`module.stack.module.licensee_api.aws_apigatewayv2_domain_name.this[0]` and
`module.stack.module.portal_api.aws_apigatewayv2_domain_name.this[0]`,
respectively. AT state owns no custom domain or API mapping. These are stale
state records, not authorization to recreate the absent resources; reconcile
the state lineages in reviewed configuration before planning a replacement API.

The shared stack makes that rule a hard plan-time precondition. It unions HTTP
APIs tagged `Application=uid-portal-api` with the exact current and historical
UID Portal API names in the target account and Region. Zero is accepted only
when `api_gateway_survivor_id` is empty; one is accepted only when that input
exactly identifies it; more than one always fails. Each environment root has a
declarative import block that makes the saved plan import a nonempty reviewed
id into the stable
`module.stack.module.portal_api.aws_apigatewayv2_api.this` address rather than
create another. Thus a missing or wrong state does not plan a second API beside
the live survivor. `prevent_destroy` blocks an incidental replacement or
deletion.

Before planning and again immediately before applying a saved plan, run
`aws/terraform/repos/utahdts/uid-portal/scripts/check-api-gateway-ownership.py`.
It compares the literal reviewed
tfvars declaration with every API Gateway v2 resource in the current state and
the read-only live inventory. In AT, live custom-domain inventory must contain
only the exact configured hostname, but the externally owned domain itself must
never enter application state. The application state may own its single root
API mapping only after the owner has made that domain REGIONAL/TLS 1.2. Any
other or additional domain stops the plan. AT must also pass
`--sibling-tf-root aws/terraform/repos/utahdts/uid-portal/envs/dev` after
initializing that real S3
backend. The script binds both `--tf-root` and the sibling path to this
checkout's exact environment roots and requires the sibling dev state to own
zero API Gateway v2 APIs, custom domains and mappings. The AT state must own no
custom-domain resource; an API or mapping may exist only at its stable target
address. A gateway resource owned at any other target-state address, or any
gateway resource at all in the dev sibling state, stops for an explicit
state-lineage reconciliation using reviewed declarative configuration.
Do not point the guard at an empty substitute
directory or remove state without first proving which state will own the live
object. An out-of-band API with an arbitrary name and no
application tag is outside what Terraform can classify as UID Portal; an
account tag policy/SCP and the post-apply live audit are still required for
that administrative boundary.

This is fail-closed for plans made from these roots, not an AWS account mutex.
The immediate pre-apply recheck narrows the approval-window race, but a
concurrent administrator or other automation can still call `CreateApi` after
the check. Restrict creation to the protected deployment role/path and enforce
the application tag with IAM/SCP controls for the account-wide "ever" rule.
The two S3 backends cannot be locked as one transaction, so serialize dev/AT
deploy paths and prohibit out-of-band state writes as part of that boundary.

A fresh first apply starts with an empty survivor declaration because no API id
exists yet. Immediately record the resulting `api_gateway_id` output in that
environment's `api_gateway_survivor_id`; every later preflight rejects an empty
declaration beside a state-owned/live API. The declarative import remains in
configuration and is idempotent for the already-owned address.

All S3 backends use native conditional locking (`use_lockfile = true`), which
requires Terraform 1.10 or newer. Provider lockfiles are committed for every
root. A `.tflock` object means an operation may be active; confirm no process is
using the state before force-unlocking it.

## Guarded full environment build

From the parent `uid-portal` repository root, use the namespaced entry points
below. They operate only on the corresponding complete API environment root;
the separate dev RDS Proxy and CDN policy roots remain held and independently
reviewed. State-owned network, database, secret, adopted bucket, CloudFront,
DNS, certificate and KMS resources are never replacement selectors.

Start with the read-only inventory:

```bash
aws/terraform/repos/utahdts/uid-portal/scripts/full-build-tf-at.sh --dry-run
aws/terraform/repos/utahdts/uid-portal/scripts/full-build-tf-prod.sh --dry-run
```

The inventory prints a stable opaque selector for each eligible application
resource and sanitizes string `for_each` keys. A tagged live application ARN
which is absent from Terraform state blocks planning; reconcile it through
reviewed configuration/import instead of deleting it. Tag inventory cannot
prove that an untagged object is absent, so the ordinary full plan and service
ownership checks remain mandatory.

Create a complete saved plan, optionally selecting individual stateless
resources for graph-aware delete/recreate:

```bash
aws/terraform/repos/utahdts/uid-portal/scripts/full-build-tf-at.sh --plan \
  --delete-recreate r-SELECTOR_FROM_DRY_RUN \
  --allow-delete r-EXACT_RETIRED_RESOURCE_SELECTOR
```

`--delete-recreate` maps to Terraform `-replace` within the complete graph; it
is not a raw delete and Terraform decides safe dependency ordering.
`--allow-delete` does not target anything--it acknowledges one delete-only
change already required by checked-in configuration. Every replacement and
delete must be selected individually or the plan is rejected. Durable
application resources (the gateway, domains/mappings, logs, queues, topics and
application-created buckets) are labeled `application-hold`; they have
selectors, but remain protected by their checked-in lifecycle and cannot be
replaced until a separate reviewed source change deliberately permits it.
Adopted State buckets and every other State-owned dependency never receive a
selector.

After reviewing the exact private plan and text paths printed by the planner,
apply from an attended terminal within the 30-minute window:

```bash
aws/terraform/repos/utahdts/uid-portal/scripts/full-build-tf-at.sh --apply-plan \
  aws/terraform/repos/utahdts/uid-portal/scripts/uid-full-build-at-XXXXXX/full-build.tfplan
```

The planner creates each bundle in a unique, gitignored directory beside the
entry-point scripts
(`aws/terraform/repos/utahdts/uid-portal/scripts/uid-full-build-<environment>-XXXXXX/`).
The directory is mode 0700 and its plan, rendered review and metadata files are
mode 0600 because they can contain cleartext variable and state values. Securely
remove an expired or applied bundle when its retention requirements have been
satisfied.

The apply invocation rechecks account, state lineage/serial, source and
placeholder-package digests, plan hash and semantics, API ownership,
State-owned boundaries, tagged inventory and the explicit destructive
selections. It requires a typed phrase, applies only the saved plan, then runs
the live Lambda/API ingress audit. There is no auto-approve, Terraform
destroy/targeting, imperative state surgery or AWS delete path.

## Reviewed-plan workflow

### Developer-only email in the nonproduction account

The AT deployment in account `705157108110` redirects all application email to
its one approved private `alert_emails` recipient. The module forwards that
address as `DEV_EMAIL_RECIPIENT`; production receives no override. SIFE messages
and operational alerts carry a `[DEV]` subject plus the intended production
recipients, original subject, and original message. Preview links and data
remain from the current environment. CloudWatch alarm subscriptions also use
the same single recipient, retaining their normal SNS message format.

Keep the mailbox out of tracked files. CI supplies the one-entry list through
`AT_ALERT_EMAILS_JSON`; local planning uses the ignored, mode-0600
`envs/at/ci-alerts.local.auto.tfvars` file. The plan rejects missing, multiple,
or malformed recipient addresses. Do not replace the list with a broader
distribution list to satisfy this guard.

Apply the reviewed saved plan and publish the matching tested Lambda code;
configuration alone cannot update an already published worker implementation.
This change does not provision or rotate the State-owned SendGrid secret,
alter the sender, or grant database roles. The historical dev root stays
non-deployable so AT remains the one nonproduction API owner.

### Create and review the plan

```bash
cd aws/terraform/repos/utahdts/uid-portal/envs/at
terraform init
terraform validate
python3 ../../scripts/check-state-owned-boundary.py --terraform-root .
PLAN_FILE="at-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%dT%H%M%SZ)-$$.tfplan"
test ! -e "$PLAN_FILE"
terraform plan \
  -var="release_version=$(git rev-parse HEAD)" \
  -var="build_time=$(git show -s --format=%cI HEAD)" \
  -out="$PLAN_FILE"
terraform show -no-color "$PLAN_FILE"
terraform show -json "$PLAN_FILE" |
  python3 ../../scripts/check-state-owned-boundary.py \
    --terraform-root . --plan-json -
# review that exact file, then in the protected deployment environment:
terraform show -json "$PLAN_FILE" |
  python3 ../../scripts/check-state-owned-boundary.py \
    --terraform-root . --plan-json -
terraform apply "$PLAN_FILE"
```

That snippet assumes the target database has already been migrated and
verified through the repository's latest `V###` migration. Follow the
approved-network procedure in
[`docs/apigw-migration/04-runbook.md`](../../../../../docs/apigw-migration/04-runbook.md)
before creating or applying the infrastructure plan; the API contains routes
that depend on the newest tables and functions.

Always apply the saved plan that was reviewed. `*.tfplan` and the complete
generated `scripts/uid-full-build-*/` bundles are ignored because saved plans
can contain cleartext variable and state values. Do not commit one or reuse one
after configuration, credentials or remote state have changed. Every
pre-hardening saved plan is invalid and must never be read or applied. Known
files include `at.tfplan`, `at-recovery.tfplan`, the legacy local
`infra/terraform/envs/dev/dev.tfplan`, and
`infra/terraform/db-proxy/dev/proxy.tfplan`. Those pre-migration files were
deliberately excluded from this submodule. Only the operator may quarantine
one by restricting it to mode 0600 and moving it outside the working tree, or
securely delete it after satisfying retention requirements.

The source-only formatting and contract gates do not contact AWS:

```bash
terraform fmt -recursive -check -diff aws/terraform/repos/utahdts/uid-portal
services/api/.venv/bin/python -m pytest -q services/api/tests/test_terraform_contract.py
```

The central `uid-portal-terraform-validate` reusable workflow initializes
providers without a backend and runs `terraform validate` for all environment
roots, the dev proxy, and the unassigned CDN headers stack. The parent
`apigw-api` workflow delegates to it; Terraform automation is not copied into
the application repository. Historical State-owned network inventory is
deliberately excluded. Its validation step alone sets
`TF_VAR_offline_provider_validation=true`, which suppresses AWS credential,
account-ID and instance-metadata requests and temporarily omits the provider's
allowed-account list. The variable defaults to `false`; never set it for a
plan or apply, where the credential checks and account guard are required. A
`terraform_data` lifecycle precondition also rejects any plan made with the
flag enabled, so accidentally adding it to tfvars cannot create an unguarded
saved plan.

To reproduce that credential-free check for one root, use the flag only for
these two commands:

```bash
TF_DATA_DIR="$PWD/.terraform-validation/dev" TF_VAR_offline_provider_validation=true terraform -chdir=aws/terraform/repos/utahdts/uid-portal/envs/dev init -backend=false -input=false -lockfile=readonly
TF_DATA_DIR="$PWD/.terraform-validation/dev" TF_VAR_offline_provider_validation=true terraform -chdir=aws/terraform/repos/utahdts/uid-portal/envs/dev validate
```

The dedicated `TF_DATA_DIR` is part of the safety boundary: without it, a
previous local S3-backed init can leave cached backend metadata that causes a
later `init -backend=false` to request AWS credentials before validation.

The validation workflow does not plan or apply. The separate AT and production
release workflows create saved plans. Their branch triggers are plan-only, and
a manual dispatch plus protected-environment approval is required to apply the
reviewed artifact.

## Before a first plan

Resolve every placeholder from the target account. In particular:

- VPC, subnet and route-table IDs;
- the portal RDS Proxy endpoint and proxy security group;
- snapproxy and Oracle hosts/network boundaries;
- secret names and customer-managed secret keys, when used;
- deploy-role OIDC trust for both reusable-workflow subjects: the plan job uses
  the repository/ref subject because it has no GitHub environment, while the
  protected apply job uses the `at` or `prod` environment subject;
- the SIFE buckets that already hold files, their default encryption, and every
  customer-managed bucket key in `adopted_bucket_kms_key_arns` (including a key
  policy that admits the generated runtime roles), or the bucket purpose in
  `adopted_buckets_without_customer_kms` after verifying SSE-S3/AWS-managed
  encryption; validation requires every adopted bucket to be classified;
- API custom-origin hostname, certificate, and the separately owned CloudFront
  behavior that preserves the approved Host/Authorization contract;
- preserve the Cloud IAM-approved shared Ping contract pinned in AT/production:
  the exact audience, required scope set, `azp` client, and protected-header
  `typ=at+jwt`; lifecycle preconditions reject incomplete or different values;
- JWKS egress and, before mail-producing jobs are enabled, outbound HTTPS to
  the SendGrid v3 Mail Send API;
- alarm recipients and account concurrency budget.

Live inventory on 2026-08-17 resolved AT's VPC, subnets, route table, RDS
Proxy/database security group, snapproxy/Oracle paths, secrets and adopted SIFE
buckets. AT intentionally reuses dev-account resources. The supplied SendGrid
secret ARN is a State-owned, read-only runtime dependency in the shared
dev/AT account (`705157108110`). Terraform records only its ARN and grants the
mail runtimes scoped read access; it must neither own the secret nor read its
value. The secret's JSON object contains the field `sendgrid_key`.

Production runs in account `281669077180` and therefore remains blocked on an
account-local SendGrid secret ARN with the same JSON field. That secret must
use the AWS-managed Secrets Manager key, as the verified dev/AT secret does, or
the production change must also add its exact customer-managed KMS key grant.
The interrupted AT
apply is reconciled in state but not complete. Functional deployment still
requires repairing JWKS egress and applying/verifying schema V025;
operational acceptance has an AWS-confirmed AT alert subscriber. Licensee sync
alerts are submitted to that existing `alert_emails` operations list and must
be provider-accepted before an Oracle kill begins. Local development suppresses
mail, and dev/AT SIFE requests use SendGrid sandbox mode without delivery;
production SIFE recipients remain database-derived.
Because the tracked AT list is deliberately empty, a hard plan precondition
requires its approved ignored override; clean CI cannot delete the confirmed
live subscription by interpreting the base value as intent.
Every mail-producing environment also requires `EMAIL_FROM` to be verified in
SendGrid and a successful outbound-HTTPS runtime probe before its schedules are
enabled.

AT and dev are separate states in one account. The configured AT origin is
`api.uid-dev.utah.gov`, the account's sole API Gateway custom domain;
`insureu.uid-dev.utah.gov` remains the CloudFront viewer hostname. The live
domain observed on 2026-08-19 is externally owned, untagged, `AVAILABLE` and
EDGE, targeting `d3etwdwvbw34ww.cloudfront.net` with the us-east-1 certificate
ending `32f16885-fcda-4c02-8264-ed136d6de499`. It has no REST base-path mapping
or v2 API mapping, and the account has no live REST or HTTP API.

That EDGE domain is not compatible with an HTTP API mapping: AWS requires a
REGIONAL TLS 1.2 domain for that mapping. After the stale dev/AT state records
are separately reconciled, DTS/the domain owner must migrate the same hostname
to REGIONAL using the issued us-west-2 certificate ending
`5b17baae-453a-4418-81e8-788e8336c3de` and cut external DNS over to the new
regional target. The application state must keep the domain, certificate and
DNS read-only; it may create only the root v2 mapping once the compatible
domain and the one HTTP API exist. CloudFront must then add the reviewed API
behaviors before cutover. None of those mutations has been completed. The
external `portal-api.uid-dev.utah.gov` legacy-ALB name remains State-owned DNS
and must not become a second API Gateway custom domain. The default execute-api
endpoint remains disabled.

The shared module validates the active AWS account against `aws_account_id` on
every normal provider operation. Only the explicitly scoped credential-free
`init`/`validate` mode omits that lookup; its default is off. This prevents
production-named resources from being created with dev credentials, but it
cannot detect a real VPC ID copied from the wrong environment.

## Resource ownership boundaries

The API stack consumes State-owned resources by identifier. It must not create,
update, replace, destroy, import, retag or repair the organization VPC/network,
existing databases or secrets, adopted SIFE buckets/objects, external
CloudFront distributions, DNS or certificates. The versioned inventory at
`state-owned-resources.json` and the source/saved-plan checker run
before planning, after planning and immediately before apply. A missing or
unhealthy prerequisite is an owner change, not an application-Terraform repair.
This lifecycle boundary does not prohibit approved runtime SIFE object reads,
writes or deletes through the application's scoped IAM roles.
The Aurora cluster is preserved; the separate UID-owned RDS Proxy state is
rebuildable application infrastructure.

For the shared dev/AT VPC, Lambda placement is pinned to the two inventoried
private-app subnets. The VPC must have exactly one associated IPv4 CIDR,
`10.192.6.0/23`, and no IPv6 CIDR associations. An exact lookup must resolve
that CIDR to AWS `local` in every selected route table; outside-CIDR routes and
their targets remain State-owned. Each selected table must also expose exactly
one existing IPv4 default route, without application Terraform prescribing or
modifying its target. Production fails closed until its owner supplies its own
CIDR, subnet and route-table inventory.

The dev proxy has separate state because it is slow and long-lived. The API
stack consumes its endpoint through `db_proxy_host`; password authentication
uses the named portal secret, so no proxy ARN/IAM-connect input is required.

Existing SIFE upload/download buckets must be adopted through
`existing_bucket_names`. Creating replacements beside them silently strands
files in flight. An adopted uploads bucket also needs the reviewed CORS rule for
every portal browser origin. Other adopted-bucket encryption, lifecycle,
versioning and policy remain with their existing owner.

Managed ZIP and report workers are part of the API stack. Do not keep a second
standalone ZIP or notification resource live after cutover without an explicit
owner and duplicate-delivery analysis.

## Network traps

- Both selected AT subnets use `rtb-00f83bc1b800e256e`. The last live inventory
  showed that its IPv4 default route was not operational, even though the VPC
  also contains existing Internet and NAT gateways. Terraform reads the
  selected Lambda route tables but never prescribes, creates or repairs their
  State-owned targets. It requires the VPC to have only the reviewed IPv4 CIDR
  and no IPv6 association, uses an exact lookup for the
  `10.192.6.0/23 -> local` route, prevents a more-specific route from diverting
  traffic within that CIDR, and requires exactly one existing IPv4 default
  route. Provider 6.58's aggregate route-table data omits the implicit local
  route and does not expose route state, so a successful plan is not a
  reachability proof. The State network owner must select and maintain the
  appropriate existing route, and a runtime JWKS probe from the deployed
  Lambda path remains mandatory.
- The 2026-08-18 live inventory has four organization-owned endpoints: one
  DynamoDB gateway endpoint on this route table, GuardDuty Data and RDS Data
  interface endpoints on the private-db subnets, and a custom PrivateLink
  interface endpoint on the Lambda subnets. There is no Secrets Manager, Logs,
  Lambda, KMS, X-Ray or S3 endpoint. F-15 records the exact IDs, placements and
  security groups. Dev and AT do not adopt the unrelated interface endpoint
  SGs; AWS-service calls require the verified existing egress path. The
  application stack does not remove or replace the DynamoDB endpoint.
- Any required endpoint or endpoint SG-rule change belongs to the State network
  owner; the application plan is required to reject either mutation.
- Snapproxy and Oracle security-group IDs identify the rule targets but do not
  prove connectivity. Keep all mail-producing schedules disabled until a
  runtime probe proves outbound HTTPS to SendGrid and `EMAIL_FROM` is a verified
  SendGrid sender.
- `db_proxy_host` must be a proxy endpoint. A cluster endpoint can pass a smoke
  test and still exhaust Aurora connections under Lambda concurrency.
- The imported dev network and an older ECS state have overlapping ownership of
  core VPC resources. Do not destroy either state until those resources have one
  owner.

## State safety

- Never edit state JSON by hand.
- Never point two configurations at one state key.
- Never put secret values in tfvars; store only Secrets Manager names or ARNs.
  In particular, the SendGrid secret is State-owned: Terraform may pass its ARN
  and grant runtime read access, but must not read the secret value.
- Never destroy a shared environment as a troubleshooting step.
- Recover a corrupt S3 state from bucket version history only after taking a
  copy of the current object. A partially applied stack is normally reconciled
  by the next reviewed plan, not by state surgery.

The previously tracked VPC state and backup have been removed from the current
tree and repository-wide ignore rules prevent recurrence. Their historical
topology remains in git history unless the separately documented destructive
history purge is approved.

## Operational verification after apply

Use `api_gateway_url` only through the approved custom-domain/CloudFront path,
inspect `reserved_concurrency_total`, confirm each SNS subscription, run the
read-only Lambda/API ingress audit, and verify the RDS Proxy target is
`AVAILABLE`. Run database schema checks with an interpreter:

```bash
python3 scripts/verify-schema.py --dsn ...
aws rds describe-db-proxy-targets --db-proxy-name uid-dev-portal-proxy \
  --query "Targets[?Type=='RDS_INSTANCE'].TargetHealth"
```

The migration runbook contains the complete smoke and rollback sequence.
