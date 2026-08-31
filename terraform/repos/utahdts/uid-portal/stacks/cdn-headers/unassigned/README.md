# cdn_headers

The security response headers for the portal UI, as a CloudFront response
headers policy.

The application already ships a Content-Security-Policy as a `<meta>` tag,
generated at build time from the same environment variables it uses
(`ui/src/csp.js`). That one applies today. This module exists for the parts a
meta tag cannot carry:

- **`frame-ancestors`** — specified to be ignored in a meta CSP. Clickjacking
  protection has to arrive as a header. This is the one that matters.
- **Strict-Transport-Security**, **X-Content-Type-Options**, **Referrer-Policy**
  — not CSP at all.

## The distributions

Supplied by UID operations. Production is recorded here; the replacement AT
distribution id is not yet known to this repository:

| Environment | Distribution | Bucket |
|---|---|---|
| `prod` | `E2FZZADHPAMGOH` | `cloudfront-static-site-portal-uid-prod` |
| `at` | unknown -- UID operations must supply it | `cloudfront-static-site-portal-uid-dev` |

The former AT id, `E2L8GSFVL165TN`, returned `NoSuchDistribution` in the
expected account on 2026-08-24. It is historical, not a value to reuse. Do not
create or attach a replacement from this repository: UID operations owns the
distribution, alias, certificate, and DNS cutover.

Note the `at` environment's bucket is named `-dev`. That is what it is called;
it is written down here so nobody "corrects" it to `-at` and points a deploy at
a bucket that does not exist.

Neither distribution is managed by this Terraform. `portal-prod-ui-deploy.yml`
syncs to the bucket and invalidates the distribution by id.

## Planning the application-owned policy

**Nothing here has been planned or applied.** Per the standing instruction on
this branch, Terraform is written and left for a human to run.

This root may create only the standalone response-headers policy. It must never
import or update either State-owned distribution. Before planning:

```bash
cd aws/terraform/repos/utahdts/uid-portal/stacks/cdn-headers/unassigned
terraform init
python3 ../../../scripts/check-state-owned-boundary.py --terraform-root .
PLAN_FILE="headers-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%dT%H%M%SZ)-$$.tfplan"
test ! -e "$PLAN_FILE"
terraform plan -out="$PLAN_FILE" \
  -var 'name=portal-uid-prod-security-headers' \
  -var "content_security_policy=$(...)"   # see below
terraform show -json "$PLAN_FILE" |
  python3 ../../../scripts/check-state-owned-boundary.py \
    --terraform-root . --plan-json -
terraform show -no-color "$PLAN_FILE"
```

After the separately reviewed application plan creates the policy, give its
`response_headers_policy_id` output, the reviewed CSP value and the target
environment to the State CloudFront owner. That owner attaches it through their
controlled distribution workflow. Application operators do not run an import,
console edit or `update-distribution` command.

## Keeping the two policies in step

`content_security_policy` must match what `ui/src/csp.js` generates for that
environment, plus `frame-ancestors`. To see the current value:

```bash
cd ui && npx vite build --mode production
# the policy is the content of the Content-Security-Policy meta tag in dist/index.html
```

Two policies do not negotiate. The browser enforces both, so the effective
policy is their intersection: a directive present in one and absent from the
other silently becomes the stricter of the two, and the symptom is a blocked
request that neither file explains on its own.
