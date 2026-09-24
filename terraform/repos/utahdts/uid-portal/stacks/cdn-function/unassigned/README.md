# cdn_function

The SPA rewrite for the portal UI, as a CloudFront function.

The portal is one bundle. Every route it has -- `/sife`, `/sife/users/all`,
`/sife/divisions` -- is resolved by React in the browser and is not an object
in the bucket, so S3 answers 404 for all of them. A deep link, a refresh and a
bookmark fail while the same page reached by clicking works. This function
rewrites those requests to `/index.html`, which does exist, and the router
takes it from there.

`spa-rewrite.js` is the source. It is read by `main.tf` with `file()` and
executed directly by `ui/test/cloudfront/spaRewrite.test.js`, so what is
reviewed, what is deployed and what is tested are one file.

## This stack creates; it does not attach

The distributions are not managed by this repository. Applying this produces a
function and nothing else, and a CloudFront function is inert until a cache
behaviour references it. Give `function_arn` to the CloudFront owner, who
attaches it through the distribution's own workflow.

Never import or update a distribution from here. See D-018, and the same
arrangement in the neighbouring `cdn-headers` stack.

## Attach it to the default cache behaviour only

The portal's API is served from the same hostname under `/portal/*` and
`/licensee/*`. Those paths are extensionless, so this function would rewrite
every one of them to `/index.html` -- turning each API call into the HTML of
the home page, returned with status 200. They belong to cache behaviours
pointing at the API origin, which the default behaviour's function never sees.

A test pins that this is what the function would do, so the constraint is
recorded rather than remembered.

## The distributions

Read from the account on 2026-09-22, not supplied:

| Distribution | Role | Aliases |
|---|---|---|
| `E3VBU8PSNYBN8D` | the live AT distribution | `insureu.uid-dev.utah.gov` |
| `E27M1PAVF6U3YD` | the multi-tenant replacement, deployed | none yet; tenant-only |
| `E2FZZADHPAMGOH` | production | recorded in `state-owned-resources.json` |

`uid-portal-at-spa-rewrite` already exists on `E3VBU8PSNYBN8D`, created outside
Terraform. This stack deliberately creates a second, identically behaving
function for the multi-tenant distribution rather than adopting that one: the
live path stays untouched until DNS moves, and stays available as a rollback
after it does. `var.name` refuses the existing name.

## Before the multi-tenant distribution can serve the portal

As read on 2026-09-22, `E27M1PAVF6U3YD` carries one S3 origin and nothing
else. It is missing every part of the live distribution that is not the bucket:

| Setting | Live distribution | Multi-tenant distribution |
|---|---|---|
| Origins | `portal-s3`, `portal-api` (`api.uid-dev.utah.gov`) | S3 only |
| Behaviour `/portal/*` | `portal-api` | absent |
| Behaviour `/licensee/*` | `portal-api` | absent |
| Default behaviour function | `uid-portal-at-spa-rewrite` | none |
| `DefaultRootObject` | `index.html` | empty |

Cutting DNS to it in that state loads the UI and fails every API call. Those
four settings belong to the distribution owner, not to this stack.
