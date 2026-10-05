# Release and health orchestration

Two Step Functions Standard workflows record release evidence and bounded
health observations. The shared `api_environment` module owns this optional
module. Set its `release_orchestration` object only after the three distinct
execution roles and the published infrastructure-probe version are reviewed.

The checked-in [release.asl.json](release.asl.json) and
[health.asl.json](health.asl.json) are the canonical workflow definitions.
Terraform binds their qualified Lambda and activity ARN placeholders.
The application checkout builds the validator ZIP and ASL templates with
`scripts/build_release_orchestration.py`. The saved-plan workflow preserves
these exact artifacts with the plan and verifies their hashes before apply.
The release role can invoke only the pinned validator; the health role can
invoke only the reviewed published probe version. IAM provisioning remains
with the State review process. No new network resources, database access,
API routes, schedules, or second Terraform-apply path are introduced.

See the application repository's `docs/spec/release-state-machine.md` and
`handoff/release-orchestration/README.md` for evidence, operator, and IAM review
interfaces. The module inherits the environment provider and organizational
tags. AT remains pinned to the approved private subnet pair.
