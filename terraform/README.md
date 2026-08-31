# Terraform repository namespaces

Infrastructure from each consuming service repository lives below
`repos/<owner>/<repo>/`. The two path components come from that repository's
verified Git origin, so projects with similar names do not collide.

Every repository root must contain `repository.toml` with the source slug and
origin URL. Keep environment roots, independently stateful stacks, local
modules, helper scripts, and historical inventory inside that namespace.

Do not place service-owned Terraform directly in this directory. Cross-service
modules belong in a separate, explicitly reviewed shared-module namespace; do
not promote a service module merely because a second repository might use it.
