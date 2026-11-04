# AT function images

This root owns the ECR repository `uid-portal-at-functions` for manifest
`package: image` functions (D-080). Today that is only `translate_text`, the
MADLAD-400 translation route.

It has its own state because the repository must exist and hold a pushed image
before `envs/at` can create an image function. `envs/at` reads only the
digest-pinned image URI through `function_image_uris`.

- Images are immutable and scanned on push, with AWS-managed AES-256
  encryption. This root creates no KMS key and no network resource.
- The repository policy lets only the Lambda service pull, and only for the
  exact image functions derived from `services/api/routes/routes.yaml`.
- The lifecycle policy keeps the 20 most recent images, so published Lambda
  versions keep their rollback targets.
- `prevent_destroy` protects the repository.

Plan, review and apply it with the commands in
[the translation image README](../../../../../../../../services/api/images/translate/README.md#1-create-the-ecr-repository-review-then-apply).
