# Historical network inventory -- not deployable

This directory records a past read of the State of Utah organization-owned dev
VPC. It is not a Terraform root:

- topology and import blocks use the `.tf.inventory` suffix, which Terraform
  does not load;
- the historical provider lock also has an `.inventory` suffix;
- the only retained `.tf` file has no AWS provider and contains an
  unconditional plan-time guard;
- the former generator exits without querying AWS or writing files.

Do not rename the inventory files, import their resources, or run plan/apply
here. Use read-only AWS inventory commands and give any missing or unhealthy
network path to the State network owner.
