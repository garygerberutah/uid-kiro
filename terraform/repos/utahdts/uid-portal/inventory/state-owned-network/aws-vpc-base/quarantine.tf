terraform {
  required_version = ">= 1.10, < 2.0"
}

# This is the only executable Terraform file retained in the historical
# inventory directory. The mutually exclusive validation and precondition make
# every plan fail, even if a caller tries to override inventory_only. The actual
# topology and old import blocks have non-.tf suffixes, so Terraform cannot load
# them as resources.
variable "inventory_only" {
  description = "Permanent marker: this organization-owned network inventory is never deployable."
  type        = bool
  default     = true

  validation {
    condition     = var.inventory_only
    error_message = "inventory_only is permanent; this repository cannot manage the State network."
  }
}

resource "terraform_data" "organization_owned_network_inventory_only" {
  lifecycle {
    precondition {
      condition     = !var.inventory_only
      error_message = "BLOCKED: organization-owned network inventory is read-only; never plan or apply this root."
    }
  }
}
