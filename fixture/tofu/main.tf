# The fixture's one OpenTofu module: enough for fmt, validate, tflint and a
# config scan to have something to hold, and no provider, so `init` needs
# no network and the job runs under an egress block with nothing to allow.
terraform {
  required_version = ">= 1.6"
}

variable "name" {
  description = "What the fixture is called."
  type        = string
  default     = "fixture"
}

variable "replicas" {
  description = "How many of it there would be."
  type        = number
  default     = 1

  validation {
    condition     = var.replicas >= 1
    error_message = "replicas must be at least 1."
  }
}

locals {
  label = "${var.name}-${var.replicas}"
}

output "label" {
  description = "The name and the count, joined."
  value       = local.label
}
