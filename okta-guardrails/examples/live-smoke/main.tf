# Live smoke test: PLAN ONLY against a developer tenant. Never apply this.
#
#   export OKTA_API_TOKEN=...   # read-only admin token is enough to plan
#   terraform init && terraform plan -var org_name=dev-123456 \
#     -var existing_group_id=00g... -var existing_group_name=... -out plan.bin
#   terraform show -json plan.bin > plan.json
#   okta-guardrails export-population --out population.json
#   okta-guardrails check --plan plan.json --population population.json
#
# It imports one real group (import blocks only touch state at apply), adds a
# group rule so the access preview runs on real users, and adds one
# deliberately unsafe OAuth app so the checks have something real to block.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 7.0"
    }
  }
}

variable "org_name" {
  type = string
}

variable "base_url" {
  type    = string
  default = "okta.com"
}

variable "existing_group_id" {
  description = "An existing test group to import and modify in the plan"
  type        = string
}

variable "existing_group_name" {
  type = string
}

provider "okta" {
  org_name = var.org_name
  base_url = var.base_url
  # api_token comes from OKTA_API_TOKEN
}

import {
  to = okta_group.existing
  id = var.existing_group_id
}

resource "okta_group" "existing" {
  name        = var.existing_group_name
  description = "Managed by Terraform (guardrails smoke test)"
}

resource "okta_group_rule" "example_logins" {
  name              = "example.com logins"
  status            = "ACTIVE"
  group_assignments = [okta_group.existing.id]
  expression_type   = "urn:okta:expression:1.0"
  expression_value  = "String.endsWith(user.login, \"@example.com\")"
}

resource "okta_app_oauth" "risky" {
  label             = "guardrails-smoke-risky"
  type              = "web"
  grant_types       = ["authorization_code", "implicit"]
  response_types    = ["code", "token"]
  redirect_uris     = ["https://*.example.com/callback"]
  wildcard_redirect = "SUBDOMAIN"
}
