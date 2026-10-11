terraform {
  required_version = ">= 1.6.0"

  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 7.0"
    }
  }
}

# OAuth 2.0 service app with private_key_jwt, not an SSWS API token.
# Grant it only the okta.* scopes below, plus a custom admin role scoped to
# the groups and apps this config owns. Break-glass admins stay out of here.
provider "okta" {
  org_name       = var.okta_org_name
  base_url       = var.okta_base_url
  client_id      = var.okta_client_id
  private_key_id = var.okta_private_key_id
  private_key    = var.okta_private_key
  scopes = [
    "okta.groups.manage",
    "okta.apps.manage",
    "okta.users.read",
  ]
}
