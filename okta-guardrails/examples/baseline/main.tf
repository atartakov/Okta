# Synthetic baseline: departments drive groups, groups drive app access.
# Every group rule here is something okta-guardrails can preview.

locals {
  sales_departments = ["Sales", "Sales Operations", "Sales Engineering"]
}

resource "okta_group" "salesforce_users" {
  name        = "Salesforce-Users"
  description = "Everyone in a sales department. Managed by Terraform."
}

resource "okta_group" "salesforce_admin" {
  name        = "Salesforce-Admin"
  description = "Salesforce administrators. Managed by Terraform."
}

resource "okta_group" "aws_prod" {
  name        = "AWS-Prod"
  description = "Engineering employees with production AWS access. Managed by Terraform."
}

resource "okta_group_rule" "salesforce_users" {
  name              = "Salesforce users"
  status            = "ACTIVE"
  group_assignments = [okta_group.salesforce_users.id]
  expression_type   = "urn:okta:expression:1.0"
  expression_value  = join(" || ", [for d in local.sales_departments : "user.department == \"${d}\""])
}

resource "okta_group_rule" "salesforce_admin" {
  name                  = "Salesforce admins"
  status                = "ACTIVE"
  group_assignments     = [okta_group.salesforce_admin.id]
  expression_type       = "urn:okta:expression:1.0"
  expression_value      = "user.department == \"Sales Operations\" && user.title == \"Salesforce Administrator\""
  remove_assigned_users = true
}

resource "okta_group_rule" "aws_prod" {
  name                  = "AWS prod engineers"
  status                = "ACTIVE"
  group_assignments     = [okta_group.aws_prod.id]
  expression_type       = "urn:okta:expression:1.0"
  expression_value      = "user.department == \"Engineering\" && user.employeeType == \"Employee\""
  remove_assigned_users = true
}

# A single-page app done the safe way: authorization code + PKCE, exact
# https redirect URIs, no wildcard.
resource "okta_app_oauth" "portal" {
  label                      = "Internal Portal"
  type                       = "browser"
  grant_types                = ["authorization_code", "refresh_token"]
  response_types             = ["code"]
  token_endpoint_auth_method = "none"
  pkce_required              = true
  redirect_uris              = ["https://portal.example.com/login/callback"]
  post_logout_redirect_uris  = ["https://portal.example.com"]
  wildcard_redirect          = "DISABLED"
  refresh_token_rotation     = "ROTATE"
}

resource "okta_app_group_assignment" "portal_sales" {
  app_id   = okta_app_oauth.portal.id
  group_id = okta_group.salesforce_users.id
}
