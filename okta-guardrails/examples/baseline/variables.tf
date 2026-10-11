variable "okta_org_name" {
  description = "Okta org subdomain, e.g. dev-123456"
  type        = string
}

variable "okta_base_url" {
  description = "okta.com, oktapreview.com or okta-emea.com"
  type        = string
  default     = "okta.com"
}

variable "okta_client_id" {
  description = "Client ID of the Terraform service app"
  type        = string
}

variable "okta_private_key_id" {
  description = "kid of the service app's signing key"
  type        = string
}

variable "okta_private_key" {
  description = "PEM private key for private_key_jwt (pass via TF_VAR_okta_private_key, never commit it)"
  type        = string
  sensitive   = true
}
