# IAM documents of the customer bootstrap (spec 8.4, 8.6, P4).
#
# This module has no providers and no resources: it only computes the custom
# role permission lists, the IAM condition expressions and the service account
# policies. The root module applies them, and scripts/iam-checks renders this
# module on its own (terraform plan, no credentials) to test the documents.

terraform {
  required_version = ">= 1.7.0"
}

variable "project_id" {
  type        = string
  description = "Customer project id."
}

variable "project_number" {
  type        = string
  description = "Customer project number (Secret Manager IAM conditions use the number, not the id)."
}

variable "region" {
  type        = string
  description = "Region of the subnet, the static IPs and the key broker."
}

variable "subnetwork_name" {
  type        = string
  description = "Name of the sealed subnet."
}

variable "platform_service_account" {
  type        = string
  description = "Email of the platform service account that may impersonate the deployer."
}

variable "deployer_service_account" {
  type        = string
  description = "Email of the deployer service account (used in the rendered member lists)."
}

variable "key_broker_service_account" {
  type        = string
  description = "Email of the key broker service account."
}

variable "debug_logs_service_account" {
  type        = string
  description = "Email of the optional debug VM log writer service account."
  default     = ""
}

locals {
  # Every resource the deployer may touch is named with this prefix.
  prefix = "sealed-"

  # Granted on the project with the name condition below: only instances and
  # zonal disks named sealed-* in the region's zones, and images named
  # sealed-* in this project, match. No permission here can attach a service
  # account (compute.instances.setServiceAccount and iam.serviceAccounts.actAs
  # are absent), open OS Login or IAP, or read the serial port.
  deployer_named_permissions = sort([
    "compute.disks.create",
    "compute.disks.delete",
    "compute.disks.get",
    "compute.disks.setLabels",
    "compute.disks.use",
    "compute.images.useReadOnly",
    "compute.instances.create",
    "compute.instances.delete",
    "compute.instances.get",
    "compute.instances.setLabels",
    "compute.instances.setMetadata",
    "compute.instances.setTags",
    "compute.instances.start",
    "compute.instances.stop",
  ])

  # IAM Conditions can scope Compute Engine instances, disks and images by
  # name. A clause on an attribute a resource type does not provide never
  # grants, so the condition grants nothing outside these three types.
  deployer_named_condition = join(" || ", [
    "(resource.type == \"compute.googleapis.com/Instance\" && resource.name.startsWith(\"projects/${var.project_id}/zones/${var.region}-\") && resource.name.extract(\"/instances/{name}\").startsWith(\"${local.prefix}\"))",
    "(resource.type == \"compute.googleapis.com/Disk\" && resource.name.startsWith(\"projects/${var.project_id}/zones/${var.region}-\") && resource.name.extract(\"/disks/{name}\").startsWith(\"${local.prefix}\"))",
    "(resource.type == \"compute.googleapis.com/Image\" && resource.name.startsWith(\"projects/${var.project_id}/global/images/${local.prefix}\"))",
  ])

  # Static IPs and operations do not support name conditions, so these are
  # granted on the project without one. They cannot read data, attach
  # identities or open a shell (documented in the build note and README).
  deployer_project_permissions = sort([
    "compute.addresses.create",
    "compute.addresses.delete",
    "compute.addresses.get",
    "compute.addresses.use",
    "compute.regionOperations.get",
    "compute.zoneOperations.get",
  ])

  # Granted on the sealed subnet only (resource-level IAM), so VMs can only be
  # created in that subnet.
  deployer_subnet_permissions = sort([
    "compute.subnetworks.use",
    "compute.subnetworks.useExternalIp",
  ])

  # Authoritative policy of the deployer service account: the platform
  # service account may mint tokens for it, and nobody else holds any role on
  # it (no actAs, no key admin).
  deployer_sa_policy = {
    bindings = [
      {
        role    = "roles/iam.serviceAccountTokenCreator"
        members = ["serviceAccount:${var.platform_service_account}"]
      },
    ]
  }

  # Authoritative, empty policy of the key broker service account: no one can
  # act as it or mint tokens for it through the service account itself.
  key_broker_sa_policy = {
    bindings = []
  }

  # The key broker reads only secrets named sealed-* (Secret Manager resource
  # names use the project number).
  key_broker_secret_role = "roles/secretmanager.secretAccessor"
  key_broker_secret_condition = join(" && ", [
    "(resource.type == \"secretmanager.googleapis.com/Secret\" || resource.type == \"secretmanager.googleapis.com/SecretVersion\")",
    "resource.name.startsWith(\"projects/${var.project_number}/secrets/${local.prefix}\")",
  ])

  # The key broker writes its release decisions to Cloud Logging.
  key_broker_logging_role = "roles/logging.logWriter"

  # Debug VMs only (spec 5.8): the log writer identity may write log entries
  # and nothing else, and nobody holds a role on it through its own policy
  # (the deployer in particular, so the platform can never attach it). The VM
  # gets only this scope.
  debug_logs_role      = "roles/logging.logWriter"
  debug_logs_sa_policy = { bindings = [] }
  debug_vm_scopes      = ["https://www.googleapis.com/auth/logging.write"]

  # The key broker uses the bootstrap's KMS HMAC key and nothing else in KMS.
  key_broker_kms_role = "roles/cloudkms.signer"
  key_broker_kms_policy = {
    bindings = [
      {
        role    = local.key_broker_kms_role
        members = ["serviceAccount:${var.key_broker_service_account}"]
      },
    ]
  }
}

output "deployer_named_permissions" {
  value = local.deployer_named_permissions
}

output "deployer_named_condition" {
  value = local.deployer_named_condition
}

output "deployer_project_permissions" {
  value = local.deployer_project_permissions
}

output "deployer_subnet_permissions" {
  value = local.deployer_subnet_permissions
}

output "deployer_sa_policy" {
  value = local.deployer_sa_policy
}

output "deployer_sa_policy_json" {
  value = jsonencode(local.deployer_sa_policy)
}

output "key_broker_sa_policy_json" {
  value = jsonencode(local.key_broker_sa_policy)
}

output "key_broker_secret_role" {
  value = local.key_broker_secret_role
}

output "key_broker_secret_condition" {
  value = local.key_broker_secret_condition
}

output "key_broker_kms_policy" {
  value = local.key_broker_kms_policy
}

output "key_broker_kms_policy_json" {
  value = jsonencode(local.key_broker_kms_policy)
}

output "deployer_member" {
  value = "serviceAccount:${var.deployer_service_account}"
}

output "key_broker_member" {
  value = "serviceAccount:${var.key_broker_service_account}"
}

output "key_broker_logging_role" {
  value = local.key_broker_logging_role
}

output "debug_logs_role" {
  value = local.debug_logs_role
}

output "debug_logs_sa_policy_json" {
  value = jsonencode(local.debug_logs_sa_policy)
}

output "debug_logs_member" {
  value = "serviceAccount:${var.debug_logs_service_account}"
}

output "debug_vm_scopes" {
  value = local.debug_vm_scopes
}
