# Environment contract of the key broker container (spec 5.7, INTERFACES
# section 9, review-ws-key-broker F5).
#
# This module has no providers and no resources. It turns the bootstrap's
# inputs into exactly the environment variables key-broker/cmd/key-broker
# reads (its README's configuration table), so the root module and the
# contract test in cli/internal/bootstrap render the same map. A variable the
# broker ignored would silently replace the customer's choice (their RPC, their
# chain, their key) with the broker's mainnet default, so the contract test
# runs the broker's own config parser on this map and fails on any variable it
# does not read and on any choice that does not reach its effective config.
# key_broker.tf lists the names literally (the broker's own test parses it).

terraform {
  required_version = ">= 1.7.0"
}

variable "customer_address" {
  type        = string
  description = "The customer's Tempo address."
}

variable "tempo_rpc_url" {
  type        = string
  description = "Tempo JSON-RPC URL chosen by the customer."
}

variable "chain_id" {
  type        = number
  description = "Tempo chain id."
}

variable "platform_registry" {
  type        = string
  description = "PlatformRegistry address."
}

variable "app_registry" {
  type        = string
  description = "AppRegistry address."
}

variable "deployment_registry" {
  type        = string
  description = "DeploymentRegistry address."
}

variable "release_asset_base" {
  type        = string
  description = "Base URL of the catalog's release assets (D-046)."
}

variable "project_id" {
  type        = string
  description = "Customer project id (Secret Manager and Cloud Logging)."
}

variable "project_number" {
  type        = string
  description = "Customer project number (recorded by the broker)."
}

variable "kms_crypto_key" {
  type        = string
  description = "The HMAC key: projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>."
}

locals {
  # Cloud Run sends requests to this port and sets PORT to it.
  container_port = 8080

  # The broker pins version 1 of the HMAC key: a new primary version would
  # change every disk key and signer seed (D-011, D-058).
  kms_key_version = 1

  # Name for name, what cmd/key-broker reads (flag defaults are the mainnet
  # values, so every customer choice must arrive here or it is lost). The
  # broker refuses any other SEALED_* or TEMPO_* variable. It takes the region
  # of its decision log resource from the metadata server.
  env = {
    SEALED_CUSTOMER_ADDRESS    = lower(var.customer_address)
    TEMPO_RPC_URL              = var.tempo_rpc_url
    TEMPO_CHAIN_ID             = tostring(var.chain_id)
    SEALED_PLATFORM_REGISTRY   = lower(var.platform_registry)
    SEALED_APP_REGISTRY        = lower(var.app_registry)
    SEALED_DEPLOYMENT_REGISTRY = lower(var.deployment_registry)
    SEALED_RELEASE_ASSET_BASE  = var.release_asset_base
    SEALED_GCP_PROJECT         = var.project_id
    SEALED_GCP_PROJECT_NUMBER  = var.project_number
    SEALED_SECRET_PREFIX       = "sealed-"
    SEALED_KMS_KEY_VERSION     = "${var.kms_crypto_key}/cryptoKeyVersions/${local.kms_key_version}"
  }

  # Go runtime settings, not broker configuration: a soft heap limit below the
  # container memory limit, so the garbage collector works harder before the
  # instance is killed (review F1).
  memory_limit = "1Gi"
  runtime_env = {
    GOMEMLIMIT = "768MiB"
  }
}

output "env" {
  description = "Broker configuration variables, by name."
  value       = local.env
}

output "runtime_env" {
  description = "Go runtime variables of the broker container."
  value       = local.runtime_env
}

output "container_port" {
  value = local.container_port
}

output "memory_limit" {
  value = local.memory_limit
}

output "kms_key_version" {
  value = "${var.kms_crypto_key}/cryptoKeyVersions/${local.kms_key_version}"
}
