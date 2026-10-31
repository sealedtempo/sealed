variable "project_id" {
  type        = string
  description = "The customer's Google Cloud project id."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project id (6 to 30 lowercase letters, digits and hyphens)."
  }
}

variable "region" {
  type        = string
  description = "Region for the subnet, static IPs, the KMS key ring and the key broker. Pick one with C3 TDX zones."
  default     = "us-central1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must look like us-central1."
  }
}

variable "customer_address" {
  type        = string
  description = "The customer's Tempo wallet address. The key broker releases secrets only for stacks this address approved."

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.customer_address))
    error_message = "customer_address must be a 0x-prefixed 20-byte hex address."
  }
}

variable "platform_service_account" {
  type        = string
  description = "Email of the platform service account. It is the only identity that may impersonate the deployer."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.platform_service_account))
    error_message = "platform_service_account must be a user-managed service account email (name@project.iam.gserviceaccount.com)."
  }
}

variable "key_broker_image" {
  type        = string
  description = "Key broker container image, pinned by digest. ghcr.io images are pulled through an Artifact Registry remote repository, because Cloud Run cannot pull from ghcr.io directly."

  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$", var.key_broker_image))
    error_message = "key_broker_image must be pinned by digest (registry/path@sha256:<64 hex>)."
  }

  validation {
    condition     = !endswith(var.key_broker_image, "@sha256:0000000000000000000000000000000000000000000000000000000000000000")
    error_message = "key_broker_image still has the all-zero placeholder digest; pass the digest of a published key broker image."
  }
}

variable "tempo_rpc_url" {
  type        = string
  description = "Tempo JSON-RPC URL the key broker reads approvals from. Chosen by the customer, never by the platform."
  default     = "https://rpc.tempo.xyz"
  # The customer's RPC can embed an API key in its path, query or userinfo, so
  # Terraform must redact it from the plan, the apply and the outputs (cli-1).
  sensitive = true

  validation {
    condition     = can(regex("^https://[^/@\\s]+(/[^\\s]*)?$", var.tempo_rpc_url))
    error_message = "tempo_rpc_url must be an https URL without credentials."
  }
}

variable "chain_id" {
  type        = number
  description = "Tempo chain id the key broker expects from tempo_rpc_url."
  default     = 4217

  validation {
    condition     = var.chain_id > 0 && floor(var.chain_id) == var.chain_id
    error_message = "chain_id must be a positive integer."
  }
}

variable "platform_registry" {
  type        = string
  description = "PlatformRegistry address."

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.platform_registry))
    error_message = "platform_registry must be an address."
  }
}

variable "app_registry" {
  type        = string
  description = "AppRegistry address."

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.app_registry))
    error_message = "app_registry must be an address."
  }
}

variable "deployment_registry" {
  type        = string
  description = "DeploymentRegistry address."

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.deployment_registry))
    error_message = "deployment_registry must be an address."
  }
}

variable "release_asset_base" {
  type        = string
  description = "Base URL of the catalog's release assets (D-046); the key broker fetches bundles below it."
  default     = "https://github.com/sealedtempo/sealed/releases/download"

  validation {
    condition     = can(regex("^https://[^/@\\s]+(/[^\\s]*)?[^/]$", var.release_asset_base))
    error_message = "release_asset_base must be an https URL without a trailing slash."
  }
}

variable "fee_splitter" {
  type        = string
  description = "FeeSplitter address the key broker requires in every config (SEALED_FEE_SPLITTER). Empty: mainnet's. sealed bootstrap sets it from its deployments file when the registries are not mainnet's."
  default     = ""

  validation {
    condition     = var.fee_splitter == "" || can(regex("^0x[0-9a-fA-F]{40}$", var.fee_splitter))
    error_message = "fee_splitter must be empty or an address."
  }
}

variable "fee_token" {
  type        = string
  description = "Fee token the key broker requires in every config (SEALED_FEE_TOKEN). Empty: mainnet's USDC.e. sealed bootstrap sets it from its deployments file when it is not mainnet's."
  default     = ""

  validation {
    condition     = var.fee_token == "" || can(regex("^0x[0-9a-fA-F]{40}$", var.fee_token))
    error_message = "fee_token must be empty or an address."
  }
}

variable "key_broker_allowed_images" {
  type        = list(string)
  description = "The customer's own allowlist of imageIds the key broker releases to, on top of PlatformRegistry approval (SEALED_ALLOWED_IMAGES). Empty: every approved image."
  default     = []

  validation {
    condition     = alltrue([for i in var.key_broker_allowed_images : can(regex("^0x[0-9a-fA-F]{64}$", i))])
    error_message = "key_broker_allowed_images must be 0x-prefixed 32-byte imageIds."
  }
}

variable "subnet_cidr" {
  type        = string
  description = "IPv4 range of the sealed subnet."
  default     = "10.42.0.0/24"

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0)) && can(regex("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)", var.subnet_cidr))
    error_message = "subnet_cidr must be an RFC 1918 IPv4 range."
  }
}

variable "kms_protection_level" {
  type        = string
  description = "Protection level of the HMAC key: SOFTWARE or HSM."
  default     = "SOFTWARE"

  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.kms_protection_level)
    error_message = "kms_protection_level must be SOFTWARE or HSM."
  }
}

variable "key_broker_max_instances" {
  type        = number
  description = "Maximum Cloud Run instances of the key broker. Nonces are single use, so keep 1 unless the broker shares its nonce store."
  default     = 1

  validation {
    condition     = var.key_broker_max_instances >= 1 && var.key_broker_max_instances <= 10
    error_message = "key_broker_max_instances must be between 1 and 10."
  }
}

variable "key_broker_deletion_protection" {
  type        = bool
  description = "Refuse to delete the key broker service on destroy."
  default     = true
}

variable "enable_debug_logging" {
  type        = bool
  description = "Create sealed-debug-logs, a service account that may only write logs, for debug VMs (spec 5.8). Production VMs never get it."
  default     = false
}

variable "create_boot_bucket" {
  type        = bool
  description = "Create <project>-sealed-boot, where sealed deploy stages the dstack shared disk image."
  default     = true
}

variable "enable_apis" {
  type        = bool
  description = "Enable the Google Cloud APIs the bootstrap needs. Turn off when they are managed elsewhere."
  default     = true
}

variable "labels" {
  type        = map(string)
  description = "Extra labels on every labeled resource."
  default     = {}
}
