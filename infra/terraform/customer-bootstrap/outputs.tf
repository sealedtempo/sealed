# `sealed bootstrap` builds the sct_ connection token from these outputs.

output "project_id" {
  value = var.project_id
}

output "project_number" {
  value = data.google_project.this.number
}

output "region" {
  value = var.region
}

output "customer_address" {
  value = local.customer_address
}

output "network" {
  value = google_compute_network.sealed.name
}

output "subnetwork" {
  value = google_compute_subnetwork.sealed.name
}

output "subnetwork_self_link" {
  value = google_compute_subnetwork.sealed.self_link
}

output "vm_tag" {
  description = "Network tag that opens 80 and 443 on a VM."
  value       = local.vm_tag
}

output "deployer_service_account" {
  value = google_service_account.deployer.email
}

output "key_broker_service_account" {
  value = google_service_account.key_broker.email
}

output "key_broker_url" {
  value = google_cloud_run_v2_service.key_broker.uri
}

output "tempo_rpc_url" {
  description = "The Tempo RPC the key broker reads approvals and revocations from (TEMPO_RPC_URL)."
  value       = module.key_broker_env.env["TEMPO_RPC_URL"]
}

output "chain_id" {
  value = var.chain_id
}

output "key_broker_env" {
  description = "The key broker's configuration variables, name for name (nothing secret)."
  value       = module.key_broker_env.env
}

output "key_broker_image" {
  value = local.key_broker_image
}

output "kms_key" {
  value = google_kms_crypto_key.hmac.id
}

output "kms_key_version" {
  value = module.key_broker_env.kms_key_version
}

output "secret_prefix" {
  value = local.secret_prefix
}

output "boot_bucket" {
  description = "Bucket sealed deploy stages shared disk images in (empty when not created)."
  value       = var.create_boot_bucket ? google_storage_bucket.boot[0].name : ""
}

output "debug_log_service_account" {
  description = "Log writer identity for debug VMs (empty unless enable_debug_logging)."
  value       = var.enable_debug_logging ? google_service_account.debug_logs[0].email : ""
}
