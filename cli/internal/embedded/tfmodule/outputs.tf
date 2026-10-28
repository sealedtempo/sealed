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

output "key_broker_image" {
  value = local.key_broker_image
}

output "kms_key" {
  value = google_kms_crypto_key.hmac.id
}

output "kms_key_version" {
  value = "${google_kms_crypto_key.hmac.id}/cryptoKeyVersions/1"
}

output "secret_prefix" {
  value = local.secret_prefix
}
