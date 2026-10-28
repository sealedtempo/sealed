# The key broker derives each deployment's disk key and signer seed with this
# HMAC-SHA256 key (D-011, INTERFACES section 9). The root key never leaves KMS.
# Losing or rotating it makes every data disk unreadable, so it can neither be
# destroyed by Terraform nor rotated: the broker pins version 1.

resource "google_kms_key_ring" "sealed" {
  name     = local.key_ring_name
  project  = var.project_id
  location = var.region

  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "hmac" {
  name     = local.kms_key_name
  key_ring = google_kms_key_ring.sealed.id
  purpose  = "MAC"

  version_template {
    algorithm        = "HMAC_SHA256"
    protection_level = var.kms_protection_level
  }

  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

# Authoritative: only the key broker may use the key.
resource "google_kms_crypto_key_iam_policy" "hmac" {
  crypto_key_id = google_kms_crypto_key.hmac.id
  policy_data   = module.iam.key_broker_kms_policy_json

  depends_on = [google_service_account.key_broker]
}
