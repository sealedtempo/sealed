# Key broker (spec 5.7) on Cloud Run with its own service account. It may read
# only Secret Manager secrets named sealed-* and use the HMAC key. The
# deployer has no access to the service, its identity, its secrets or its key.

resource "google_service_account" "key_broker" {
  account_id   = local.key_broker_sa_id
  project      = var.project_id
  display_name = "Sealed key broker"
  description  = "Runs the Sealed key broker. Reads sealed-* secrets and uses the sealed KMS HMAC key."

  depends_on = [google_project_service.apis]
}

# Authoritative and empty: nobody can act as the broker's identity through the
# service account itself.
resource "google_service_account_iam_policy" "key_broker" {
  service_account_id = google_service_account.key_broker.name
  policy_data        = module.iam.key_broker_sa_policy_json
}

resource "google_project_iam_member" "key_broker_secrets" {
  project = var.project_id
  role    = module.iam.key_broker_secret_role
  member  = module.iam.key_broker_member

  condition {
    title       = "sealed-secrets-only"
    description = "Only Secret Manager secrets named sealed-*."
    expression  = module.iam.key_broker_secret_condition
  }

  depends_on = [google_service_account.key_broker]
}

# The decision log (key-broker/gcp, Cloud Logging entries.write).
resource "google_project_iam_member" "key_broker_logs" {
  project = var.project_id
  role    = module.iam.key_broker_log_role
  member  = module.iam.key_broker_member

  depends_on = [google_service_account.key_broker]
}

# Pull-through cache for ghcr.io (Cloud Run cannot pull from it directly).
# Images keep their digests, which Cloud Run pins.
resource "google_artifact_registry_repository" "ghcr" {
  repository_id = local.ghcr_remote_repo
  project       = var.project_id
  location      = var.region
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  description   = "Pull-through cache of ghcr.io for the key broker image."

  remote_repository_config {
    description = "ghcr.io"

    docker_repository {
      custom_repository {
        uri = "https://ghcr.io"
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service" "key_broker" {
  name     = local.key_broker_name
  project  = var.project_id
  location = var.region

  description = "Sealed key broker: releases secrets only to attested stacks the customer approved on Tempo."

  # The VMs have no identity, so callers are not authenticated by IAM. Every
  # release is gated by the TDX quote and the onchain approval instead.
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = true
  ssh_enabled          = false
  deletion_protection  = var.key_broker_deletion_protection

  template {
    service_account                  = google_service_account.key_broker.email
    max_instance_request_concurrency = 40
    timeout                          = "60s"

    scaling {
      min_instance_count = 0
      max_instance_count = var.key_broker_max_instances
    }

    containers {
      image = local.key_broker_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      env {
        name  = "SEALED_CUSTOMER_ADDRESS"
        value = local.customer_address
      }
      env {
        name  = "SEALED_GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "SEALED_GCP_PROJECT_NUMBER"
        value = data.google_project.this.number
      }
      env {
        name  = "SEALED_SECRET_PREFIX"
        value = local.secret_prefix
      }
      env {
        name  = "SEALED_KMS_KEY_VERSION"
        value = "${google_kms_crypto_key.hmac.id}/cryptoKeyVersions/1"
      }
      env {
        name  = "TEMPO_RPC_URL"
        value = var.tempo_rpc_url
      }
      env {
        name  = "TEMPO_CHAIN_ID"
        value = tostring(var.chain_id)
      }
      env {
        name  = "SEALED_PLATFORM_REGISTRY"
        value = lower(var.platform_registry)
      }
      env {
        name  = "SEALED_APP_REGISTRY"
        value = lower(var.app_registry)
      }
      env {
        name  = "SEALED_DEPLOYMENT_REGISTRY"
        value = lower(var.deployment_registry)
      }
      env {
        name  = "SEALED_RELEASE_ASSET_BASE"
        value = var.release_asset_base
      }
    }
  }

  depends_on = [
    google_project_iam_member.key_broker_secrets,
    google_project_iam_member.key_broker_logs,
    google_kms_crypto_key_iam_policy.hmac,
    google_artifact_registry_repository.ghcr,
  ]
}
