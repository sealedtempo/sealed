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

# The broker writes every release decision to Cloud Logging and withholds an
# allowed release when that write fails, so it needs the log writer role
# (review F5).
resource "google_project_iam_member" "key_broker_logging" {
  project = var.project_id
  role    = module.iam.key_broker_logging_role
  member  = module.iam.key_broker_member

  depends_on = [google_service_account.key_broker]
}

# The environment the broker reads, name for name (modules/key-broker-env).
module "key_broker_env" {
  source = "./modules/key-broker-env"

  customer_address    = local.customer_address
  tempo_rpc_url       = var.tempo_rpc_url
  chain_id            = var.chain_id
  platform_registry   = var.platform_registry
  app_registry        = var.app_registry
  deployment_registry = var.deployment_registry
  release_asset_base  = var.release_asset_base
  project_id          = var.project_id
  region              = var.region
  kms_crypto_key      = google_kms_crypto_key.hmac.id
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
    # Above the broker's 90 s release deadline (which covers the 60 s bundle
    # fetches of a cold start), so Cloud Run never cuts a release short.
    timeout = "120s"

    scaling {
      min_instance_count = 0
      max_instance_count = var.key_broker_max_instances
    }

    containers {
      image = local.key_broker_image

      ports {
        container_port = module.key_broker_env.container_port
      }

      resources {
        limits = {
          cpu    = "1"
          memory = module.key_broker_env.memory_limit
        }
      }

      dynamic "env" {
        for_each = merge(module.key_broker_env.env, module.key_broker_env.runtime_env)
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [
    google_project_iam_member.key_broker_secrets,
    google_project_iam_member.key_broker_logging,
    google_kms_crypto_key_iam_policy.hmac,
    google_artifact_registry_repository.ghcr,
  ]
}
