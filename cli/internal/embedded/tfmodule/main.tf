# Customer bootstrap (spec 8.4, D-032). Run by the customer with their own
# credentials through `sealed bootstrap` (or `sealed connect gcp`). It creates
# the network, the KMS HMAC key, the key broker on Cloud Run with its own
# service account, and the deployer service account the platform impersonates.
# The platform never holds any credential for this project beyond tokens for
# the deployer, which cannot read secrets, change the key broker, attach a
# service account to a VM or open a shell (P4, spec 8.6).

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  apis = toset([
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
  ])

  customer_address = lower(var.customer_address)

  # Fixed names: the deployer's IAM condition and the IAM checks rely on them.
  network_name      = "sealed-vpc"
  subnetwork_name   = "sealed-subnet"
  vm_tag            = "sealed-vm"
  key_ring_name     = "sealed"
  kms_key_name      = "sealed-kb-hmac"
  key_broker_name   = "sealed-key-broker"
  key_broker_sa_id  = "sealed-key-broker"
  deployer_sa_id    = "sealed-deployer"
  ghcr_remote_repo  = "sealed-ghcr"
  secret_prefix     = "sealed-"
  key_broker_sa_fqn = "${local.key_broker_sa_id}@${var.project_id}.iam.gserviceaccount.com"
  deployer_sa_fqn   = "${local.deployer_sa_id}@${var.project_id}.iam.gserviceaccount.com"

  # Cloud Run pulls only from Artifact Registry and Docker Hub, so ghcr.io
  # images go through a remote repository. The digest is unchanged.
  key_broker_image = (
    startswith(var.key_broker_image, "ghcr.io/")
    ? "${var.region}-docker.pkg.dev/${var.project_id}/${local.ghcr_remote_repo}/${trimprefix(var.key_broker_image, "ghcr.io/")}"
    : var.key_broker_image
  )
}

resource "google_project_service" "apis" {
  for_each = var.enable_apis ? local.apis : toset([])

  project = var.project_id
  service = each.value

  # Never switch APIs off on destroy: other workloads in the project may use them.
  disable_on_destroy = false
  deletion_policy    = "ABANDON"
}

module "iam" {
  source = "./modules/iam"

  project_id                 = var.project_id
  project_number             = data.google_project.this.number
  region                     = var.region
  subnetwork_name            = local.subnetwork_name
  platform_service_account   = var.platform_service_account
  deployer_service_account   = local.deployer_sa_fqn
  key_broker_service_account = local.key_broker_sa_fqn
}
