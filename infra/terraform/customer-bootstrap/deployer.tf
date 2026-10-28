# Deployer service account (spec 8.4, P4). The platform impersonates it to
# create, start, stop and delete sealed-* instances, disks and static IPs in
# the sealed subnet. It holds no other role: it cannot read secrets, change the
# key broker, act as any service account or open a shell.

resource "google_service_account" "deployer" {
  account_id   = local.deployer_sa_id
  project      = var.project_id
  display_name = "Sealed deployer"
  description  = "Impersonated by the Sealed platform to manage sealed-* VMs, disks and static IPs."

  depends_on = [google_project_service.apis]
}

# Authoritative: serviceAccountTokenCreator for the platform service account,
# and nothing else on this identity.
resource "google_service_account_iam_policy" "deployer" {
  service_account_id = google_service_account.deployer.name
  policy_data        = module.iam.deployer_sa_policy_json
}

resource "google_project_iam_custom_role" "deployer_named" {
  project     = var.project_id
  role_id     = "sealedDeployer"
  title       = "Sealed deployer (sealed-* instances, disks, images)"
  description = "Create, start, stop and delete sealed-* instances and disks. Granted only with a name condition."
  permissions = module.iam.deployer_named_permissions
}

resource "google_project_iam_member" "deployer_named" {
  project = var.project_id
  role    = google_project_iam_custom_role.deployer_named.id
  member  = module.iam.deployer_member

  condition {
    title       = "sealed-named-resources"
    description = "Only instances and disks named sealed-* in the bootstrap region, and images named sealed-* in this project."
    expression  = module.iam.deployer_named_condition
  }

  depends_on = [google_service_account.deployer]
}

resource "google_project_iam_custom_role" "deployer_project" {
  project     = var.project_id
  role_id     = "sealedDeployerAddresses"
  title       = "Sealed deployer (static IPs, operations)"
  description = "Static IPs and operation polling, which IAM Conditions cannot scope by name."
  permissions = module.iam.deployer_project_permissions
}

resource "google_project_iam_member" "deployer_project" {
  project = var.project_id
  role    = google_project_iam_custom_role.deployer_project.id
  member  = module.iam.deployer_member

  depends_on = [google_service_account.deployer]
}

resource "google_project_iam_custom_role" "subnet_user" {
  project     = var.project_id
  role_id     = "sealedSubnetUser"
  title       = "Sealed subnet user"
  description = "Attach VMs and external IPs to the sealed subnet. Granted on that subnet only."
  permissions = module.iam.deployer_subnet_permissions
}

resource "google_compute_subnetwork_iam_member" "deployer" {
  project    = var.project_id
  region     = var.region
  subnetwork = google_compute_subnetwork.sealed.name
  role       = google_project_iam_custom_role.subnet_user.id
  member     = module.iam.deployer_member

  depends_on = [google_service_account.deployer]
}
