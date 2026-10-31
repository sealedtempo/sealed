# Staging bucket for the shared disks the platform publishes (D-074). The
# platform api builds a deployment's dstack shared disk tarball (public config
# only, no secrets), uploads it here with the deployer's token and imports it
# as the sealed-<name>-shared image, the way `sealed deploy` does with the
# boot bucket. Objects are only needed until the import finishes.
#
# The deployer holds roles/storage.objectAdmin on this bucket and on nothing
# else in Cloud Storage. It has no access to the boot bucket, where the
# customer's own credentials stage the OS images.

resource "google_storage_bucket" "staging" {
  name     = local.staging_bucket
  project  = var.project_id
  location = var.region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_storage_bucket_iam_member" "deployer_staging" {
  bucket = google_storage_bucket.staging.name
  role   = module.iam.deployer_staging_role
  member = module.iam.deployer_member

  depends_on = [google_service_account.deployer]
}
