# Staging bucket for the per-deployment dstack shared disk (docs/notes/dstack.md
# 4.3). `sealed deploy` uploads a gzip raw disk holding the public, measured
# app-compose.json and imports it as an image. Objects are only needed until
# the import finishes. Neither the deployer nor the key broker has access.

resource "google_storage_bucket" "boot" {
  count = var.create_boot_bucket ? 1 : 0

  name     = "${var.project_id}-sealed-boot"
  project  = var.project_id
  location = var.region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.apis]
}
