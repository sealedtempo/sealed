# Optional log writer identity for debug VMs (spec 5.8, the one exception to
# "no service account" in spec 5.9).
#
# The debug OS image (sealed-dstack-os-debug) ships sealed-logship, which sends
# container logs to Cloud Logging in this project. It needs a token from the
# metadata server, so a debug VM gets this service account with only the
# logging.write scope. Production VMs never get it: `sealed deploy` attaches it
# only when the stack file says image.debug and PlatformRegistry marks the image
# as debug, and the key broker never releases anything to a debug image.
#
# It may only write log entries. Its own IAM policy is authoritative and empty,
# and the deployer gets no role on it, so the platform can never attach it
# (spec 8.6): debug VMs are created by the customer with their own credentials.

resource "google_service_account" "debug_logs" {
  count = var.enable_debug_logging ? 1 : 0

  account_id   = local.debug_logs_sa_id
  project      = var.project_id
  display_name = "Sealed debug VM log writer"
  description  = "Attached only to Sealed debug VMs. Writes container logs to Cloud Logging and nothing else."

  depends_on = [google_project_service.apis]
}

resource "google_service_account_iam_policy" "debug_logs" {
  count = var.enable_debug_logging ? 1 : 0

  service_account_id = google_service_account.debug_logs[0].name
  policy_data        = module.iam.debug_logs_sa_policy_json
}

resource "google_project_iam_member" "debug_logs_writer" {
  count = var.enable_debug_logging ? 1 : 0

  project = var.project_id
  role    = module.iam.debug_logs_role
  member  = module.iam.debug_logs_member

  depends_on = [google_service_account.debug_logs]
}
