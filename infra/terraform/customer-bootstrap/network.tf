# VPC, subnet and firewall (spec 8.4): ingress 80 and 443 to tagged VMs only,
# egress 443 and 53 only.

resource "google_compute_network" "sealed" {
  name                    = local.network_name
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Sealed confidential VMs."

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "sealed" {
  name          = local.subnetwork_name
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.sealed.id
  ip_cidr_range = var.subnet_cidr
  stack_type    = "IPV4_ONLY"

  # Sealed VMs have no service account, so they never call Google APIs.
  private_ip_google_access = false
}

resource "google_compute_firewall" "allow_web_ingress" {
  name        = "sealed-allow-web-ingress"
  project     = var.project_id
  network     = google_compute_network.sealed.id
  description = "HTTP (ACME) and HTTPS to Caddy on sealed VMs only."
  direction   = "INGRESS"
  priority    = 1000

  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.vm_tag]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "deny_ingress" {
  name        = "sealed-deny-ingress"
  project     = var.project_id
  network     = google_compute_network.sealed.id
  description = "Everything else inbound is dropped, SSH (22) included."
  direction   = "INGRESS"
  priority    = 65000

  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

resource "google_compute_firewall" "allow_egress" {
  name        = "sealed-allow-egress"
  project     = var.project_id
  network     = google_compute_network.sealed.id
  description = "Outbound HTTPS and DNS only. sealed-egress enforces the per-app allowlist inside the VM."
  direction   = "EGRESS"
  priority    = 1000

  destination_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["443", "53"]
  }

  allow {
    protocol = "udp"
    ports    = ["53"]
  }
}

resource "google_compute_firewall" "deny_egress" {
  name        = "sealed-deny-egress"
  project     = var.project_id
  network     = google_compute_network.sealed.id
  description = "Overrides the implied allow-all egress rule."
  direction   = "EGRESS"
  priority    = 65000

  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}
