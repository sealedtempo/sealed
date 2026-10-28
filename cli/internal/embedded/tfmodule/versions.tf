terraform {
  # 1.7 brings mock providers for tests/plan.tftest.hcl.
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "8.7.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region

  default_labels = merge(var.labels, {
    sealed = "bootstrap"
  })
}
