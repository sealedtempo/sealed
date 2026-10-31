# Plan-only tests with a mocked google provider: no credentials, no API calls,
# nothing is created. Run with `terraform init && terraform test`.

mock_provider "google" {
  mock_data "google_project" {
    defaults = {
      number = "123456789012"
    }
  }

  mock_resource "google_kms_crypto_key" {
    override_during = plan
    defaults = {
      id = "projects/sealed-test-1234/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac"
    }
  }

}

override_resource {
  target          = google_service_account.deployer
  override_during = plan
  values = {
    name  = "projects/sealed-test-1234/serviceAccounts/sealed-deployer@sealed-test-1234.iam.gserviceaccount.com"
    email = "sealed-deployer@sealed-test-1234.iam.gserviceaccount.com"
  }
}

override_resource {
  target          = google_service_account.debug_logs
  override_during = plan
  values = {
    name  = "projects/sealed-test-1234/serviceAccounts/sealed-debug-logs@sealed-test-1234.iam.gserviceaccount.com"
    email = "sealed-debug-logs@sealed-test-1234.iam.gserviceaccount.com"
  }
}

override_resource {
  target          = google_cloud_run_v2_service.key_broker
  override_during = plan
  values = {
    uri = "https://sealed-key-broker-xyz-uc.a.run.app"
  }
}

override_resource {
  target          = google_service_account.key_broker
  override_during = plan
  values = {
    name  = "projects/sealed-test-1234/serviceAccounts/sealed-key-broker@sealed-test-1234.iam.gserviceaccount.com"
    email = "sealed-key-broker@sealed-test-1234.iam.gserviceaccount.com"
  }
}

variables {
  project_id               = "sealed-test-1234"
  region                   = "us-central1"
  customer_address         = "0x00000000000000000000000000000000000000C1"
  platform_service_account = "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com"
  key_broker_image         = "ghcr.io/sealedtempo/sealed-key-broker@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  platform_registry        = "0x18AB956ea44757587896dfD25632FB3e89F7002d"
  app_registry             = "0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43"
  deployment_registry      = "0x254eFB9d1809A95Ec6d233cC57b3a10849bd2C8E"
}

run "network_and_firewall" {
  command = plan

  assert {
    condition     = google_compute_network.sealed.auto_create_subnetworks == false
    error_message = "the VPC must not auto-create subnets"
  }

  assert {
    condition     = google_compute_subnetwork.sealed.name == "sealed-subnet" && google_compute_subnetwork.sealed.region == "us-central1"
    error_message = "subnet name and region"
  }

  assert {
    condition     = google_compute_subnetwork.sealed.description == "sealed-binding/v1 customer=0x00000000000000000000000000000000000000c1 key_broker=https://sealed-key-broker-xyz-uc.a.run.app"
    error_message = "the subnet carries the connection binding the platform checks: this wallet, lowercase, and this project's key broker"
  }

  assert {
    condition     = output.connection_binding == google_compute_subnetwork.sealed.description
    error_message = "the binding is an output"
  }

  assert {
    condition     = google_compute_firewall.allow_web_ingress.direction == "INGRESS" && google_compute_firewall.allow_web_ingress.target_tags == toset(["sealed-vm"])
    error_message = "web ingress must target tagged VMs only"
  }

  assert {
    condition     = length(google_compute_firewall.allow_web_ingress.allow) == 1 && toset(tolist(google_compute_firewall.allow_web_ingress.allow)[0].ports) == toset(["80", "443"]) && tolist(google_compute_firewall.allow_web_ingress.allow)[0].protocol == "tcp"
    error_message = "ingress allows exactly tcp 80 and 443"
  }

  assert {
    condition     = google_compute_firewall.deny_ingress.priority > google_compute_firewall.allow_web_ingress.priority && tolist(google_compute_firewall.deny_ingress.deny)[0].protocol == "all"
    error_message = "everything else inbound is denied"
  }

  assert {
    condition = (
      google_compute_firewall.allow_egress.direction == "EGRESS" &&
      length(google_compute_firewall.allow_egress.allow) == 2 &&
      alltrue([for a in google_compute_firewall.allow_egress.allow : (a.protocol == "tcp" && toset(a.ports) == toset(["443", "53"])) || (a.protocol == "udp" && toset(a.ports) == toset(["53"]))])
    )
    error_message = "egress allows only tcp 443 and 53 and udp 53"
  }

  assert {
    condition     = google_compute_firewall.deny_egress.direction == "EGRESS" && google_compute_firewall.deny_egress.priority > google_compute_firewall.allow_egress.priority && tolist(google_compute_firewall.deny_egress.deny)[0].protocol == "all"
    error_message = "everything else outbound is denied"
  }
}

run "kms_key" {
  command = plan

  assert {
    condition     = google_kms_crypto_key.hmac.purpose == "MAC" && google_kms_crypto_key.hmac.version_template[0].algorithm == "HMAC_SHA256"
    error_message = "the key broker key is an HMAC-SHA256 key"
  }

  assert {
    condition     = google_kms_crypto_key.hmac.deletion_policy == "PREVENT"
    error_message = "the HMAC key is protected from deletion"
  }

  assert {
    condition     = jsondecode(google_kms_crypto_key_iam_policy.hmac.policy_data) == { bindings = [{ role = "roles/cloudkms.signer", members = ["serviceAccount:sealed-key-broker@sealed-test-1234.iam.gserviceaccount.com"] }] }
    error_message = "only the key broker may use the HMAC key"
  }
}

run "key_broker" {
  command = plan

  assert {
    condition     = google_cloud_run_v2_service.key_broker.template[0].containers[0].image == "us-central1-docker.pkg.dev/sealed-test-1234/sealed-ghcr/sealedtempo/sealed-key-broker@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    error_message = "ghcr.io images are pulled through the remote repository with the same digest"
  }

  assert {
    condition     = google_cloud_run_v2_service.key_broker.ssh_enabled == false && google_cloud_run_v2_service.key_broker.invoker_iam_disabled == true
    error_message = "no SSH into the key broker; callers are gated by attestation"
  }

  assert {
    condition     = google_cloud_run_v2_service.key_broker.template[0].scaling[0].max_instance_count == 1
    error_message = "one key broker instance by default (single-use nonces)"
  }

  assert {
    condition = (
      { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value } == {
        SEALED_CUSTOMER_ADDRESS    = "0x00000000000000000000000000000000000000c1"
        TEMPO_RPC_URL              = "https://rpc.tempo.xyz"
        TEMPO_CHAIN_ID             = "4217"
        SEALED_PLATFORM_REGISTRY   = "0x18ab956ea44757587896dfd25632fb3e89f7002d"
        SEALED_APP_REGISTRY        = "0x88c91cacb74ccec3b8a1823977eec42ae3b93b43"
        SEALED_DEPLOYMENT_REGISTRY = "0x254efb9d1809a95ec6d233cc57b3a10849bd2c8e"
        SEALED_RELEASE_ASSET_BASE  = "https://github.com/sealedtempo/sealed/releases/download"
        SEALED_GCP_PROJECT         = "sealed-test-1234"
        SEALED_GCP_PROJECT_NUMBER  = "123456789012"
        SEALED_SECRET_PREFIX       = "sealed-"
        SEALED_KMS_KEY_VERSION     = "projects/sealed-test-1234/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac/cryptoKeyVersions/1"
        GOMEMLIMIT                 = "768MiB"
      }
    )
    error_message = "the broker gets exactly the variables it reads (cmd/key-broker): the customer, not the platform, sets its address, RPC, chain, key and registries"
  }

  assert {
    condition     = { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value } == merge(module.key_broker_env.env, module.key_broker_env.runtime_env)
    error_message = "the Cloud Run env is modules/key-broker-env unchanged (cli/internal/bootstrap TestKeyBrokerEnvContract runs the broker's parser on it)"
  }

  assert {
    condition     = output.kms_key_version == "projects/sealed-test-1234/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac/cryptoKeyVersions/1" && output.tempo_rpc_url == "https://rpc.tempo.xyz" && output.key_broker_env == module.key_broker_env.env
    error_message = "the outputs name the key version and the RPC the broker uses"
  }

  assert {
    condition     = google_cloud_run_v2_service.key_broker.template[0].timeout == "120s" && google_cloud_run_v2_service.key_broker.template[0].containers[0].resources[0].limits["memory"] == "1Gi" && google_cloud_run_v2_service.key_broker.template[0].containers[0].ports[0].container_port == 8080
    error_message = "the request timeout exceeds the broker's 90 s release deadline; 1 GiB with GOMEMLIMIT below it; port 8080"
  }

  assert {
    condition     = google_cloud_run_v2_service.key_broker.template[0].max_instance_request_concurrency == 80
    error_message = "the broker bounds its own work, so Cloud Run hands it up to 80 requests (harden-kb)"
  }

  assert {
    condition     = length(module.key_broker_env.optional_env) == 0 && !anytrue([for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : contains(["SEALED_FEE_SPLITTER", "SEALED_FEE_TOKEN", "SEALED_ALLOWED_IMAGES"], e.name)])
    error_message = "no optional broker variable unless the customer chose one (mainnet FeeSplitter and fee token, no own allowlist)"
  }

  assert {
    condition     = google_project_iam_member.key_broker_logging.role == "roles/logging.logWriter" && google_project_iam_member.key_broker_logging.member == "serviceAccount:sealed-key-broker@sealed-test-1234.iam.gserviceaccount.com"
    error_message = "the broker may write its decision log"
  }

  assert {
    condition     = google_project_iam_member.key_broker_secrets.role == "roles/secretmanager.secretAccessor" && google_project_iam_member.key_broker_secrets.member == "serviceAccount:sealed-key-broker@sealed-test-1234.iam.gserviceaccount.com"
    error_message = "the broker gets secretAccessor"
  }

  assert {
    condition     = strcontains(google_project_iam_member.key_broker_secrets.condition[0].expression, "resource.name.startsWith(\"projects/123456789012/secrets/sealed-\")")
    error_message = "secretAccessor is limited to sealed-* secrets by project number"
  }

  assert {
    condition     = jsondecode(google_service_account_iam_policy.key_broker.policy_data) == { bindings = [] }
    error_message = "nobody holds a role on the key broker identity"
  }
}

run "deployer" {
  command = plan

  assert {
    condition     = toset(google_project_iam_custom_role.deployer_named.permissions) == toset(module.iam.deployer_named_permissions)
    error_message = "the named role carries the module's permission list"
  }

  assert {
    condition     = google_project_iam_member.deployer_named.condition[0].expression == module.iam.deployer_named_condition
    error_message = "the named role is granted only with the name condition"
  }

  assert {
    condition     = google_project_iam_member.deployer_named.member == "serviceAccount:sealed-deployer@sealed-test-1234.iam.gserviceaccount.com"
    error_message = "granted to the deployer"
  }

  assert {
    condition = alltrue([
      for p in setunion(google_project_iam_custom_role.deployer_named.permissions, google_project_iam_custom_role.deployer_project.permissions, google_project_iam_custom_role.subnet_user.permissions) :
      !contains(["iam.serviceAccounts.actAs", "compute.instances.setServiceAccount", "compute.instances.osLogin", "compute.instances.osAdminLogin", "compute.projects.setCommonInstanceMetadata", "compute.instances.getSerialPortOutput"], p) &&
      !startswith(p, "secretmanager.") && !startswith(p, "run.") && !startswith(p, "cloudkms.") && !startswith(p, "iam.") && !startswith(p, "resourcemanager.") && !startswith(p, "iap.")
    ])
    error_message = "the deployer can never act as a service account, read secrets, touch the key broker or open a shell"
  }

  assert {
    condition     = google_compute_subnetwork_iam_member.deployer.subnetwork == "sealed-subnet" && toset(google_project_iam_custom_role.subnet_user.permissions) == toset(["compute.subnetworks.get", "compute.subnetworks.use", "compute.subnetworks.useExternalIp"])
    error_message = "subnet use, and reading the connection binding, are granted on the sealed subnet only"
  }

  assert {
    condition = (
      length(setintersection(google_project_iam_custom_role.deployer_named.permissions, toset(["compute.images.create", "compute.images.delete", "compute.images.get", "compute.images.useReadOnly"]))) == 4 &&
      contains(google_project_iam_custom_role.deployer_project.permissions, "compute.globalOperations.get") &&
      !anytrue([for p in setunion(google_project_iam_custom_role.deployer_project.permissions, google_project_iam_custom_role.subnet_user.permissions) : startswith(p, "compute.images.")])
    )
    error_message = "the deployer creates, reads, deletes and boots images only under the sealed-* name condition, and follows their global operations (D-074)"
  }

  assert {
    condition = alltrue([
      for p in setunion(google_project_iam_custom_role.deployer_named.permissions, google_project_iam_custom_role.deployer_project.permissions, google_project_iam_custom_role.subnet_user.permissions) :
      !startswith(p, "storage.") && !contains(["compute.subnetworks.update", "compute.subnetworks.setIamPolicy", "compute.subnetworks.create"], p)
    ])
    error_message = "the deployer holds no storage permission outside the staging bucket and cannot change the subnet or its binding"
  }

  assert {
    condition     = jsondecode(google_service_account_iam_policy.deployer.policy_data) == { bindings = [{ role = "roles/iam.serviceAccountTokenCreator", members = ["serviceAccount:sealed-platform@sealed-platform-1234.iam.gserviceaccount.com"] }] }
    error_message = "only the platform service account may mint deployer tokens"
  }
}

run "customer_rpc_and_chain_reach_the_broker" {
  command = plan

  variables {
    tempo_rpc_url      = "https://tempo.customer-node.example/rpc"
    chain_id           = 42431
    release_asset_base = "https://assets.customer.example/releases"
  }

  assert {
    condition = (
      { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value }["TEMPO_RPC_URL"] == "https://tempo.customer-node.example/rpc" &&
      { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value }["TEMPO_CHAIN_ID"] == "42431" &&
      { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value }["SEALED_RELEASE_ASSET_BASE"] == "https://assets.customer.example/releases"
    )
    error_message = "the customer's RPC, chain and asset base are never replaced by defaults"
  }
}

run "non_mainnet_fees_and_image_allowlist_reach_the_broker" {
  command = plan

  variables {
    fee_splitter              = "0x00000000000000000000000000000000000000E5"
    fee_token                 = "0x20C0000000000000000000000000000000000001"
    key_broker_allowed_images = ["0xAB00000000000000000000000000000000000000000000000000000000000001", "0x00000000000000000000000000000000000000000000000000000000000000cd"]
  }

  assert {
    condition = (
      { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value }["SEALED_FEE_SPLITTER"] == "0x00000000000000000000000000000000000000e5" &&
      { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value }["SEALED_FEE_TOKEN"] == "0x20c0000000000000000000000000000000000001" &&
      { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value }["SEALED_ALLOWED_IMAGES"] == "0xab00000000000000000000000000000000000000000000000000000000000001,0x00000000000000000000000000000000000000000000000000000000000000cd"
    )
    error_message = "the FeeSplitter, fee token and imageId allowlist the customer chose reach the broker under the names it reads"
  }

  assert {
    condition     = { for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.name => e.value } == merge(module.key_broker_env.env, module.key_broker_env.runtime_env)
    error_message = "the Cloud Run env is still modules/key-broker-env unchanged"
  }
}

run "rejects_bad_fee_splitter" {
  command = plan

  variables {
    fee_splitter = "0x12"
  }

  expect_failures = [var.fee_splitter]
}

run "rejects_bad_allowed_image" {
  command = plan

  variables {
    key_broker_allowed_images = ["0x1234"]
  }

  expect_failures = [var.key_broker_allowed_images]
}

run "no_debug_identity_by_default" {
  command = plan

  assert {
    condition     = length(google_service_account.debug_logs) == 0 && length(google_project_iam_member.debug_logs_writer) == 0 && output.debug_log_service_account == ""
    error_message = "no debug log writer identity unless asked for"
  }
}

run "debug_logging_identity" {
  command = plan

  variables {
    enable_debug_logging = true
  }

  assert {
    condition     = google_service_account.debug_logs[0].account_id == "sealed-debug-logs"
    error_message = "the debug log writer has a fixed name"
  }

  assert {
    condition     = google_project_iam_member.debug_logs_writer[0].role == "roles/logging.logWriter" && google_project_iam_member.debug_logs_writer[0].member == "serviceAccount:sealed-debug-logs@sealed-test-1234.iam.gserviceaccount.com" && length(google_project_iam_member.debug_logs_writer[0].condition) == 0
    error_message = "the debug identity may only write logs"
  }

  assert {
    condition     = jsondecode(google_service_account_iam_policy.debug_logs[0].policy_data) == { bindings = [] }
    error_message = "nobody (the deployer in particular) holds a role on the debug identity"
  }
}

run "boot_bucket" {
  command = plan

  assert {
    condition     = google_storage_bucket.boot[0].name == "sealed-test-1234-sealed-boot" && google_storage_bucket.boot[0].public_access_prevention == "enforced" && google_storage_bucket.boot[0].uniform_bucket_level_access == true
    error_message = "the boot bucket is private"
  }
}

run "staging_bucket" {
  command = plan

  assert {
    condition = (
      google_storage_bucket.staging.name == "sealed-test-1234-sealed-staging" &&
      google_storage_bucket.staging.uniform_bucket_level_access == true &&
      google_storage_bucket.staging.public_access_prevention == "enforced" &&
      google_storage_bucket.staging.location == "us-central1"
    )
    error_message = "the staging bucket is <project>-sealed-staging, private, with uniform access (D-074)"
  }

  assert {
    condition = (
      length(google_storage_bucket.staging.lifecycle_rule) == 1 &&
      tolist(google_storage_bucket.staging.lifecycle_rule[0].condition)[0].age == 1 &&
      tolist(google_storage_bucket.staging.lifecycle_rule[0].action)[0].type == "Delete"
    )
    error_message = "staged objects are deleted after 1 day"
  }

  assert {
    condition = (
      google_storage_bucket_iam_member.deployer_staging.bucket == "sealed-test-1234-sealed-staging" &&
      google_storage_bucket_iam_member.deployer_staging.role == "roles/storage.objectAdmin" &&
      google_storage_bucket_iam_member.deployer_staging.member == "serviceAccount:sealed-deployer@sealed-test-1234.iam.gserviceaccount.com" &&
      length(google_storage_bucket_iam_member.deployer_staging.condition) == 0
    )
    error_message = "the deployer gets objectAdmin on the staging bucket only"
  }

  assert {
    condition     = output.staging_bucket == "sealed-test-1234-sealed-staging"
    error_message = "the staging bucket is an output"
  }
}

run "keyed_rpc_is_redacted_from_plan_and_output" {
  command = plan

  variables {
    tempo_rpc_url = "https://tempo.provider.example/v2/FAKEAPIKEY0123456789"
  }

  # issensitive is true only because the variable and both outputs carry
  # sensitive = true; without it Terraform prints the key in the Cloud Run env
  # block and the Outputs block of every plan and apply (cli-1).
  assert {
    condition = (
      issensitive(var.tempo_rpc_url) &&
      issensitive(output.tempo_rpc_url) &&
      issensitive(output.key_broker_env) &&
      issensitive(module.key_broker_env.env["TEMPO_RPC_URL"]) &&
      issensitive([for e in google_cloud_run_v2_service.key_broker.template[0].containers[0].env : e.value if e.name == "TEMPO_RPC_URL"][0])
    )
    error_message = "the keyed Tempo RPC must be sensitive everywhere it flows, so Terraform redacts it from the plan, the apply and the outputs (cli-1)"
  }

  # The CLI still reads the full value from `terraform output -json`.
  assert {
    condition     = nonsensitive(output.tempo_rpc_url) == "https://tempo.provider.example/v2/FAKEAPIKEY0123456789"
    error_message = "the broker must still get the full keyed RPC"
  }
}

run "rejects_tag_pinned_key_broker" {
  command = plan

  variables {
    key_broker_image = "ghcr.io/sealedtempo/sealed-key-broker:latest"
  }

  expect_failures = [var.key_broker_image]
}

run "rejects_placeholder_digest" {
  command = plan

  variables {
    key_broker_image = "ghcr.io/sealedtempo/sealed-key-broker@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  }

  expect_failures = [var.key_broker_image]
}

run "rejects_bad_customer_address" {
  command = plan

  variables {
    customer_address = "0x1234"
  }

  expect_failures = [var.customer_address]
}
