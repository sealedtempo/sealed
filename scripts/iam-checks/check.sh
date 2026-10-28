#!/usr/bin/env bash
# IAM checks of a bootstrapped customer project (spec 8.6, P2, P4).
#
# Impersonates the deployer service account and expects every path to secrets, the key broker, service account
# identities and a shell to be denied. It also reads (as you) the IAM policies, custom roles, firewall rules, the
# key broker service and the sealed VMs, and checks that the key broker refuses a VM without a TDX quote.
#
# By default it changes nothing: denials are probed with testIamPermissions and read-only calls. With
# --attempt-mutations it also tries real changes as the deployer (update the key broker, attach a service
# account to a sealed VM); they must be refused, and would only touch sealed-* resources if IAM were broken.
#
# Impersonating the deployer needs serviceAccountTokenCreator on it, which only the platform service account
# holds. Run this as the platform operator with --platform-sa (gcloud then uses the delegation chain
# <you> -> platform SA -> deployer), or as the platform service account itself.
#
# Needs bash, gcloud, curl and jq (all present in Cloud Shell). Secret values are never printed.
#
# Usage:
#   scripts/iam-checks/check.sh --project <id> [--region us-central1] [--platform-sa <email>]
#                               [--instance sealed-<name> --zone <zone>] [--attempt-mutations]
set -uo pipefail

PROJECT="" REGION="us-central1" PLATFORM_SA="" INSTANCE="" ZONE="" ATTEMPT=0
DEPLOYER="" KEY_BROKER_NAME="sealed-key-broker" SUBNET="sealed-subnet" NETWORK="sealed-vpc"

# Permissions the deployer may hold, by grant. Keep in sync with infra/terraform/customer-bootstrap/modules/iam
# (scripts/iam-checks/policy_test.go checks it).
NAMED_ALLOWED="compute.disks.create compute.disks.delete compute.disks.get compute.disks.setLabels compute.disks.use compute.images.useReadOnly compute.instances.create compute.instances.delete compute.instances.get compute.instances.setLabels compute.instances.setMetadata compute.instances.setTags compute.instances.start compute.instances.stop"
PROJECT_ALLOWED="compute.addresses.create compute.addresses.delete compute.addresses.get compute.addresses.use compute.regionOperations.get compute.zoneOperations.get"
SUBNET_ALLOWED="compute.subnetworks.use compute.subnetworks.useExternalIp"
# Probed on the project as the deployer: none may be granted.
FORBIDDEN_PROJECT="iam.serviceAccounts.actAs iam.serviceAccounts.getAccessToken compute.instances.setServiceAccount compute.instances.osLogin compute.instances.osAdminLogin compute.projects.setCommonInstanceMetadata compute.instances.getSerialPortOutput iap.tunnelInstances.accessViaIAP secretmanager.versions.access secretmanager.secrets.list run.services.update run.services.get resourcemanager.projects.setIamPolicy cloudkms.cryptoKeyVersions.useToSign compute.firewalls.create compute.firewalls.update compute.networks.update storage.objects.get storage.objects.create iam.roles.update"
# Probed on every service account: none may be granted.
FORBIDDEN_SA="iam.serviceAccounts.actAs iam.serviceAccounts.getAccessToken iam.serviceAccounts.signBlob iam.serviceAccounts.signJwt iam.serviceAccounts.implicitDelegation iam.serviceAccounts.setIamPolicy iam.serviceAccountKeys.create"
FORBIDDEN_INSTANCE="compute.instances.setServiceAccount compute.instances.osLogin compute.instances.osAdminLogin compute.instances.getSerialPortOutput compute.instances.setIamPolicy"

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --platform-sa) PLATFORM_SA="$2"; shift 2 ;;
    --deployer-sa) DEPLOYER="$2"; shift 2 ;;
    --instance) INSTANCE="$2"; shift 2 ;;
    --zone) ZONE="$2"; shift 2 ;;
    --attempt-mutations) ATTEMPT=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$PROJECT" ] || usage
for tool in gcloud curl jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "check.sh needs $tool" >&2; exit 2; }
done
[ -n "$DEPLOYER" ] || DEPLOYER="sealed-deployer@${PROJECT}.iam.gserviceaccount.com"
KB_SA="sealed-key-broker@${PROJECT}.iam.gserviceaccount.com"
[ -n "$ZONE" ] || ZONE="${REGION}-a"

PASS=0 FAIL=0 SKIP=0
pass() { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$*"; }
# unreadable CODE WHAT: a read as you that IAM refused is skipped (run as a project owner or viewer for it).
unreadable() {
  if [ "$1" = 403 ]; then skip "cannot read $2 as $(gcloud config get-value account 2>/dev/null || echo you): run as a project owner or viewer for this check"; else fail "read $2: HTTP $1"; fi
}
fail() { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf 'SKIP  %s\n' "$*"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# api METHOD URL TOKEN [BODY] -> prints the HTTP status; the body is in $TMP/body (never echoed for secrets).
api() {
  local method="$1" url="$2" tok="$3" body="${4:-}"
  local args=(-sS -o "$TMP/body" -w '%{http_code}' -X "$method" -H "Content-Type: application/json")
  [ "$tok" = "none" ] || args+=(-H "Authorization: Bearer $tok")
  [ -z "$body" ] || args+=(--data "$body")
  : > "$TMP/body"
  curl "${args[@]}" "$url" 2>/dev/null || echo 000
}

ME="$(gcloud auth print-access-token 2>/dev/null)" || { echo "gcloud is not signed in" >&2; exit 2; }
CHAIN="$DEPLOYER"
[ -z "$PLATFORM_SA" ] || CHAIN="${PLATFORM_SA},${DEPLOYER}"
AS_DEPLOYER="$(gcloud auth print-access-token --impersonate-service-account="$CHAIN" 2>/dev/null)"
if [ -z "$AS_DEPLOYER" ]; then
  fail "impersonate the deployer $DEPLOYER (chain $CHAIN): no token; run as the platform operator with --platform-sa"
  echo "summary: $PASS passed, $FAIL failed, $SKIP skipped"
  exit 1
fi
pass "impersonated the deployer $DEPLOYER"
NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)' 2>/dev/null)"

CRM="https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT"
IAMV1="https://iam.googleapis.com/v1/projects/$PROJECT"
COMPUTE="https://compute.googleapis.com/compute/v1/projects/$PROJECT"
SM="https://secretmanager.googleapis.com/v1/projects/$PROJECT"
RUN="https://run.googleapis.com/v2/projects/$PROJECT/locations/$REGION/services/$KEY_BROKER_NAME"
KMS_KEY="projects/$PROJECT/locations/$REGION/keyRings/sealed/cryptoKeys/sealed-kb-hmac"

json_perms() { printf '%s\n' "$@" | jq -R . | jq -sc '{permissions: .}'; }
granted() { jq -r '(.permissions // [])[]' "$TMP/body" | sort | tr '\n' ' ' | sed 's/ $//'; }
words_sorted() { printf '%s\n' $1 | sort | tr '\n' ' ' | sed 's/ $//'; }

# --- 1. Policies and roles, read as you -------------------------------------------------------------------------

code="$(api POST "$IAMV1/serviceAccounts/$DEPLOYER:getIamPolicy" "$ME" '{"options":{"requestedPolicyVersion":3}}')"
if [ "$code" = 200 ]; then
  got="$(jq -c '[(.bindings // [])[] | {role, members: (.members | sort)}]' "$TMP/body")"
  want="$(jq -nc --arg m "serviceAccount:$PLATFORM_SA" '[{role: "roles/iam.serviceAccountTokenCreator", members: [$m]}]')"
  if [ -z "$PLATFORM_SA" ]; then
    want="$(jq -c '[(.bindings // [])[] | select(.role == "roles/iam.serviceAccountTokenCreator" and (.members | length) == 1) | {role, members: (.members | sort)}]' "$TMP/body")"
  fi
  if [ "$got" = "$want" ] && [ "$got" != "[]" ]; then
    pass "deployer identity: serviceAccountTokenCreator for the platform service account only"
  else
    fail "deployer identity policy is $got, want $want"
  fi
else
  unreadable "$code" "the deployer's IAM policy"
fi

code="$(api POST "$CRM:getIamPolicy" "$ME" '{"options":{"requestedPolicyVersion":3}}')"
if [ "$code" = 200 ]; then
  cp "$TMP/body" "$TMP/project-policy.json"
  roles="$(jq -r --arg m "serviceAccount:$DEPLOYER" '[(.bindings // [])[] | select(.members | index($m)) | .role] | sort | join(" ")' "$TMP/project-policy.json")"
  want_roles="projects/$PROJECT/roles/sealedDeployer projects/$PROJECT/roles/sealedDeployerAddresses"
  if [ "$roles" = "$want_roles" ]; then
    pass "deployer project roles: sealedDeployer and sealedDeployerAddresses only"
  else
    fail "deployer project roles are [$roles], want [$want_roles]"
  fi
  cond="$(jq -r --arg m "serviceAccount:$DEPLOYER" --arg r "projects/$PROJECT/roles/sealedDeployer" '[(.bindings // [])[] | select(.role == $r and (.members | index($m)))][0].condition.expression // ""' "$TMP/project-policy.json")"
  case "$cond" in
    *'resource.name.extract("/instances/{name}").startsWith("sealed-")'*'resource.name.extract("/disks/{name}").startsWith("sealed-")'*)
      case "$cond" in
        *'!='*) fail "the sealedDeployer condition has a negated clause: $cond" ;;
        *) pass "sealedDeployer is granted only on resources named sealed-*" ;;
      esac ;;
    *) fail "sealedDeployer is not limited to sealed-* names (condition: ${cond:-none})" ;;
  esac
  kb_roles="$(jq -r --arg m "serviceAccount:$KB_SA" '[(.bindings // [])[] | select(.members | index($m)) | .role] | sort | join(" ")' "$TMP/project-policy.json")"
  kb_cond="$(jq -r --arg m "serviceAccount:$KB_SA" '[(.bindings // [])[] | select(.role == "roles/secretmanager.secretAccessor" and (.members | index($m)))][0].condition.expression // ""' "$TMP/project-policy.json")"
  if [ "$kb_roles" = "roles/logging.logWriter roles/secretmanager.secretAccessor" ] && printf '%s' "$kb_cond" | grep -q "resource.name.startsWith(\"projects/${NUMBER}/secrets/sealed-\")"; then
    pass "key broker identity: secretAccessor on sealed-* secrets only, plus logWriter for its decision log"
  else
    fail "key broker project roles [$kb_roles] condition [${kb_cond:-none}]"
  fi
else
  unreadable "$code" "the project IAM policy"
fi

check_role() { # role-id allowed-list
  local code got extra
  code="$(api GET "$IAMV1/roles/$1" "$ME")"
  if [ "$code" != 200 ]; then unreadable "$code" "custom role $1"; return; fi
  got="$(jq -r '(.includedPermissions // [])[]' "$TMP/body" | sort | tr '\n' ' ' | sed 's/ $//')"
  if [ "$got" = "$(words_sorted "$2")" ]; then
    pass "custom role $1 has exactly its permissions"
  else
    extra="$(comm -23 <(printf '%s\n' $got | sort) <(printf '%s\n' $2 | sort) | tr '\n' ' ')"
    fail "custom role $1 permissions differ (extra: ${extra:-none})"
  fi
}
check_role sealedDeployer "$NAMED_ALLOWED"
check_role sealedDeployerAddresses "$PROJECT_ALLOWED"
check_role sealedSubnetUser "$SUBNET_ALLOWED"

code="$(api GET "$COMPUTE/regions/$REGION/subnetworks/$SUBNET/getIamPolicy?optionsRequestedPolicyVersion=3" "$ME")"
if [ "$code" != 200 ]; then
  unreadable "$code" "the IAM policy of subnet $SUBNET"
elif [ "$(jq -r --arg m "serviceAccount:$DEPLOYER" '[(.bindings // [])[] | select(.members | index($m)) | .role] | join(" ")' "$TMP/body")" = "projects/$PROJECT/roles/sealedSubnetUser" ]; then
  pass "subnet $SUBNET: the deployer may attach VMs to it, and holds nothing else there"
else
  fail "subnet $SUBNET IAM policy does not grant exactly sealedSubnetUser to the deployer"
fi

code="$(api GET "https://cloudkms.googleapis.com/v1/$KMS_KEY:getIamPolicy?options.requestedPolicyVersion=3" "$ME")"
if [ "$code" != 200 ]; then
  unreadable "$code" "the KMS key policy"
elif [ "$(jq -c '[(.bindings // [])[] | {role, members}]' "$TMP/body")" = "$(jq -nc --arg m "serviceAccount:$KB_SA" '[{role: "roles/cloudkms.signer", members: [$m]}]')" ]; then
  pass "KMS HMAC key: only the key broker may use it"
else
  fail "KMS key policy: $(jq -c '.bindings // []' "$TMP/body" 2>/dev/null)"
fi

code="$(api GET "$RUN" "$ME")"
if [ "$code" = 200 ]; then
  sa="$(jq -r '.template.serviceAccount // ""' "$TMP/body")"
  img="$(jq -r '.template.containers[0].image // ""' "$TMP/body")"
  case "$img" in *@sha256:????????????????????????????????????????????????????????????????) pinned=1 ;; *) pinned=0 ;; esac
  if [ "$sa" = "$KB_SA" ] && [ "$pinned" = 1 ]; then
    pass "key broker runs as its own identity from an image pinned by digest"
  else
    fail "key broker runs as [$sa] from [$img]"
  fi
else
  unreadable "$code" "the key broker service"
fi

code="$(api GET "$COMPUTE/global/firewalls" "$ME")"
if [ "$code" = 200 ]; then
  rules="$(jq -c --arg n "$NETWORK" '[.items[]? | select(.network | endswith("/networks/" + $n)) | select(.disabled != true)]' "$TMP/body")"
  bad_in="$(printf '%s' "$rules" | jq -r '[.[] | select(.direction == "INGRESS" and .allowed != null) | .allowed[] | select(.IPProtocol != "tcp" or ((.ports // ["all"]) | sort) != ["443","80"])] | length')"
  untagged="$(printf '%s' "$rules" | jq -r '[.[] | select(.direction == "INGRESS" and .allowed != null and ((.targetTags // []) != ["sealed-vm"]))] | length')"
  bad_out="$(printf '%s' "$rules" | jq -r '[.[] | select(.direction == "EGRESS" and .allowed != null) | .allowed[] | select(((.ports // ["all"]) - ["443","53"]) != [] or (.IPProtocol != "tcp" and .IPProtocol != "udp"))] | length')"
  deny_out="$(printf '%s' "$rules" | jq -r '[.[] | select(.direction == "EGRESS" and .denied != null) | .denied[] | select(.IPProtocol == "all")] | length')"
  if [ "$bad_in" = 0 ] && [ "$untagged" = 0 ] && [ "$bad_out" = 0 ] && [ "$deny_out" -ge 1 ]; then
    pass "firewall: ingress 80/443 to sealed-vm only, egress 443/53 only, everything else denied"
  else
    fail "firewall rules of $NETWORK: bad ingress $bad_in, untagged ingress $untagged, bad egress $bad_out, egress deny-all $deny_out"
  fi
else
  unreadable "$code" "the firewall rules"
fi

# --- 2. As the deployer: nothing beyond sealed-* VMs, disks and IPs ---------------------------------------------

code="$(api POST "$CRM:testIamPermissions" "$AS_DEPLOYER" "$(json_perms $FORBIDDEN_PROJECT)")"
if [ "$code" = 200 ] && [ -z "$(granted)" ]; then
  pass "deployer holds none of: secrets, key broker, KMS, actAs, setServiceAccount, OS Login, IAP, serial port, IAM, firewall"
else
  fail "deployer holds forbidden project permissions (HTTP $code): $(granted)"
fi
code="$(api POST "$CRM:testIamPermissions" "$AS_DEPLOYER" "$(json_perms compute.addresses.create compute.zoneOperations.get)")"
if [ "$code" = 200 ] && [ "$(granted)" = "compute.addresses.create compute.zoneOperations.get" ]; then
  pass "positive control: the impersonated deployer holds its own project permissions"
else
  fail "positive control failed (HTTP $code, granted: $(granted)): the probes above may not run as the deployer"
fi

code="$(api GET "$SM/secrets?filter=name:sealed-&pageSize=250" "$ME")"
secrets_list=""
[ "$code" = 200 ] && secrets_list="$(jq -r '.secrets[]?.name | sub(".*/"; "")' "$TMP/body")"
if [ -z "$secrets_list" ]; then
  skip "no sealed-* secrets yet: store one (sealed secrets set) to probe secret access"
fi
for s in $secrets_list; do
  code="$(api POST "$SM/secrets/$s:testIamPermissions" "$AS_DEPLOYER" "$(json_perms secretmanager.versions.access secretmanager.secrets.get secretmanager.secrets.setIamPolicy secretmanager.versions.add)")"
  if [ "$code" = 200 ] && [ -z "$(granted)" ]; then
    pass "deployer cannot read or change secret $s"
  else
    fail "deployer holds $(granted) on secret $s (HTTP $code)"
  fi
  code="$(api GET "$SM/secrets/$s/versions/latest:access" "$AS_DEPLOYER")"
  : > "$TMP/body" # the response is never shown
  if [ "$code" = 403 ]; then
    pass "reading $s as the deployer is denied"
  else
    fail "reading $s as the deployer returned HTTP $code"
  fi
done

code="$(api POST "$RUN:testIamPermissions" "$AS_DEPLOYER" "$(json_perms run.services.update run.services.delete run.services.setIamPolicy run.services.get)")"
if [ "$code" = 200 ] && [ -z "$(granted)" ]; then
  pass "deployer cannot change, delete or re-permission the key broker"
else
  fail "deployer holds $(granted) on the key broker (HTTP $code)"
fi
code="$(api POST "https://cloudkms.googleapis.com/v1/$KMS_KEY:testIamPermissions" "$AS_DEPLOYER" "$(json_perms cloudkms.cryptoKeyVersions.useToSign cloudkms.cryptoKeys.setIamPolicy cloudkms.cryptoKeys.update)")"
if [ "$code" = 200 ] && [ -z "$(granted)" ]; then
  pass "deployer cannot use or change the KMS HMAC key"
else
  fail "deployer holds $(granted) on the KMS key (HTTP $code)"
fi

code="$(api GET "$IAMV1/serviceAccounts?pageSize=100" "$ME")"
sas=""
[ "$code" = 200 ] && sas="$(jq -r '.accounts[]?.email' "$TMP/body")"
[ -n "$NUMBER" ] && sas="$sas ${NUMBER}-compute@developer.gserviceaccount.com"
for sa in $sas; do
  code="$(api POST "https://iam.googleapis.com/v1/projects/-/serviceAccounts/$sa:testIamPermissions" "$AS_DEPLOYER" "$(json_perms $FORBIDDEN_SA)")"
  if [ "$code" = 404 ]; then
    skip "service account $sa does not exist"
  elif [ "$code" = 200 ] && [ -z "$(granted)" ]; then
    pass "deployer cannot act as or mint tokens for $sa"
  else
    fail "deployer holds $(granted) on service account $sa (HTTP $code)"
  fi
done

# --- 3. Sealed VMs: no identity, no shell ----------------------------------------------------------------------

instances="$INSTANCE"
if [ -z "$instances" ]; then
  code="$(api GET "$COMPUTE/zones/$ZONE/instances?filter=name%3Dsealed-*" "$ME")"
  [ "$code" = 200 ] && instances="$(jq -r '.items[]?.name' "$TMP/body")"
fi
[ -n "$instances" ] || skip "no sealed-* VM in $ZONE: deploy one to check VM settings, instance permissions and SSH"
for vm in $instances; do
  code="$(api GET "$COMPUTE/zones/$ZONE/instances/$vm" "$ME")"
  if [ "$code" != 200 ]; then unreadable "$code" "VM $vm"; continue; fi
  cp "$TMP/body" "$TMP/vm.json"
  problems="$(jq -r '
    (((.metadata.items // []) | map({(.key): (.value | ascii_upcase)}) | add) // {}) as $m
    | [ (if ((.serviceAccounts // []) | length) > 0 then "has a service account" else empty end),
        (if .confidentialInstanceConfig.confidentialInstanceType != "TDX" then "not TDX" else empty end),
        (if $m["serial-port-enable"] != "FALSE" then "serial port not off" else empty end),
        (if $m["enable-oslogin"] != "FALSE" then "OS Login not off" else empty end),
        (if $m["block-project-ssh-keys"] != "TRUE" then "project SSH keys not blocked" else empty end),
        (if $m["ssh-keys"] != null then "ssh-keys metadata set" else empty end) ]
    | join(", ")' "$TMP/vm.json")"
  if [ -z "$problems" ]; then
    pass "VM $vm: TDX, no service account, serial port and OS Login off, project SSH keys blocked"
  else
    fail "VM $vm: $problems"
  fi
  code="$(api POST "$COMPUTE/zones/$ZONE/instances/$vm/testIamPermissions" "$AS_DEPLOYER" "$(json_perms $FORBIDDEN_INSTANCE)")"
  if [ "$code" = 200 ] && [ -z "$(granted)" ]; then
    pass "deployer cannot attach a service account to $vm, log in, or read its serial port"
  else
    fail "deployer holds $(granted) on $vm (HTTP $code)"
  fi
  code="$(api POST "$COMPUTE/zones/$ZONE/instances/$vm/testIamPermissions" "$AS_DEPLOYER" "$(json_perms compute.instances.start compute.instances.stop compute.instances.delete)")"
  if [ "$code" = 200 ] && [ "$(granted)" = "compute.instances.delete compute.instances.start compute.instances.stop" ]; then
    pass "positive control: the deployer may start, stop and delete $vm"
  else
    fail "positive control on $vm failed (HTTP $code, granted: $(granted))"
  fi
  ip="$(jq -r '.networkInterfaces[0].accessConfigs[0].natIP // ""' "$TMP/vm.json")"
  port="${SEALED_IAMCHECK_SSH_PORT:-22}"
  if [ -n "$ip" ]; then
    ( exec 3<>"/dev/tcp/$ip/$port" ) 2>/dev/null &
    probe=$!
    ( sleep 5; kill "$probe" 2>/dev/null ) >/dev/null 2>&1 &
    timer=$!
    if wait "$probe" 2>/dev/null; then
      fail "port $port is reachable on $vm ($ip)"
    else
      pass "no SSH: port $port on $vm ($ip) does not accept connections"
    fi
    { kill "$timer"; wait "$timer"; } 2>/dev/null
  else
    skip "VM $vm has no external IP to probe"
  fi
  if [ "$ATTEMPT" = 1 ]; then
    code="$(api POST "$COMPUTE/zones/$ZONE/instances/$vm/setServiceAccount" "$AS_DEPLOYER" "$(jq -nc --arg e "$KB_SA" '{email: $e, scopes: ["https://www.googleapis.com/auth/cloud-platform"]}')")"
    if [ "$code" = 403 ]; then pass "attaching the key broker identity to $vm as the deployer is denied"; else fail "setServiceAccount on $vm returned HTTP $code"; fi
  fi
done

if [ "$ATTEMPT" = 1 ]; then
  code="$(api PATCH "$RUN?updateMask=labels" "$AS_DEPLOYER" '{"labels":{"sealed-iam-check":"1"}}')"
  if [ "$code" = 403 ]; then pass "changing the key broker as the deployer is denied"; else fail "updating the key broker as the deployer returned HTTP $code"; fi
fi

# --- 4. The key broker refuses a VM without a TDX quote (D-036) -------------------------------------------------

code="$(api GET "$RUN" "$ME")"
kb_url=""
[ "$code" = 200 ] && kb_url="$(jq -r '.uri // ""' "$TMP/body")"
if [ -n "$kb_url" ]; then
  code="$(api GET "$kb_url/v1/nonce" none)"
  nonce="$(jq -r '.nonce // ""' "$TMP/body" 2>/dev/null)"
  if [ "$code" = 200 ] && [ -n "$nonce" ]; then
    # A dev simulator quote: what a VM without TDX could send at best.
    sim="$(printf 'SEALEDSIM1{"debug":false,"mrtd":"%s","reportData":"%s","rtmr0":"","rtmr1":"","rtmr2":"","rtmr3":"","schema":"sealed-sim-quote/v1"}' "$(printf '11%.0s' $(seq 48))" "$(printf '00%.0s' $(seq 64))" | od -An -tx1 | tr -d ' \n')"
    body="$(jq -nc --arg n "$nonce" --arg q "0x$sim" '{nonce: $n, ephemeralPub: ("0x" + ("00" * 32)), quote: $q, eventLog: [], config: {}, appCompose: "", releaseIds: [], imageId: ("0x" + ("00" * 32))}')"
    code="$(api POST "$kb_url/v1/release" none "$body")"
    reason="$(jq -r '.reason // ""' "$TMP/body" 2>/dev/null)"
    if [ "$code" = 403 ] && [ "$reason" = "quote_invalid" ]; then
      pass "key broker refuses a VM without a TDX quote (403 quote_invalid)"
    else
      fail "key broker answered HTTP $code reason [$reason] to a non-TDX release request"
    fi
  else
    fail "key broker nonce: HTTP $code"
  fi
else
  skip "key broker URL unknown"
fi

echo "summary: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" = 0 ]
