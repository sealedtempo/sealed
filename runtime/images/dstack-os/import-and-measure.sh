#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Import a Sealed dstack OS image into a GCP project and record its TDX
# measurements (MRTD, RTMR0-2) from first boots, per machine type (spec 5.1,
# THREAT_MODEL "TOFU"). Writes an images file for
# contracts/script/RegisterCatalog.s.sol (CATALOG_FILE), with
# imageId = keccak256(abi.encode(name, version, measurementsHash)).
#
# Usage:
#   import-and-measure.sh --project P --zone Z --bucket gs://B \
#     --tarball <name>-<version>-gce.tar.gz --identity <name>-<version>-identity.tar.gz \
#     [--machine-types c3-standard-8[,c3-standard-4,...]] [--boots 2] \
#     [--release-base https://github.com/<owner>/<repo>/releases/download | --source-uri URL] \
#     [--repo OWNER/REPO] [--allow-unsigned] \
#     [--image-name NAME] [--network N --subnet S] [--out FILE] [--work DIR] \
#     [--osimage BIN] [--timeout SECONDS] [--keep] [--dry-run]
#
# What it does, in order:
#   1. Verifies the Sigstore bundles of the identity and the tarball
#      (<file>.sigstore.json, release assets next to them): both must be signed
#      keyless by .github/workflows/os-image.yml of OWNER/REPO at the tag
#      os-image-v<version of the identity>, which only signs a commit on main
#      (supply-7). OWNER/REPO is --repo, else the --release-base repository,
#      else sealedtempo/sealed. Needs cosign. --allow-unsigned skips this for a
#      local or workflow_dispatch build, which must never be registered for
#      production. Then checks the tarball against the identity file (sha256)
#      and imports it as a GCE image with UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC
#      (reused if an image of that name already carries the same tarball
#      sha256).
#   2. Builds two small auxiliary disks: a dstack-data GPT disk and a DSTACKSHR
#      FAT32 disk holding a measurement app-compose.json (runner "bash", no
#      containers, no network, no secrets) and .sys-config.json (no KMS, no
#      gateway, this image's vm_config).
#   3. For every machine type and boot, creates a TDX VM (no service account,
#      no scopes, no external IP, project SSH keys blocked, OS Login off),
#      waits until the measurement app prints a quote over a fresh 64-byte
#      nonce to the serial console, verifies it (Intel PCS collateral,
#      report_data == nonce, production TD attributes) and deletes the VM.
#      VMs run one at a time (D-037 quota).
#   4. Requires identical MRTD/RTMR0-2 across the boots of each machine type
#      and writes one catalog entry per distinct set of measurements.
#
# It creates and deletes GCE images, disks and VMs and GCS objects in the given
# project, so it is run by the operator, never by CI. --dry-run prints the
# gcloud commands instead of running them (the signature and sha256 checks still
# run). Needs gcloud, cosign, mtools (mformat, mcopy), sgdisk (gdisk/gptfdisk),
# GNU tar or bsdtar, and the osimage helper (built from tools/osimage with Go
# when --osimage is not given).
set -euo pipefail
umask 0022

SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SELF/../../.." && pwd)

die() { echo "import-and-measure: $*" >&2; exit 1; }
log() { echo "import-and-measure: $*" >&2; }

project='' zone='' bucket='' tarball='' identity_in='' machine_types=c3-standard-8 boots=2
release_base='' source_uri='' image_name='' network='' subnet='' out='' work='' osimage='' timeout=1200
keep=0 dry_run=0 repo='' allow_unsigned=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --project) project=$2; shift 2 ;;
    --zone) zone=$2; shift 2 ;;
    --bucket) bucket=${2%/}; shift 2 ;;
    --tarball) tarball=$2; shift 2 ;;
    --identity) identity_in=$2; shift 2 ;;
    --machine-types) machine_types=$2; shift 2 ;;
    --boots) boots=$2; shift 2 ;;
    --release-base) release_base=$2; shift 2 ;;
    --source-uri) source_uri=$2; shift 2 ;;
    --repo) repo=$2; shift 2 ;;
    --allow-unsigned) allow_unsigned=1; shift ;;
    --image-name) image_name=$2; shift 2 ;;
    --network) network=$2; shift 2 ;;
    --subnet) subnet=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --work) work=$2; shift 2 ;;
    --osimage) osimage=$2; shift 2 ;;
    --timeout) timeout=$2; shift 2 ;;
    --keep) keep=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) sed -n '2,49p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
done
[[ -n $project && -n $zone && -n $bucket && -n $tarball && -n $identity_in ]] ||
  die "--project, --zone, --bucket, --tarball and --identity are required"
[[ $bucket == gs://* ]] || die "--bucket must be a gs:// URL"
[[ $boots =~ ^[1-9][0-9]*$ ]] || die "--boots must be a positive integer"
[[ -f $tarball ]] || die "no such tarball: $tarball"
[[ -n $release_base || -n $source_uri ]] || die "--release-base or --source-uri is required (the onchain sourceURI)"
if [[ -z $repo ]]; then
  if [[ $release_base =~ ^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/download/?$ ]]; then
    repo=${BASH_REMATCH[1]}
  else
    repo=sealedtempo/sealed
  fi
fi
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo must be OWNER/REPO"

for tool in gcloud mformat mcopy sgdisk gzip; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
if [[ $allow_unsigned == 0 ]]; then
  command -v cosign >/dev/null || die "cosign is required to verify the release signatures"
fi
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
# GCE wants a GNU-format tar whose only member is disk.raw.
gce_tar() { # gce_tar DIR OUTPUT
  if command -v gtar >/dev/null; then
    gtar --format=oldgnu -C "$1" -cf - disk.raw | gzip -n > "$2"
  elif tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar --format=oldgnu -C "$1" -cf - disk.raw | gzip -n > "$2"
  else
    tar --format=gnutar -C "$1" -cf - disk.raw | gzip -n > "$2"
  fi
}
# Sparse zero file of N MiB (portable: no GNU truncate on macOS).
zero_file() { : > "$1"; dd if=/dev/zero of="$1" bs=1048576 count=0 seek="$2" 2>/dev/null; }

# gcloud wrapper: --dry-run prints instead of running.
gc() {
  if [[ $dry_run == 1 ]]; then
    printf 'DRY-RUN gcloud'; printf ' %q' "$@"; printf '\n'
    return 0
  fi
  gcloud "$@"
}

work=${work:-$(mktemp -d "${TMPDIR:-/tmp}/sealed-measure.XXXXXX")}
mkdir -p "$work"
log "work directory $work"

if [[ -z $osimage ]]; then
  command -v go >/dev/null || die "go is required to build the osimage helper (or pass --osimage)"
  osimage="$work/osimage"
  (cd "$REPO" && go build -o "$osimage" ./runtime/images/dstack-os/tools/osimage)
fi

# 1. Signatures (supply-7): os-image.yml signs the disk tarball and the identity
# files keyless at its os-image-v<version> tag, and only for a commit on main.
# The identity is checked before it is unpacked, against any such tag; the
# version it names then fixes the tag both signatures must come from.
signer="https://github.com/$repo/.github/workflows/os-image.yml@refs/tags/os-image-v"
verify_signature() { # verify_signature FILE --certificate-identity[-regexp] VALUE
  local file=$1
  shift
  [[ -f $file.sigstore.json ]] ||
    die "no signature $file.sigstore.json: download it with the release asset (--allow-unsigned only for a local build)"
  cosign verify-blob --bundle "$file.sigstore.json" "$@" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$file" >/dev/null 2>"$work/cosign.err" ||
    die "$file is not signed by os-image.yml of $repo ($*): $(cat "$work/cosign.err")"
}
if [[ $allow_unsigned == 1 ]]; then
  log "WARNING: --allow-unsigned: the tarball and identity signatures are NOT checked; never register this image for production"
else
  verify_signature "$identity_in" --certificate-identity-regexp "^${signer//./\\.}[0-9A-Za-z.+_-]+\$"
fi

# 2. Identity of the image, and the tarball it vouches for.
mkdir -p "$work/identity"
case $identity_in in
  *.tar.gz) tar -xzf "$identity_in" -C "$work/identity" ;;
  *.json) cp "$identity_in" "$work/identity/image-identity.json" ;;
  *) die "--identity must be the -identity.tar.gz or -identity.json release asset" ;;
esac
identity="$work/identity/image-identity.json"
[[ -f $identity ]] || die "no image-identity.json in $identity_in"
# json_field FILE a.b.c prints that string field of a JSON file.
json_field() {
  python3 -I -c '
import json, sys
v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    v = v[k]
print(v)' "$1" "$2"
}
name=$(json_field "$identity" name)
variant=$(json_field "$identity" variant)
version=$(json_field "$identity" sealedOsVersion)
os_image_hash=$(json_field "$identity" osImageHash)
want_sha=$(json_field "$identity" gceTarball.sha256)
if [[ $allow_unsigned == 0 ]]; then
  [[ $version =~ ^[0-9A-Za-z.+_-]+$ ]] || die "the identity names an invalid version $version"
  verify_signature "$identity_in" --certificate-identity "$signer$version"
  verify_signature "$tarball" --certificate-identity "$signer$version"
  log "signed by os-image.yml of $repo at os-image-v$version"
fi
got_sha=$(sha256 "$tarball")
[[ $got_sha == "$want_sha" ]] || die "tarball sha256 $got_sha does not match the identity's $want_sha"
log "image $name $version ($variant), os_image_hash $os_image_hash, tarball sha256 $got_sha"

image_name=${image_name:-$(echo "$name-$version" | tr 'A-Z.+_' 'a-z---')}
version_label=$(echo "$version" | tr 'A-Z.+' 'a-z--')
run_id=$("$osimage" nonce | cut -c1-8)
created_instances=()
created_images=()
created_objects=()

cleanup() {
  local status=$? i
  if [[ $keep == 1 ]]; then
    log "--keep: leaving instances ${created_instances[*]:-none}, images ${created_images[*]:-none}"
    exit "$status"
  fi
  for i in "${created_instances[@]:-}"; do
    [[ -n $i ]] && gc compute instances delete "$i" --project "$project" --zone "$zone" --quiet >/dev/null 2>&1 || true
  done
  for i in "${created_images[@]:-}"; do
    [[ -n $i ]] && gc compute images delete "$i" --project "$project" --quiet >/dev/null 2>&1 || true
  done
  for i in "${created_objects[@]:-}"; do
    [[ -n $i ]] && gc storage rm "$i" --project "$project" >/dev/null 2>&1 || true
  done
  exit "$status"
}
trap cleanup EXIT

# Import the boot image unless an image of that name already holds this tarball.
existing=
if [[ $dry_run == 0 ]]; then
  existing=$(gcloud compute images describe "$image_name" --project "$project" --format='value(description)' 2>/dev/null || true)
fi
if [[ -n $existing ]]; then
  [[ $existing == *"sha256=$want_sha"* ]] || die "image $image_name exists but was not made from this tarball ($existing)"
  log "reusing image $image_name"
else
  object="$bucket/sealed-os/$image_name.tar.gz"
  gc storage cp "$tarball" "$object" --project "$project"
  gc compute images create "$image_name" --project "$project" --source-uri "$object" \
    --guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC \
    --labels="sealed-os=$variant,sealed-os-version=$version_label" \
    --description="Sealed dstack OS $name $version ($variant). os_image_hash=$os_image_hash sha256=$want_sha"
  log "imported $image_name; it stays in the project for deployments"
fi

# 3. Auxiliary disks.
nonce=$("$osimage" nonce)
mkdir -p "$work/data" "$work/shared" "$work/files"
zero_file "$work/data/disk.raw" 10
sgdisk -o -n 1:0:0 -c 1:dstack-data "$work/data/disk.raw" >/dev/null
"$osimage" compose -report-data "$nonce" > "$work/files/app-compose.json"
"$osimage" sys-config -identity "$identity" > "$work/files/.sys-config.json"
zero_file "$work/shared/disk.raw" 64
mformat -i "$work/shared/disk.raw" -F -v DSTACKSHR -T 131072 -h 64 -s 32 ::
mcopy -i "$work/shared/disk.raw" "$work/files/app-compose.json" "$work/files/.sys-config.json" ::
gce_tar "$work/data" "$work/data.tar.gz"
gce_tar "$work/shared" "$work/shared.tar.gz"
data_image="sealed-measure-data-$run_id"
shared_image="sealed-measure-shared-$run_id"
for pair in "$data_image:$work/data.tar.gz" "$shared_image:$work/shared.tar.gz"; do
  img=${pair%%:*} file=${pair#*:}
  gc storage cp "$file" "$bucket/sealed-os/$img.tar.gz" --project "$project"
  created_objects+=("$bucket/sealed-os/$img.tar.gz")
  gc compute images create "$img" --project "$project" --source-uri "$bucket/sealed-os/$img.tar.gz" \
    --guest-os-features=GVNIC --labels="purpose=sealed-os-measure"
  created_images+=("$img")
done

# 4. Boots.
net_flags=()
[[ -n $network ]] && net_flags+=(--network "$network")
[[ -n $subnet ]] && net_flags+=(--subnet "$subnet")
results=()
IFS=, read -r -a types <<< "$machine_types"
for mt in "${types[@]}"; do
  [[ $mt =~ ^[a-z0-9-]+$ ]] || die "bad machine type $mt"
  b=1
  while [[ $b -le $boots ]]; do
    vm="sealed-measure-$run_id-$mt-$b"
    log "boot $b/$boots on $mt: $vm"
    gc compute instances create "$vm" --project "$project" --zone "$zone" --machine-type "$mt" \
      --confidential-compute-type=TDX --maintenance-policy=TERMINATE \
      --image "$image_name" --image-project "$project" --boot-disk-size=10GB --boot-disk-type=pd-balanced \
      --create-disk="name=$vm-data,size=10GB,type=pd-balanced,image=$data_image,image-project=$project,auto-delete=yes" \
      --create-disk="name=$vm-shared,size=1GB,type=pd-balanced,image=$shared_image,image-project=$project,auto-delete=yes" \
      --no-service-account --no-scopes --no-address \
      --shielded-vtpm --no-shielded-secure-boot \
      --metadata=block-project-ssh-keys=TRUE,enable-oslogin=FALSE \
      --labels="purpose=sealed-os-measure" "${net_flags[@]+"${net_flags[@]}"}"
    created_instances+=("$vm")
    serial="$work/$mt-$b.serial.txt"
    if [[ $dry_run == 1 ]]; then
      log "dry run: would poll the serial console of $vm and run osimage measure"
      b=$((b + 1))
      continue
    fi
    deadline=$(( $(date +%s) + timeout ))
    while :; do
      gcloud compute instances get-serial-port-output "$vm" --project "$project" --zone "$zone" \
        --start=0 > "$serial" 2>/dev/null || true
      if grep -q 'SEALED-MEASURE END ' "$serial"; then break; fi
      if grep -q 'SEALED-MEASURE FAIL' "$serial"; then die "measurement boot failed; serial output in $serial"; fi
      [[ $(date +%s) -lt $deadline ]] || die "no measurement after ${timeout}s; serial output in $serial"
      sleep 15
    done
    mkdir -p "$work/$mt-$b"
    "$osimage" measure -serial "$serial" -report-data "$nonce" -identity "$identity" \
      -machine-type "$mt" -zone "$zone" -boot "$b" -collateral-dir "$work/pcs" -save "$work/$mt-$b" \
      > "$work/$mt-$b.json"
    results+=(-boot "$work/$mt-$b.json")
    log "measured $mt boot $b: measurementsHash $(json_field "$work/$mt-$b.json" measurementsHash)"
    gc compute instances delete "$vm" --project "$project" --zone "$zone" --quiet
    b=$((b + 1))
  done
done

if [[ $dry_run == 1 ]]; then
  log "dry run complete; nothing was created"
  exit 0
fi

# 5. Catalog entries.
out=${out:-$SELF/measurements/$name-$version.json}
mkdir -p "$(dirname "$out")"
uri_flags=(-release-base "$release_base")
[[ -n $source_uri ]] && uri_flags=(-source-uri "$source_uri")
"$osimage" image-json -identity "$identity" "${uri_flags[@]}" "${results[@]}" > "$out"
log "wrote $out (raw quotes, event logs and Intel collateral in $work)"
cat "$out"
