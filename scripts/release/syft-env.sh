# shellcheck shell=bash
# The one syft setup for every SBOM this repository makes (spec 6.8, license audit F5 and F6). Source it; do
# not run it. scan-image.sh (release, catalog and image workflows) and the lint fixture generator
# (runtime/composer/lint/testdata/syft-image/make-image-sbom.sh) both source it, and
# catalog/tools/release/syftenv_test.go fails if the two resolve to different settings.
#
# The caller's SYFT_* variables are dropped first (registry access, SYFT_REGISTRY_*, excepted), so a shell or
# runner cannot change what an SBOM lists. Then, for every scan:
#   SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true, SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true  Go module
#       licenses from the local module cache, else from the module proxy. Without them every module of a Go
#       binary is NOASSERTION, which release lint refuses (F5). The runner's cache holds only this
#       repository's modules, not those of upstream binaries such as gosu (postgres) or ollama.
#   SYFT_GOLANG_PROXY=https://proxy.golang.org, SYFT_GOLANG_NO_PROXY=""  the public proxy only: no "direct"
#       repository clones, and GOPROXY or GONOPROXY in the environment do not apply (GOPROXY=off would make
#       syft clone every module's repository).
#   SYFT_GOLANG_MAIN_MODULE_VERSION_FROM_CONTENTS=true  a main module built without version data (ollama:
#       -trimpath, no VCS stamp) gets the version string the binary carries (v0.40.12), so a reviewed license
#       override can name that exact version (D-071) and Grype can match it. It finds none in this
#       repository's binaries, which stay without a version.
#   SYFT_CHECK_FOR_APP_UPDATE=false  no update check.
#
# Two scans of an image use these settings:
#   sealed_syft_sbom   the SBOM that ships (bundle sbom/<image>.spdx.json, release asset, Grype input): the
#                      files a package owns, with sha1 and sha256 digests.
#   sealed_syft_files  every file of the image, without digests, for lint's excluded-path check: the trees
#                      no package owns (/app/enterprise, ToolJet's ee/ directories, /usr/lib/ollama/cuda_v12,
#                      ms-playwright/chromium-*, F6). It does not ship: the ToolJet image lists about 157,000
#                      files, 83 MB of SPDX JSON, over the bundle's 32 MiB file limit. The lint fixture is
#                      made with this one.

_sealed_syft_drop="$(compgen -e | grep '^SYFT_' | grep -v '^SYFT_REGISTRY_' || true)"
for _v in $_sealed_syft_drop; do unset "$_v"; done
unset _v _sealed_syft_drop

export SYFT_CHECK_FOR_APP_UPDATE=false
export SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true
export SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true
export SYFT_GOLANG_PROXY=https://proxy.golang.org
export SYFT_GOLANG_NO_PROXY=""
export SYFT_GOLANG_MAIN_MODULE_VERSION_FROM_CONTENTS=true

# sealed_syft_sbom <source> [syft flags...]: the shipped SBOM of a linux/amd64 image (the only platform the
# VMs run), without progress output.
sealed_syft_sbom() {
	SYFT_FILE_METADATA_SELECTION=owned-by-package SYFT_FILE_METADATA_DIGESTS=sha1,sha256 \
		syft scan "$1" --platform linux/amd64 "${@:2}" -q
}

# sealed_syft_files <source> [syft flags...]: the every-file listing of the same image, for lint.
sealed_syft_files() {
	SYFT_FILE_METADATA_SELECTION=all SYFT_FILE_METADATA_DIGESTS="" \
		syft scan "$1" --platform linux/amd64 "${@:2}" -q
}
