#!/usr/bin/env bash
# Register catalog apps in AppRegistry and platform images in PlatformRegistry as OWNER with
# contracts/script/RegisterCatalog.s.sol. OWNER runs this on their own machine. It never runs in CI (spec 6.8: new
# apps need registerApp from OWNER).
#
#   scripts/release/register-apps.sh [--apps <id,id> | --images-only] [--images <file>]... [--catalog <file>] [--broadcast] [--yes]
#
# Without --broadcast it is a dry run: it prints the plan and lets forge simulate the registrations; nothing
# is sent. With --broadcast it asks for confirmation (skip with --yes), makes sure OWNER's FeeManager fee token
# preference is FEE_TOKEN (D-038), broadcasts with FOUNDRY_PROFILE=deploy (EIP-1559 transactions whose fees
# FeeManager takes in that token, D-038), then checks that every app and image is registered and prints the
# MAINNET_LEDGER.md rows. Apps and images that are already registered are skipped, so re-running is safe.
#
# Apps. On Tempo mainnet (chain 4217) they come from the reviewed RegisterCatalog input,
# contracts/catalog/catalog.mainnet.json (CatalogMainnet.t.sol pins it): blob metadataURIs, every maintainer
# written out, registered in file order so appAt(i) follows the file. The file must pass script/check-catalog.sh
# against catalog/apps (CATALOG_STRICT=1), and its _network block must name this chain and these registries.
# --catalog <file> picks another reviewed file, on any chain. Elsewhere (local chains) the apps are generated from
# catalog/apps/*/manifest.yaml (catalog/tools/release catalog-json: tree metadataURIs, the payout address unless it
# is ${MAINTAINER_DEFAULT_ADDRESS}). --apps selects some apps; from a reviewed file it must not register an app
# before an earlier unregistered app of the file. --images-only registers no app.
#
# Images. --images adds platform images (addImage) and may be given once per file: one measurements file per
# machine shape of the same OS image (D-070, D-078), and the debug image's file. Each file is what
# runtime/images/dstack-os/import-and-measure.sh writes ({"images": [...], "sealed": {...}}) or a bare JSON array
# of RegisterCatalog image entries. Before anything is sent, every entry must be well formed with
# imageId = keccak256(abi.encode(name, version, measurementsHash)) (D-008); identical entries are merged; the same
# name and version with two measurement sets (a shape that did not measure the same twice) is refused; and entries
# of one OS image must agree on everything but MRTD and RTMR0. Two shapes that measured the same values share one
# image: PlatformRegistry keeps one per measurement set, so the later entry is skipped.
#
# Environment (OWNER_PRIVATE_KEY, MAINTAINER_DEFAULT_ADDRESS and TEMPO_RPC_URL are read from SEALED_ENV,
# default ../.env next to the repository, when they are not already set; nothing is printed):
#   OWNER_PRIVATE_KEY, MAINTAINER_DEFAULT_ADDRESS (generated apps only), TEMPO_RPC_URL (default chain.public_rpc_url)
#   EXPECT_CHAIN_ID     default chain.chain_id (4217)
#   CONTRACTS_DIR       default contracts
#   DEPLOYMENTS_FILE    default $CONTRACTS_DIR/deployments/tempo-mainnet.json (must be under $CONTRACTS_DIR/deployments)

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

usage() {
	sed -n '2,6p' "$0" >&2
	exit 2
}

APPS="" APPS_SET=0 CATALOG="" IMAGES_ONLY=0 BROADCAST=0 YES=0
IMAGES=()
while [ $# -gt 0 ]; do
	case "$1" in
	--apps) APPS="${2:-}" APPS_SET=1; shift 2 ;;
	--images)
		[ -n "${2:-}" ] || usage
		IMAGES+=("$2")
		shift 2
		;;
	--images-only) IMAGES_ONLY=1; shift ;;
	--catalog)
		[ -n "${2:-}" ] || usage
		CATALOG="$2"
		shift 2
		;;
	--broadcast) BROADCAST=1; shift ;;
	--yes) YES=1; shift ;;
	-h | --help) usage ;;
	*) log "unknown argument: $1"; usage ;;
	esac
done
if [ "$IMAGES_ONLY" = 1 ]; then
	[ "$APPS_SET" = 0 ] || die "--images-only and --apps exclude each other" 2
	[ "${#IMAGES[@]}" -gt 0 ] || die "--images-only needs --images" 2
fi
need cast
need forge
need jq

# Read only the variables this script needs from the env file, without sourcing it (no code runs, and
# variables already set in the environment win).
load_env_file() {
	local file="$1" line key val
	[ -f "$file" ] || return 0
	while IFS= read -r line || [ -n "$line" ]; do
		line="${line%$'\r'}"
		case "$line" in
		OWNER_PRIVATE_KEY=* | MAINTAINER_DEFAULT_ADDRESS=* | TEMPO_RPC_URL=*) ;;
		*) continue ;;
		esac
		key="${line%%=*}"
		val="${line#*=}"
		val="${val#\"}" && val="${val%\"}"
		val="${val#\'}" && val="${val%\'}"
		if [ -z "${!key:-}" ] && [ -n "$val" ]; then export "$key=$val"; fi
	done <"$file"
}
load_env_file "${SEALED_ENV:-$RELEASE_ROOT/../.env}"

RPC="${TEMPO_RPC_URL:-$(defaults_get publicRpcUrl)}"
EXPECT_CHAIN_ID="${EXPECT_CHAIN_ID:-$(defaults_get chainId)}"
CONTRACTS_DIR="$(cd "${CONTRACTS_DIR:-$RELEASE_ROOT/contracts}" && pwd)"
DEPLOYMENTS_FILE="${DEPLOYMENTS_FILE:-$CONTRACTS_DIR/deployments/tempo-mainnet.json}"
DEPLOYMENTS_FILE="$(cd "$(dirname "$DEPLOYMENTS_FILE")" && pwd)/$(basename "$DEPLOYMENTS_FILE")"
case "$DEPLOYMENTS_FILE" in
"$CONTRACTS_DIR"/deployments/*) DEPLOYMENTS_REL="${DEPLOYMENTS_FILE#"$CONTRACTS_DIR"/}" ;;
*) die "DEPLOYMENTS_FILE must be under $CONTRACTS_DIR/deployments (forge may only read there)" 2 ;;
esac
[ -f "$DEPLOYMENTS_FILE" ] || die "deployments file $DEPLOYMENTS_FILE not found"
FEE_TOKEN="${FEE_TOKEN_ADDRESS:-$(jq -r '.config.feeToken // empty' "$DEPLOYMENTS_FILE")}"
FEE_TOKEN="$(printf '%s' "${FEE_TOKEN:-$(defaults_get feeToken)}" | lower)"

check_chain
refuse_ci_unless_local
REGISTRY="$(deployments_addr AppRegistry)"
require_code "$REGISTRY" AppRegistry
PLATFORM="$(deployments_addr PlatformRegistry)"
require_code "$PLATFORM" PlatformRegistry
make_keystore OWNER_PRIVATE_KEY
OWNER="$KS_ADDR"
# forge reads both from its environment (vm.envUint, vm.envOr); never from the command line.
export OWNER_PRIVATE_KEY
if [ -n "${MAINTAINER_DEFAULT_ADDRESS:-}" ]; then export MAINTAINER_DEFAULT_ADDRESS; else unset MAINTAINER_DEFAULT_ADDRESS; fi
owner_onchain="$(ccall "$REGISTRY" 'owner()(address)' | lower)"
[ "$owner_onchain" = "$OWNER" ] || die "OWNER_PRIVATE_KEY is $OWNER, but AppRegistry is owned by $owner_onchain" 3
log "ok   chain $CHAIN_ID, AppRegistry $REGISTRY, owner $OWNER"

# On mainnet the apps come from the reviewed file, never from the manifests (mainnet-rehearsal.md finding 3.2).
if [ -z "$CATALOG" ] && [ "$CHAIN_ID" = 4217 ] && [ "$IMAGES_ONLY" = 0 ]; then
	CATALOG="$CONTRACTS_DIR/catalog/catalog.mainnet.json"
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/register-apps.XXXXXX")"
add_cleanup "rm -rf '$WORK_DIR'"

# merge_images <out> <file>...: the image entries of every file, checked, as one JSON array sorted by name and
# version. Exits 2 when a file or an entry is malformed or two entries conflict.
merge_images() {
	local out="$1" f list bad n i e mh id given
	shift
	echo '[]' >"$out"
	for f in "$@"; do
		[ -f "$f" ] || die "--images: $f not found" 2
		list="$WORK_DIR/images.$((++_IMG_FILES)).json"
		jq -e 'if type == "array" then . elif type == "object" and (.images | type) == "array" then .images
			else error("want a JSON array of images or an object with an images array") end' "$f" >"$list" 2>/dev/null ||
			die "--images: $f is neither a JSON array of RegisterCatalog images nor an image measurements file" 2
		bad="$(jq -r --arg f "$f" '
			def mr: type == "string" and test("^0x[0-9a-fA-F]{96}$");
			def str: type == "string" and length > 0;
			to_entries[] | .key as $i | .value
			| if type != "object" then "\($f): images[\($i)] is not an object" else
				(if (.name | str) and (.version | str) then empty else "\($f): images[\($i)] needs name and version" end),
				(["mrtd", "rtmr0", "rtmr1", "rtmr2"][] as $k
					| if (.[$k] | mr) then empty else "\($f): images[\($i)].\($k) is not 48 bytes of hex" end),
				(if (.isDebug | type) == "boolean" then empty else "\($f): images[\($i)].isDebug is not a boolean" end),
				(if (.sourceURI | str) then empty else "\($f): images[\($i)] needs sourceURI" end)
			end' "$list")"
		[ -z "$bad" ] || die "--images: $bad" 2
		n="$(jq length "$list")"
		for ((i = 0; i < n; i++)); do
			e="$(jq -c ".[$i]" "$list")"
			# shellcheck disable=SC2046 # four hex words
			mh="$(cast keccak "$(cast concat-hex $(jq -r '.mrtd, .rtmr0, .rtmr1, .rtmr2' <<<"$e"))")"
			id="$(cast keccak "$(cast abi-encode 'f(string,string,bytes32)' "$(jq -r .name <<<"$e")" "$(jq -r .version <<<"$e")" "$mh")")"
			given="$(jq -r '.measurementsHash // empty' <<<"$e" | lower)"
			[ -z "$given" ] || [ "$given" = "$mh" ] ||
				die "--images: $f: images[$i] measurementsHash $given is not keccak256(mrtd, rtmr0, rtmr1, rtmr2) = $mh" 2
			given="$(jq -r '.imageId // empty' <<<"$e" | lower)"
			[ -z "$given" ] || [ "$given" = "$id" ] ||
				die "--images: $f: images[$i] imageId $given is not keccak256(abi.encode(name, version, measurementsHash)) = $id" 2
			jq --argjson e "$e" --arg mh "$mh" --arg id "$id" --arg f "$f" \
				'. + [$e + {imageId: $id, measurementsHash: $mh, _file: $f}]' "$out" >"$out.new"
			mv "$out.new" "$out"
		done
	done
	bad="$(jq -r '
		def lc: if type == "string" then ascii_downcase else . end;
		(group_by(.imageId)[] | select((map([.isDebug, .sourceURI]) | unique | length) > 1)
			| "\(.[0].name) \(.[0].version) (\(.[0].imageId)) has another isDebug or sourceURI in \(map(._file) | unique | join(" and "))"),
		(group_by([.name, .version])[] | select((map(.measurementsHash) | unique | length) > 1)
			| "\(.[0].name) \(.[0].version) has two measurement sets (\(map(._file) | unique | join(", "))): the machine shape did not measure the same twice; measure it again (D-078)"),
		(group_by([.name, (.osImageHash // .sourceURI | lc)])[] | select(length > 1) | . as $g
			| ("isDebug", "sourceURI", "rtmr1", "rtmr2", "gceTarballSha256")
			| . as $k | select(($g | map(.[$k] | lc) | unique | length) > 1)
			| "\($g[0].name) entries \($g | map(.version) | unique | join(", ")) are one OS image but differ in \($k); only MRTD and RTMR0 may differ (D-070)")
		' "$out")"
	[ -z "$bad" ] || die "--images: $bad" 2
	jq -r 'group_by([.name, (.osImageHash // .sourceURI | ascii_downcase)])[] | select(length > 1)
		| select((map(.mrtd | ascii_downcase) | unique | length) > 1)
		| "warn MRTD differs between \(map(.version) | unique | join(", ")): was the Google firmware updated between the measurements? Re-measure every shape (D-070)"' \
		"$out" >&2
	jq -r 'group_by(.measurementsHash)[] | select((map(.imageId) | unique | length) > 1)
		| "note \(map(.version) | unique | join(" and ")) measured the same values: one image, the later entry is skipped"' \
		"$out" >&2
	jq 'unique_by(.imageId) | map(del(._file)) | sort_by(.name, .version)' "$out" >"$out.new"
	mv "$out.new" "$out"
}
_IMG_FILES=0
images_list="$WORK_DIR/images.json"
merge_images "$images_list" ${IMAGES[@]+"${IMAGES[@]}"}

# reviewed_apps <file> <out>: the selected apps of a reviewed RegisterCatalog input, in file order.
reviewed_apps() {
	local file="$1" out="$2" v slug id state blocked="" selected
	[ -f "$file" ] || die "--catalog: $file not found" 2
	jq -e '(.apps | type) == "array"' "$file" >/dev/null 2>&1 || die "--catalog: $file has no apps array" 2
	jq -e '(.images // []) | length == 0' "$file" >/dev/null ||
		die "--catalog: $file lists images; register images from their measurements files with --images" 2
	v="$(jq -r '._network.chainId // empty' "$file")"
	[ -z "$v" ] || [ "$v" = "$CHAIN_ID" ] || die "--catalog: $file is for chain $v, not $CHAIN_ID" 2
	v="$(jq -r '._network.AppRegistry // empty' "$file" | lower)"
	[ -z "$v" ] || [ "$v" = "$REGISTRY" ] || die "--catalog: $file names AppRegistry $v, not $REGISTRY" 2
	v="$(jq -r '._network.PlatformRegistry // empty' "$file" | lower)"
	[ -z "$v" ] || [ "$v" = "$PLATFORM" ] || die "--catalog: $file names PlatformRegistry $v, not $PLATFORM" 2
	CATALOG_STRICT=1 "$CONTRACTS_DIR/script/check-catalog.sh" "$file" "$RELEASE_ROOT/catalog/apps" >&2 ||
		die "--catalog: $file does not pass contracts/script/check-catalog.sh" 2
	selected=",$(printf '%s' "$APPS" | tr -d ' '),"
	if [ "$APPS_SET" = 1 ]; then
		for slug in $(printf '%s' "$APPS" | tr ',' ' '); do
			jq -e --arg s "$slug" 'any(.apps[]; .slug == $s)' "$file" >/dev/null || die "--apps: no app $slug in $file" 2
		done
	fi
	echo '[]' >"$out"
	for slug in $(jq -r '.apps[].slug' "$file"); do
		id="$(cast keccak "$slug")"
		state="$(ccall "$REGISTRY" 'appExists(bytes32)(bool)' "$id")"
		case "$selected" in
		*",$slug,"*) ;;
		*)
			if [ "$APPS_SET" = 1 ]; then
				[ "$state" = true ] || blocked="$blocked $slug"
				continue
			fi
			;;
		esac
		[ "$state" = true ] || [ -z "$blocked" ] ||
			die "--apps: $slug comes after${blocked} in $file, which are not registered; register them first or together, so appAt(i) follows the file" 2
		jq --arg s "$slug" --slurpfile c "$file" '. + [$c[0].apps[] | select(.slug == $s)]' "$out" >"$out.new"
		mv "$out.new" "$out"
	done
}

apps_list="$WORK_DIR/apps.json"
if [ "$IMAGES_ONLY" = 1 ]; then
	echo '[]' >"$apps_list"
	log "apps: none (--images-only)"
elif [ -n "$CATALOG" ]; then
	CATALOG="$(cd "$(dirname "$CATALOG")" && pwd)/$(basename "$CATALOG")"
	reviewed_apps "$CATALOG" "$apps_list"
	# Every maintainer is in the reviewed file; nothing may fall back to a default.
	unset MAINTAINER_DEFAULT_ADDRESS
	log "apps: from $CATALOG"
else
	args=()
	[ -n "$APPS" ] && args+=(--apps "$APPS")
	release_tool catalog-json ${args[@]+"${args[@]}"} | jq '.apps' >"$apps_list"
	log "apps: generated from catalog/apps/*/manifest.yaml"
fi

# The catalog file must be readable by forge: contracts/foundry.toml allows reads under ./catalog only.
CATALOG_REL="catalog/.register-apps.$$.json"
add_cleanup "rm -f '$CONTRACTS_DIR/$CATALOG_REL'"
jq -n --slurpfile i "$images_list" --slurpfile a "$apps_list" \
	'{_comment: "Generated by scripts/release/register-apps.sh. Not committed.", images: $i[0], apps: $a[0]}' \
	>"$CONTRACTS_DIR/$CATALOG_REL"

pending=()
if [ "$IMAGES_ONLY" = 0 ]; then
	log ""
	log "app                  registered  license          share  maintainer"
	while IFS=$'\t' read -r slug license share maint; do
		state="no"
		if [ "$(ccall "$REGISTRY" 'appExists(bytes32)(bool)' "$(cast keccak "$slug")")" = "true" ]; then
			state="yes"
		else
			pending+=("$slug")
			if [ "$maint" = "default" ]; then
				[[ "${MAINTAINER_DEFAULT_ADDRESS:-}" =~ ^0x[0-9a-fA-F]{40}$ ]] ||
					die "$slug uses MAINTAINER_DEFAULT_ADDRESS, which is not set to an address"
				maint="${MAINTAINER_DEFAULT_ADDRESS} (default)"
			fi
		fi
		printf '%-20s %-11s %-16s %-6s %s\n' "$slug" "$state" "$license" "$share" "$maint" >&2
	done < <(jq -r '.[] | [.slug, .licenseSpdx, (.maintainerShareBps|tostring), (.maintainer // "default")] | @tsv' "$apps_list")
fi
images_pending=0
n_images="$(jq length "$images_list")"
if [ "$n_images" -gt 0 ]; then
	log ""
	log "image                                              registered  imageId"
	while IFS=$'\t' read -r name version id mh; do
		state="no"
		if [ "$(ccall "$PLATFORM" 'imageStatus(bytes32)(uint8)' "$id")" != 0 ]; then
			state="yes"
		elif [ "$(ccall "$PLATFORM" 'imageByMeasurements(bytes32)(bytes32)' "$mh")" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
			state="as other"
		else
			images_pending=$((images_pending + 1))
		fi
		printf '%-50s %-11s %s\n' "$name $version" "$state" "$id" >&2
	done < <(jq -r '.[] | [.name, .version, .imageId, .measurementsHash] | @tsv' "$images_list")
fi
log ""
if [ "${#pending[@]}" -eq 0 ] && [ "$images_pending" = 0 ]; then
	log "nothing to register"
	exit 0
fi
log "to register: ${pending[*]:-no apps}, and $images_pending of $n_images platform image entries"

forge_env=(env CATALOG_FILE="$CATALOG_REL" DEPLOYMENTS_FILE="$DEPLOYMENTS_REL" FOUNDRY_PROFILE=deploy)
if [ "$BROADCAST" != 1 ]; then
	DRY_RUN=1 ensure_fee_token "$OWNER"
	(cd "$CONTRACTS_DIR" && "${forge_env[@]}" forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url "$RPC") >&2 ||
		die "forge simulation failed"
	log "dry run: nothing sent. Re-run with --broadcast to register."
	exit 0
fi

if [ "$YES" != 1 ]; then
	printf 'Send the registrations on chain %s from %s? Type the chain id to continue: ' "$CHAIN_ID" "$OWNER" >&2
	read -r answer
	[ "$answer" = "$CHAIN_ID" ] || die "not confirmed; nothing sent"
fi
# Spend guard (R5, G26): registrations are not acceptance transactions, so they are refused once the
# ledger total reaches the $40 line, and never if they would cross the $50 cap. LEDGER_FILE points at the
# private repo's docs/MAINNET_LEDGER.md (or SEALED_LEDGER_TOTAL_USD gives the total directly).
"$(dirname "$0")/check-budget.sh"
ensure_fee_token "$OWNER"
(cd "$CONTRACTS_DIR" && "${forge_env[@]}" forge script script/RegisterCatalog.s.sol:RegisterCatalog --rpc-url "$RPC" \
	--broadcast --skip-simulation --slow) >&2 || die "forge broadcast failed (re-run to retry: registered apps are skipped)"

for slug in ${pending[@]+"${pending[@]}"}; do
	[ "$(ccall "$REGISTRY" 'appExists(bytes32)(bool)' "$(cast keccak "$slug")")" = "true" ] || die "$slug is still not registered"
	log "ok   $slug registered"
done
while IFS=$'\t' read -r name version id mh; do
	if [ "$(ccall "$PLATFORM" 'imageStatus(bytes32)(uint8)' "$id")" != 0 ]; then
		state="approved"
		[ "$(ccall "$PLATFORM" 'isApprovedImage(bytes32)(bool)' "$id")" = true ] || state="registered, not approved (debug)"
		log "ok   image $name $version $state ($id)"
	else
		got="$(ccall "$PLATFORM" 'imageByMeasurements(bytes32)(bytes32)' "$mh")"
		[ "$got" != "0x0000000000000000000000000000000000000000000000000000000000000000" ] ||
			die "image $name $version is still not registered"
		log "ok   image $name $version: its measurements are registered as $got"
	fi
done < <(jq -r '.[] | [.name, .version, .imageId, .measurementsHash] | @tsv' "$images_list")

# Ledger rows from forge's broadcast record (one per transaction).
run_file="$CONTRACTS_DIR/broadcast/RegisterCatalog.s.sol/$CHAIN_ID/run-latest.json"
if [ -f "$run_file" ]; then
	log ""
	log "MAINNET_LEDGER.md rows:"
	[ -n "$FEE_PREF_TX" ] && log "(setUserToken for OWNER: tx $FEE_PREF_TX)"
	n="$(jq '.receipts | length' "$run_file")"
	for ((i = 0; i < n; i++)); do
		rf="$(mktemp)"
		add_cleanup "rm -f '$rf'"
		jq ".receipts[$i]" "$run_file" >"$rf"
		what="$(jq -r --argjson i "$i" '.transactions[$i] | "\((.function // "call") | split("(")[0]) \(.arguments[1] // "")"' "$run_file")"
		to="$(jq -r '.to // empty' "$rf" | lower)"
		label=PlatformRegistry
		[ "$to" = "$REGISTRY" ] && label=AppRegistry
		ts="$(cast block "$(jq -r .blockNumber "$rf")" -f timestamp --rpc-url "$RPC")"
		release_tool tx-summary --receipt "$rf" --chain-id "$CHAIN_ID" --to "$to" --from-label OWNER \
			--to-label "$label" --purpose "$what" --timestamp "$ts" | jq -r .ledger
	done
fi
