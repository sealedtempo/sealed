#!/usr/bin/env bash
# Spend guard (spec rule 5, R5): refuse a mainnet transaction that would push the ledger total past the
# $50 run cap, and refuse any non-acceptance transaction once the total has reached the $40 warning line
# (at $40, only acceptance-test transactions are sent). The value-moving release scripts call this before
# anything is sent; release.yml passes the total in through the SEALED_LEDGER_TOTAL_USD repo variable.
#
#   scripts/release/check-budget.sh [--cost <usd>] [--acceptance]
#
# --cost <usd>   the transaction's estimated cost in USD (fees plus any amount moved); default 0.
# --acceptance   this is an acceptance-test transaction, so it is allowed above the $40 warning line
#                (spec 10 and the MAINNET_LEDGER rules). Registration and release transactions are not.
#
# The running total is read from SEALED_LEDGER_TOTAL_USD when that is set, otherwise from LEDGER_FILE
# (docs/MAINNET_LEDGER.md in the private repo): the sum of the fee and amount columns of every table row,
# the same number tests/acceptance/lib/ledger.ts computes and gate.ts guards. A LEDGER_FILE that is set
# but missing is a hard error (fail closed). With neither set, the total is treated as $0 and a warning is
# printed, for a local dry run with no ledger wired in.
#
# Caps: SPEND_CAP_USD (default 50), SPEND_WARN_USD (default 40).
# Exit codes: 0 within budget, 2 usage, 3 refused.

# shellcheck source=scripts/release/lib.sh
. "$(dirname "$0")/lib.sh"

usage() {
	sed -n '8,9p' "$0" >&2
	exit 2
}

COST=0 ACCEPTANCE=0
while [ $# -gt 0 ]; do
	case "$1" in
	--cost) COST="${2:-}"; shift 2 ;;
	--acceptance) ACCEPTANCE=1; shift ;;
	-h | --help) usage ;;
	*) log "unknown argument: $1"; usage ;;
	esac
done
[[ "$COST" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "--cost must be a non-negative USD amount, got '$COST'" 2

CAP="${SPEND_CAP_USD:-50}"
WARN="${SPEND_WARN_USD:-40}"
[[ "$CAP" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "SPEND_CAP_USD must be a USD amount, got '$CAP'" 2
[[ "$WARN" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "SPEND_WARN_USD must be a USD amount, got '$WARN'" 2

# ledger_total <file>: the sum of the fee and amount columns of the MAINNET_LEDGER.md table, by column
# name (parseLedger in tests/acceptance/lib/ledger.ts). Separator rows and the running-total line are
# ignored; a cell of "0" or "-" counts as zero.
ledger_total() {
	awk -F'|' '
		function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
		function money(s,  m) { m = s; gsub(/[$, \t]/, "", m); if (m == "" || m == "-") return 0; return m + 0 }
		/^[[:space:]]*\|/ {
			n = 0
			for (i = 2; i < NF; i++) { cell[++n] = trim($i) }
			if (!have) {
				for (i = 1; i <= n; i++) {
					lc = tolower(cell[i])
					if (lc ~ /^fee/) iFee = i
					if (lc ~ /^amount/) iAmt = i
				}
				if (iFee && iAmt) have = 1
				next
			}
			sep = 1
			for (i = 1; i <= n; i++) if (cell[i] !~ /^:?-{3,}:?$/) sep = 0
			if (sep) next
			total += money(cell[iFee]) + money(cell[iAmt])
		}
		END { if (!have) { print "NO_TABLE"; exit 0 } printf "%.6f\n", total }
	' "$1"
}

SOURCE=""
if [ -n "${SEALED_LEDGER_TOTAL_USD:-}" ]; then
	TOTAL="$SEALED_LEDGER_TOTAL_USD"
	[[ "$TOTAL" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "SEALED_LEDGER_TOTAL_USD must be a USD amount, got '$TOTAL'" 2
	SOURCE="SEALED_LEDGER_TOTAL_USD"
elif [ -n "${LEDGER_FILE:-}" ]; then
	[ -f "$LEDGER_FILE" ] || die "LEDGER_FILE=$LEDGER_FILE does not exist; point it at docs/MAINNET_LEDGER.md" 2
	TOTAL="$(ledger_total "$LEDGER_FILE")"
	[ "$TOTAL" != "NO_TABLE" ] || die "LEDGER_FILE=$LEDGER_FILE has no transaction table to total" 2
	SOURCE="$LEDGER_FILE"
else
	TOTAL=0
	log "warn no SEALED_LEDGER_TOTAL_USD and no LEDGER_FILE; treating the mainnet ledger total as \$0"
	SOURCE="(none)"
fi

# fcmp <a> <op> <b>: float comparison through awk (op is gt or ge). Prints 1 when it holds, else 0.
fcmp() { awk -v a="$1" -v b="$3" -v op="$2" 'BEGIN { print (op == "gt" ? (a > b) : (a >= b)) ? 1 : 0 }'; }

AFTER="$(awk -v t="$TOTAL" -v c="$COST" 'BEGIN { printf "%.6f", t + c }')"
if [ "$(fcmp "$AFTER" gt "$CAP")" = 1 ]; then
	die "refused: ledger total \$$TOTAL plus this transaction (\$$COST) is \$$AFTER, over the \$$CAP cap (source: $SOURCE). Raise SPEND_CAP_USD only with the operator's approval; see docs/MAINNET_LEDGER.md." 3
fi
if [ "$ACCEPTANCE" != 1 ] && [ "$(fcmp "$TOTAL" ge "$WARN")" = 1 ]; then
	die "refused: ledger total \$$TOTAL has reached the \$$WARN line (source: $SOURCE); only acceptance-test transactions are sent past it (spec rule 5). This is not an acceptance transaction." 3
fi
if [ "$(fcmp "$TOTAL" ge "$WARN")" = 1 ]; then
	log "ok   budget: ledger total \$$TOTAL past \$$WARN, acceptance transaction allowed (\$$AFTER of \$$CAP; source: $SOURCE)"
else
	log "ok   budget: ledger total \$$TOTAL plus \$$COST is \$$AFTER of the \$$CAP cap (source: $SOURCE)"
fi
