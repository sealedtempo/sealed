package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// sampleLedger writes a MAINNET_LEDGER.md whose fee+amount columns sum to feeUSD+amountUSD, plus a couple
// of rows that must be ignored (the separator and the running-total line), so the test exercises the same
// column parsing tests/acceptance/lib/ledger.ts does.
func sampleLedger(t *testing.T, feeRow, amountRow string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "MAINNET_LEDGER.md")
	writeFile(t, p, strings.Join([]string{
		"# Tempo mainnet ledger",
		"",
		"| time (UTC) | from | to | purpose | tx hash | fee (USD) | amount (USD) |",
		"|---|---|---|---|---|---|---|",
		"| t | OWNER | A | deploy | [0xabc](u) | " + feeRow + " | 0 |",
		"| t | TEST_CUSTOMER | B | spend | [0xdef](u) | 0.000100 | " + amountRow + " |",
		"",
		"Running total: fees $x, amounts $y, total $z (cap $50).",
		"",
	}, "\n"))
	return p
}

// runBudget runs scripts/release/check-budget.sh from the real repo with env and arguments.
func runBudget(t *testing.T, env []string, args ...string) scriptResult {
	t.Helper()
	return runScript(t, "check-budget.sh", env, "", args...)
}

// TestCheckBudgetGuard proves the spend guard (R5, G26) refuses a transaction that would push the ledger
// past the $50 cap, and refuses any non-acceptance transaction once the total reaches the $40 line, from
// both a LEDGER_FILE total and the SEALED_LEDGER_TOTAL_USD variable release.yml passes.
func TestCheckBudgetGuard(t *testing.T) {
	// LEDGER_FILE: the total is the sum of the fee and amount columns (here 10.000100 + 5 = 15.000100).
	ledger := sampleLedger(t, "10.000000", "5.000000")
	r := runBudget(t, []string{"LEDGER_FILE=" + ledger}, "--cost", "1")
	if r.code != 0 || !strings.Contains(r.output, "ledger total $15.000100") {
		t.Fatalf("within budget from LEDGER_FILE: %d\n%s", r.code, r.output)
	}

	// A LEDGER_FILE that is set but missing fails closed (it must not silently treat the total as zero).
	r = runBudget(t, []string{"LEDGER_FILE=" + filepath.Join(t.TempDir(), "gone.md")})
	if r.code != 2 || !strings.Contains(r.output, "does not exist") {
		t.Fatalf("missing LEDGER_FILE must fail closed: %d\n%s", r.code, r.output)
	}

	// Over the $50 cap: a total plus cost that crosses it is refused (exit 3), and raising it is the
	// operator's call.
	over := sampleLedger(t, "49.900000", "0")
	r = runBudget(t, []string{"LEDGER_FILE=" + over}, "--cost", "0.2")
	if r.code != 3 || !strings.Contains(r.output, "over the $50 cap") {
		t.Fatalf("over the cap must be refused: %d\n%s", r.code, r.output)
	}
	// Same through the SEALED_LEDGER_TOTAL_USD variable (how release.yml supplies the total in CI).
	r = runBudget(t, []string{"SEALED_LEDGER_TOTAL_USD=50.5"})
	if r.code != 3 || !strings.Contains(r.output, "over the $50 cap") {
		t.Fatalf("over the cap via the variable must be refused: %d\n%s", r.code, r.output)
	}

	// At or above the $40 warning line only acceptance transactions go through.
	r = runBudget(t, []string{"SEALED_LEDGER_TOTAL_USD=41"})
	if r.code != 3 || !strings.Contains(r.output, "reached the $40 line") {
		t.Fatalf("a non-acceptance transaction above $40 must be refused: %d\n%s", r.code, r.output)
	}
	r = runBudget(t, []string{"SEALED_LEDGER_TOTAL_USD=41"}, "--acceptance")
	if r.code != 0 || !strings.Contains(r.output, "acceptance transaction allowed") {
		t.Fatalf("an acceptance transaction above $40 is allowed: %d\n%s", r.code, r.output)
	}
	// Exactly at $40 is already the line.
	r = runBudget(t, []string{"SEALED_LEDGER_TOTAL_USD=40"})
	if r.code != 3 || !strings.Contains(r.output, "reached the $40 line") {
		t.Fatalf("exactly $40 is the acceptance-only line: %d\n%s", r.code, r.output)
	}
	// An acceptance transaction is still refused if it would cross the $50 cap.
	r = runBudget(t, []string{"SEALED_LEDGER_TOTAL_USD=49.99"}, "--acceptance", "--cost", "0.5")
	if r.code != 3 || !strings.Contains(r.output, "over the $50 cap") {
		t.Fatalf("even acceptance must not cross the cap: %d\n%s", r.code, r.output)
	}

	// Below both lines a normal (non-acceptance) release transaction passes; today's real ledger is here.
	r = runBudget(t, []string{"SEALED_LEDGER_TOTAL_USD=0.025839"}, "--cost", "0.01")
	if r.code != 0 || !strings.Contains(r.output, "of the $50 cap") {
		t.Fatalf("a normal transaction well under the cap passes: %d\n%s", r.code, r.output)
	}

	// The caps are configurable (the operator may lower them), and a bad total is a usage error.
	r = runBudget(t, []string{"SEALED_LEDGER_TOTAL_USD=12", "SPEND_CAP_USD=10"}, "--acceptance")
	if r.code != 3 || !strings.Contains(r.output, "over the $10 cap") {
		t.Fatalf("SPEND_CAP_USD must be honoured: %d\n%s", r.code, r.output)
	}
	r = runBudget(t, []string{"SEALED_LEDGER_TOTAL_USD=notanumber"})
	if r.code != 2 {
		t.Fatalf("a non-numeric total is a usage error: %d\n%s", r.code, r.output)
	}
}
