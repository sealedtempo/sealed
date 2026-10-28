package verify_test

import (
	"strings"
	"testing"

	verify "github.com/sealed-dev/sealed/verifier"
)

// TestTextReportEscapesControlCharacters: details carry bundle, /attest and chain strings; none may drive the
// terminal or reorder the text people read to make a trust decision.
func TestTextReportEscapesControlCharacters(t *testing.T) {
	rep := &verify.Report{
		Mode:         "evidence",
		DeploymentID: "0xab\x1b]0;title\x07",
		Checks: []verify.Check{
			{Name: "releases_active", OK: false, Detail: "crm\x1b[2K\r  ok    releases_active  all good\nsecond line"},
			{Name: "bundle", OK: true, Detail: "app \u202egnp.exe\u202c, tab\there, bad utf8 \xff, zero width \u200b, caf\u00e9 ok"},
		},
	}
	text := rep.Text()
	for _, bad := range []string{"\x1b", "\r", "\u202e", "\u202c", "\u200b", "\x07", "\xff", "\there"} {
		if strings.Contains(text, bad) {
			t.Fatalf("text report contains %q:\n%s", bad, text)
		}
	}
	for _, want := range []string{`crm\x1b[2K\r  ok`, `\n`, `\u202e`, `\t`, `\xff`, `\u200b`, "caf\u00e9 ok", `0xab\x1b]0;title\a`} {
		if !strings.Contains(text, want) {
			t.Fatalf("text report lacks %q:\n%s", want, text)
		}
	}
	if got := strings.Count(text, "\n"); got != 8 {
		t.Fatalf("%d lines, a detail added or removed lines:\n%s", got, text)
	}
}
