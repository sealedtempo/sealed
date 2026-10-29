package deploy

import (
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/cli/internal/testkit"
)

// TestApprovalInstructionsNeverPrintTheRPCKey: a keyed RPC URL never appears in the approval instructions `sealed
// deploy` prints; the cast command reads it from $TEMPO_RPC_URL and only the host is named. A plain RPC without a
// path or query is printed as is, so the command still pastes.
func TestApprovalInstructionsNeverPrintTheRPCKey(t *testing.T) {
	r := newRig(t)
	p := r.plan(t, "")
	const feeToken = "0x20c000000000000000000000b9537d11c60e8b50"
	for _, rpc := range []string{
		"https://tempo.provider.example/v2/FAKEAPIKEY0123456789",
		"https://tempo.provider.example/rpc?apikey=FAKEAPIKEY0123456789",
		"https://user:FAKEAPIKEY0123456789@tempo.provider.example",
	} {
		instr := p.ApprovalInstructions(testkit.Addresses.DeploymentRegistry, rpc, feeToken)
		if strings.Contains(instr, "FAKEAPIKEY0123456789") {
			t.Fatalf("the approval instructions print the RPC API key:\n%s", instr)
		}
		if !strings.Contains(instr, `--rpc-url "$TEMPO_RPC_URL"`) || !strings.Contains(instr, "the RPC this run used, https://tempo.provider.example with its path") {
			t.Errorf("instructions for %s:\n%s", rpc, instr)
		}
	}
	instr := p.ApprovalInstructions(testkit.Addresses.DeploymentRegistry, "https://rpc.tempo.xyz", feeToken)
	if !strings.Contains(instr, "--rpc-url https://rpc.tempo.xyz --tempo.fee-token") || strings.Contains(instr, "TEMPO_RPC_URL") {
		t.Errorf("public RPC:\n%s", instr)
	}
}
