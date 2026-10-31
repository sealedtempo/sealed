package app

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/cli/internal/token"
)

// TestDeployRefusesMachineTypesWithoutAnImage: sealed deploy stops before the wallet is asked to approve, and before
// any VM, when the VM's machine type has no registered image or is not the shape the stack's image entry was
// measured on (D-083, G05). The key broker would otherwise deny the VM at first boot.
func TestDeployRefusesMachineTypesWithoutAnImage(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	w, _, _ := h.world(false)
	conn, _ := token.Encode(token.Connection{V: 1, Project: "acme-prod-4417", Region: "us-central1",
		DeployerAccount: "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com", KeyBrokerURL: "https://kb.example.com", Customer: w.Customer.Hex()})
	body := fmt.Sprintf(`schema: sealed-deploy/v1
name: demo
connection: %s
image:
  id: 0x%s
  boot: projects/sealed-images-1/global/images/sealed-os-0-6-1
  systemDisk: projects/sealed-images-1/global/images/sealed-dstack-data-v1
apps:
  - id: notes
  - id: llm-gateway
endpoints:
  platformApi: https://api.sealed.example
  relay: https://attest.relay.sealed.example
  relayAttest: https://attest.relay.sealed.example/attest
relayOwner: "0x00000000000000000000000000000000000000b1"
`, conn, hex.EncodeToString(w.ImageID[:]))
	stack := h.write("stack.yaml", body)

	// The stack file names a shape without a registered image.
	for _, mt := range []string{"c3-standard-4", "c4-standard-8"} {
		code, _, errs := h.run("deploy", "--config", h.write("stack-"+mt+".yaml", body+"machineType: "+mt+"\n"), "--dev-allow-unbuilt", "--skip-secrets-check")
		if code != ExitFailed || !strings.Contains(errs, "has no registered Sealed OS image") || strings.Contains(errs, "approveStack") {
			t.Fatalf("machineType %s: %d %s", mt, code, errs)
		}
	}

	// The image entry was measured on another shape than the VM's (c3-standard-8, the default).
	img := h.chain.Images[w.ImageID]
	img.Version = "0.6.1-s1+c3-standard-4"
	code, _, errs := h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--skip-secrets-check")
	if code != ExitFailed || !strings.Contains(errs, "was measured on c3-standard-4, not on machine type c3-standard-8") || strings.Contains(errs, "approveStack") {
		t.Fatalf("image measured on c3-standard-4: %d %s", code, errs)
	}
	if len(h.compute.instances) != 0 || len(h.compute.disks) != 0 {
		t.Fatal("a VM or disk was created")
	}

	// The entry measured on c3-standard-8 goes on to the approval step.
	img.Version = "0.6.1-s1+c3-standard-8"
	if code, _, errs := h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--skip-secrets-check"); code != ExitNotApproved || !strings.Contains(errs, "approveStack") {
		t.Fatalf("image measured on c3-standard-8: %d %s", code, errs)
	}
}
