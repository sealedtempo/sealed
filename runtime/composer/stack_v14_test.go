package composer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sealed-dev/sealed/runtime/caddy"
)

// Tests for composer 1.4.0: sealed-mpp-payer's state on the data disk
// (fix-payments, harden-agent) and the bearer-passthrough gate (review C-6,
// in caddy_integration_test.go and runtime/caddy).

// TestPayerStateOnTheDataDisk: the payer's journal, stored channel and
// spend state survive image updates and VM replacement, because they live
// in a data-disk directory owned by the payer's numeric user with mode 0700.
func TestPayerStateOnTheDataDisk(t *testing.T) {
	stacks := composedStacks(t)
	source := DataPath(payerDataApp, payerDataVolume)
	if source != "/mnt/sealed-data/_mpp-payer/state" || PayerStateDir != "/var/lib/sealed-mpp-payer" || PayerRunAs != "1000:1000" {
		t.Fatalf("payer state %s at %s for %s", source, PayerStateDir, PayerRunAs)
	}
	// No catalog app can own the directory: app ids cannot start with "_".
	if appIDRe.MatchString(payerDataApp) {
		t.Fatalf("%s is a valid app id", payerDataApp)
	}
	for _, name := range []string{"notes+gateway", "all"} {
		r := stacks[name]
		doc := composeDoc(t, r)
		p := svc(doc, svcPayer)
		if p["user"] != PayerRunAs {
			t.Errorf("%s: payer user %v", name, p["user"])
		}
		var bind map[string]any
		var binBin bool
		for _, v := range p["volumes"].([]any) {
			m := v.(map[string]any)
			if m["target"] == PayerStateDir {
				bind = m
			}
			if m["type"] == "volume" && m["source"] == volBin && m["target"] == BinDir && m["read_only"] == true {
				binBin = true
			}
		}
		// Fail closed: Docker must never create the source on the host side
		// of the data-disk mount point (sealed-agent creates it after unlocking).
		if bind == nil || bind["type"] != "bind" || bind["source"] != source || bind["read_only"] != nil ||
			bind["bind"].(map[string]any)["create_host_path"] != false {
			t.Errorf("%s: payer state bind %v", name, bind)
		}
		if !binBin {
			t.Errorf("%s: the payer needs envexec from sealed-bin, read-only", name)
		}
		entry, _ := json.Marshal(p["entrypoint"])
		command, _ := json.Marshal(p["command"])
		if string(entry) != `["/sealed/bin/envexec","private","/var/lib/sealed-mpp-payer","--","node"]` || string(command) != `["/app/dist/main.js"]` {
			t.Errorf("%s: payer runs %s %s", name, entry, command)
		}
		if env := p["environment"].(map[string]any); env["STATE_DIR"] != PayerStateDir {
			t.Errorf("%s: STATE_DIR %v", name, env["STATE_DIR"])
		}
		deps := p["depends_on"].(map[string]any)
		if c, _ := deps[svcInit].(map[string]any); c["condition"] != "service_completed_successfully" {
			t.Errorf("%s: payer must wait for sealed-init (envexec): %v", name, deps)
		}
		if p["stop_grace_period"] != PayerStopGracePeriod {
			t.Errorf("%s: stop_grace_period %v", name, p["stop_grace_period"])
		}
		// sealed-agent gives a new directory the numeric user of the first
		// service that binds it, so the payer must be the only one.
		for _, other := range sortedKeys(doc["services"].(map[string]any)) {
			if other == svcPayer {
				continue
			}
			vols, _ := svc(doc, other)["volumes"].([]any)
			for _, v := range vols {
				if src, _ := v.(map[string]any)["source"].(string); strings.HasPrefix(src, DataRoot+"/"+payerDataApp) {
					t.Errorf("%s: %s binds the payer's state %s", name, other, src)
				}
			}
		}
		var si stackInfoDoc
		if err := json.Unmarshal(r.StackInfo, &si); err != nil {
			t.Fatal(err)
		}
		if !contains(si.DataDirs, source) {
			t.Errorf("%s: dataDirs %v lack %s", name, si.DataDirs, source)
		}
	}
	// Without llm-gateway there is no payer and no payer directory.
	for _, name := range []string{"notes", "relay"} {
		var si stackInfoDoc
		if err := json.Unmarshal(stacks[name].StackInfo, &si); err != nil {
			t.Fatal(err)
		}
		if contains(si.DataDirs, source) || strings.Contains(string(stacks[name].AppCompose), payerDataApp) {
			t.Errorf("%s: payer state without a payer", name)
		}
	}
}

// TestPayerCommandMatchesImage: the composer replaces the payer's entrypoint
// (envexec private), which makes compose drop the image's CMD, so it runs
// the image's ENTRYPOINT and CMD itself. They, the image's state directory
// and the payer's default STATE_DIR must stay what the composer assumes.
func TestPayerCommandMatchesImage(t *testing.T) {
	root := filepath.Join("..", "mpp-payer")
	df, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	stages := strings.Split(string(df), "\nFROM ")
	final := stages[len(stages)-1]
	instr := func(name string) []string {
		m := regexp.MustCompile(`(?m)^`+name+` (\[.*\])\s*$`).FindAllStringSubmatch(final, -1)
		if len(m) != 1 {
			t.Fatalf("final stage has %d %s instructions in JSON form", len(m), name)
		}
		var v []string
		if err := json.Unmarshal([]byte(m[0][1]), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	image := append(instr("ENTRYPOINT"), instr("CMD")...)
	if strings.Join(image, " ") != strings.Join(payerCommand, " ") {
		t.Fatalf("payer image runs %q, the composer runs %q", image, payerCommand)
	}
	// The image's user is node (uid 1000 in the node images) and its state
	// directory is PayerStateDir; the bind replaces that directory.
	if !regexp.MustCompile(`(?m)^USER node\s*$`).MatchString(final) ||
		!strings.Contains(final, "install -d -o node -g node -m 0700 "+PayerStateDir+"\n") ||
		!strings.HasPrefix(PayerRunAs, "1000:") {
		t.Fatalf("payer image user or state directory changed:\n%s", final)
	}
	src, err := os.ReadFile(filepath.Join(root, "src", "config.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "DEFAULT_STATE_DIR = '"+PayerStateDir+"'") || !strings.Contains(string(src), "env.STATE_DIR") {
		t.Fatalf("the payer's STATE_DIR is no longer %s", PayerStateDir)
	}
}

// TestBearerGateInComposedStacks: every bearer-passthrough handle a stack
// gets asks the agent in bearer mode for its own route (review C-6), and no
// other handle does.
func TestBearerGateInComposedStacks(t *testing.T) {
	for name, r := range composedStacks(t) {
		cf := string(r.Caddyfile)
		bearer := regexp.MustCompile(`uri `+regexp.QuoteMeta(caddy.DefaultGatePath)+`\?route=([a-z0-9-]+)&`+regexp.QuoteMeta(caddy.GateBearerQuery)+"\n").FindAllStringSubmatch(cf, -1)
		var si struct {
			Apps []struct {
				Routes []struct{ Name, Auth string } `json:"routes"`
			} `json:"apps"`
		}
		if err := json.Unmarshal(r.StackInfo, &si); err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, a := range si.Apps {
			for _, rt := range a.Routes {
				if rt.Auth == AuthBearerPassthrough {
					want = append(want, rt.Name)
				}
			}
		}
		var got []string
		for _, m := range bearer {
			got = append(got, m[1])
		}
		if strings.Join(got, ",") != strings.Join(want, ",") || strings.Count(cf, caddy.GateBearerQuery) != len(want) {
			t.Errorf("%s: bearer gate for %v, bearer-passthrough routes %v", name, got, want)
		}
		if strings.Contains(name, "gateway") || name == "all" {
			if len(want) != 1 || want[0] != "gateway" {
				t.Errorf("%s: bearer-passthrough routes %v", name, want)
			}
		}
		// The payment-needed variant answers 402 and asks nobody.
		if strings.Contains(string(r.CaddyfilePaymentNeeded), caddy.GateBearerQuery) {
			t.Errorf("%s: payment-needed Caddyfile asks the gate", name)
		}
	}
}
