package composer

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/egress/policy"
)

// Tests for the composer 1.3.0 hardening (D-059, D-061, D-063, D-064,
// D-067; docker-checks bugs 1, 2, 5 and 6; reviews ws-int-composer and
// ws-int-agent).

// composedStacks are the stack shapes the tests below check: notes with the
// gateway (payer and verifierd), notes alone, the relay alone and all three.
func composedStacks(t *testing.T) map[string]*Result {
	t.Helper()
	notes, gw, relay := buildFixture(t, "notes"), buildFixture(t, "llm-gateway"), buildFixture(t, "inference-relay")
	out := map[string]*Result{}
	for name, stack := range map[string][]*Bundle{
		"notes+gateway": {notes, gw}, "notes": {notes}, "relay": {relay}, "all": {notes, gw, relay},
	} {
		out[name] = mustCompose(t, testConfig(stack...), stack...)
	}
	return out
}

// TestInlineConfigsAreNotReadOnly is docker-checks bug 1 (D-063): compose
// copies inline configs into the container at create time, which a
// read-only root filesystem forbids, so "docker compose up" refused every
// stack of composer 1.1.1 and 1.2.0 before anything started.
func TestInlineConfigsAreNotReadOnly(t *testing.T) {
	for stack, r := range composedStacks(t) {
		doc := composeDoc(t, r)
		configs := doc["configs"].(map[string]any)
		for _, name := range sortedKeys(doc["services"].(map[string]any)) {
			s := svc(doc, name)
			mounts, _ := s["configs"].([]any)
			for _, m := range mounts {
				src := m.(map[string]any)["source"].(string)
				if _, inline := configs[src].(map[string]any)["content"]; !inline {
					t.Errorf("%s: %s mounts config %s without content", stack, name, src)
				}
			}
			if ro, _ := s["read_only"].(bool); ro && len(mounts) > 0 {
				t.Errorf("%s: %s is read_only with inline configs", stack, name)
			}
		}
		// The sidecars that were read-only before 1.3.0 stay without it.
		for _, name := range []string{"sealed-egress", "sealed-verifierd"} {
			if s, ok := doc["services"].(map[string]any)[name].(map[string]any); ok && s["read_only"] != nil {
				t.Errorf("%s: %s read_only %v", stack, name, s["read_only"])
			}
		}
	}
	// The composer refuses to emit the broken combination.
	err := checkInlineConfigsWritable(map[string]any{
		"a": map[string]any{"read_only": true},
		"b": map[string]any{"configs": []any{configMount(cfgConfig, ConfigPath)}},
		"c": map[string]any{"read_only": true, "configs": []any{configMount(cfgConfig, ConfigPath)}},
	})
	if err == nil || !strings.Contains(err.Error(), "service c is read_only") {
		t.Fatalf("read-only service with an inline config: %v", err)
	}
	// App fragments may still set read_only: app services get no configs.
	notes := buildFixture(t, "notes")
	doc := composeDoc(t, mustCompose(t, testConfig(notes), notes))
	if svc(doc, "notes-web")["read_only"] != true || svc(doc, "notes-web")["configs"] != nil {
		t.Error("notes-web lost its fragment read_only or gained configs")
	}
}

// TestMultiHomedContainersDoNotForward is docker-checks bug 5 and D-064: a
// container on two or more networks has IPv4 forwarding off, so routing
// through sealed-egress (or Caddy, the agent, the payer or a primary) does
// not depend on Docker's bridge rules.
func TestMultiHomedContainersDoNotForward(t *testing.T) {
	for stack, r := range composedStacks(t) {
		doc := composeDoc(t, r)
		for _, name := range sortedKeys(doc["services"].(map[string]any)) {
			s := svc(doc, name)
			nets, _ := s["networks"].(map[string]any)
			sys, _ := s["sysctls"].(map[string]any)
			if len(nets) > 1 {
				if !jsonEqual(sys, map[string]any{"net.ipv4.ip_forward": "0"}) {
					t.Errorf("%s: %s on %d networks has sysctls %v", stack, name, len(nets), sys)
				}
			} else if sys != nil {
				t.Errorf("%s: %s on one network has sysctls %v", stack, name, sys)
			}
		}
		if sys, _ := svc(doc, "sealed-egress")["sysctls"].(map[string]any); sys["net.ipv4.ip_forward"] != "0" {
			t.Errorf("%s: sealed-egress forwards", stack)
		}
	}
}

// TestVerifierdOnlyReachableFromPayer is D-061 (review V-1): sealed-verifierd
// shares a network only with sealed-mpp-payer and sealed-egress, so no app
// can make it send requests with its egress allowlist; its DNS and proxy
// are egress on that network, and URL fetches are limited to the relay
// attest host.
func TestVerifierdOnlyReachableFromPayer(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	doc := composeDoc(t, r)
	members := map[string][]string{}
	for _, name := range sortedKeys(doc["services"].(map[string]any)) {
		for _, n := range serviceNetworks(t, doc, name) {
			members[n] = append(members[n], name)
		}
	}
	if got := strings.Join(members[VerifierNetwork], ","); got != "sealed-egress,sealed-mpp-payer,sealed-verifierd" {
		t.Errorf("verifier network members %s", got)
	}
	if got := serviceNetworks(t, doc, "sealed-verifierd"); strings.Join(got, ",") != VerifierNetwork {
		t.Errorf("verifierd networks %v", got)
	}
	n := doc["networks"].(map[string]any)[VerifierNetwork].(map[string]any)
	ipam := n["ipam"].(map[string]any)["config"].([]any)[0].(map[string]any)
	opts := n["driver_opts"].(map[string]any)
	if n["internal"] != true || ipam["subnet"] != VerifierSubnet || opts["com.docker.network.bridge.name"] != "sealed-verifier" {
		t.Errorf("verifier network %v", n)
	}
	vd := svc(doc, "sealed-verifierd")
	env := vd["environment"].(map[string]any)
	proxy := "http://" + EgressVerifierIP + ":3128"
	if !jsonEqual(vd["dns"], []any{EgressVerifierIP}) || env["HTTPS_PROXY"] != proxy || env["HTTP_PROXY"] != proxy || env["https_proxy"] != proxy {
		t.Errorf("verifierd dns %v proxy %v", vd["dns"], env["HTTPS_PROXY"])
	}
	// verifierd's own lockdown (ws/harden-verifier): only the payer's
	// address on the verifier network, no URL fetches.
	for k, want := range map[string]string{
		"SEALED_VERIFIERD_ALLOWED_CLIENTS": PayerVerifierIP, "SEALED_VERIFIERD_LIVE_FETCH": "false",
		"SEALED_VERIFIERD_LIVE_HOSTS": "attest.relay.sealed.example", "SEALED_CONFIG_FILE": ConfigPath,
	} {
		if env[k] != want {
			t.Errorf("verifierd %s = %v, want %s", k, env[k], want)
		}
	}
	payer := svc(doc, "sealed-mpp-payer")
	if env := payer["environment"].(map[string]any); env["SEALED_VERIFIERD_URL"] != "http://sealed-verifierd:8088" || env["HTTPS_PROXY"] != ProxyURL {
		t.Errorf("payer env %v", env)
	}
	var sc struct {
		Sidecars map[string]string `json:"sidecars"`
	}
	if err := json.Unmarshal(r.StackInfo, &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Sidecars["sealed-verifierd"] != VerifierdIP || sc.Sidecars["sealed-mpp-payer"] != PayerIP {
		t.Errorf("sidecars %v", sc.Sidecars)
	}
	// Without llm-gateway there is no verifier network.
	notes := buildFixture(t, "notes")
	if _, ok := composeDoc(t, mustCompose(t, testConfig(notes), notes))["networks"].(map[string]any)[VerifierNetwork]; ok {
		t.Error("verifier network without the gateway")
	}
}

// TestReleaseAssetHostsCoverDefaults keeps verifierd's asset hosts (D-061)
// in step with catalog.release_asset_base: the base host must be listed.
func TestReleaseAssetHostsCoverDefaults(t *testing.T) {
	d, err := LoadDefaults(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(d.Catalog.ReleaseAssetBase)
	if err != nil || u.Scheme != "https" {
		t.Fatalf("release_asset_base %q", d.Catalog.ReleaseAssetBase)
	}
	if !contains(releaseAssetHosts, u.Hostname()+":443") {
		t.Errorf("%s:443 is not in %v", u.Hostname(), releaseAssetHosts)
	}
	for _, h := range releaseAssetHosts {
		if _, err := ParseHostPort(h); err != nil {
			t.Error(err)
		}
	}
}

// TestPayerStopGracePeriod is D-067: the payer gets at least 45 s to close
// its relay session on SIGTERM.
func TestPayerStopGracePeriod(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	doc := composeDoc(t, mustCompose(t, cfg, bundles...))
	v, _ := svc(doc, "sealed-mpp-payer")["stop_grace_period"].(string)
	d, err := time.ParseDuration(v)
	if err != nil || d < 45*time.Second {
		t.Fatalf("payer stop_grace_period %q", v)
	}
}

// TestVMRangesMatchEgress keeps the composer's VM ranges, sealed-egress's
// vm-internal class and the host rules in step (D-064, docker-checks bug
// 6), and checks that every network a stack can use lies inside them.
func TestVMRangesMatchEgress(t *testing.T) {
	if strings.Join(VMRanges, ",") != strings.Join(policy.VMInternalPrefixes, ",") {
		t.Fatalf("composer VMRanges %v, egress VMInternalPrefixes %v", VMRanges, policy.VMInternalPrefixes)
	}
	inside := func(subnet string) bool {
		p := netip.MustParsePrefix(subnet)
		for _, r := range VMRanges {
			rp := netip.MustParsePrefix(r)
			if rp.Bits() <= p.Bits() && rp.Contains(p.Addr()) {
				return true
			}
		}
		return false
	}
	subnets := []string{AppsSubnet, EdgeSubnet, VerifierSubnet}
	for n := 1; n <= MaxConfigApps; n++ {
		subnets = append(subnets, AppSubnet(n))
	}
	for _, s := range subnets {
		if !inside(s) {
			t.Errorf("%s is outside %v", s, VMRanges)
		}
		if addr := netip.MustParsePrefix(s).Addr().Next(); policy.Classify(addr) != policy.ClassVMInternal {
			t.Errorf("egress classes %s (%s) as %s", addr, s, policy.Classify(addr))
		}
	}
	for stack, r := range composedStacks(t) {
		doc := composeDoc(t, r)
		for name, n := range doc["networks"].(map[string]any) {
			cfg := n.(map[string]any)["ipam"].(map[string]any)["config"].([]any)[0].(map[string]any)
			if !inside(cfg["subnet"].(string)) {
				t.Errorf("%s: network %s subnet %v outside the VM ranges", stack, name, cfg["subnet"])
			}
			bridge := n.(map[string]any)["driver_opts"].(map[string]any)["com.docker.network.bridge.name"].(string)
			if !strings.HasPrefix(bridge, strings.TrimSuffix(ContainerBridgePattern, "+")) || len(bridge) > 15 {
				t.Errorf("%s: bridge %q does not match %s or is too long for an interface name", stack, bridge, ContainerBridgePattern)
			}
		}
		// The composed egress config passes egress's own validation, which
		// now refuses allowedPrivateCidrs inside any VM range.
		if _, err := policy.Parse(r.EgressConfig); err != nil {
			t.Errorf("%s: egress refuses the composed config: %v", stack, err)
		}
	}
	// A VPC range the composer accepts is one egress accepts too.
	cfg, bundles := fixtureStack(t)
	cfg.AllowedVpcRanges = []string{"172.29.0.0/16", "172.31.1.0/24"}
	if _, err := policy.Parse(mustCompose(t, cfg, bundles...).EgressConfig); err != nil {
		t.Errorf("egress refuses accepted VPC ranges: %v", err)
	}
}
