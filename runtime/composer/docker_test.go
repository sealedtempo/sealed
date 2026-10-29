package composer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sealedtempo/sealed/runtime/composer/cjson"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
)

// Docker tests (D-063): the composed stack must start under docker compose,
// not only pass "docker compose config". Both need a reachable Docker
// daemon (CI, or the local Colima VM) and skip without one.
//
//   - TestComposeStartsWithDocker runs "docker compose up -d" on every
//     fixture stack shape with busybox for every image (pulled by digest;
//     the test skips when it cannot be pulled). Only what needs the CVM is
//     removed (devices, host binds and published ports), entrypoints sleep,
//     and app healthchecks that call image tools become envexec probes;
//     networks, addresses, inline configs, read_only, sysctls, capabilities,
//     security_opt, tmpfs volumes, depends_on and the sidecar healthchecks
//     stay as composed. Compose injects inline configs when it starts a
//     container, so a read-only service with one fails here (docker-checks
//     bug 1); "docker compose create" does not catch it.
//   - TestComposeUpWithDocker (SEALED_DOCKER_UP=1) builds sealed-egress and
//     sealed-init from their Dockerfiles for the daemon's platform, composes
//     the stand-in apps in testdata/docker/apps, runs "docker compose up -d"
//     and waits until every container is healthy behind the envexec ready
//     gate, then probes the network layout. SEALED_DOCKER_HOST_RULES=1 also
//     installs the pre_launch_script in the Docker VM (through nsenter from a
//     privileged container) and checks the INPUT rules; use a disposable VM.

// standinImage is busybox 1.37.0 by index digest: sh and httpd for the
// stand-in services, nsenter for the host rules check.
const standinImage = "busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("no reachable docker daemon")
	}
	if err := exec.CommandContext(ctx, "docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose plugin not installed")
	}
}

// docker runs the docker CLI and returns its combined output.
func docker(t *testing.T, timeout time.Duration, stdin []byte, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// localStack turns a composed docker compose document into one that runs on
// a laptop: images are replaced (image maps service name to image, "" for
// the rest), and devices, bind mounts and published ports are dropped.
// Everything else stays as composed.
func localStack(t *testing.T, r *Result, project string, image func(service string) string, entrypoint func(service string) []any) []byte {
	t.Helper()
	v, err := cjson.Parse(r.ComposeJSON)
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(map[string]any)
	doc["name"] = project
	for name, s := range doc["services"].(map[string]any) {
		svc := s.(map[string]any)
		svc["image"] = image(name)
		delete(svc, "devices")
		delete(svc, "ports")
		var vols []any
		in, _ := svc["volumes"].([]any)
		for _, m := range in {
			if m.(map[string]any)["type"] != "bind" {
				vols = append(vols, m)
			}
		}
		if len(vols) > 0 {
			svc["volumes"] = vols
		} else {
			delete(svc, "volumes")
		}
		if entrypoint != nil {
			if ep := entrypoint(name); ep != nil {
				svc["entrypoint"] = ep
				delete(svc, "command")
			}
		}
		// Fast teardown; grace periods matter only for the real images.
		svc["stop_grace_period"] = "2s"
	}
	out, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// subnetsBusy skips when another Docker network already holds the fixed
// stack subnets (a shared daemon); the composed subnets cannot move.
func subnetsBusy(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "Pool overlaps") || strings.Contains(out, "overlaps with other one") {
		t.Skipf("another Docker network uses 172.30.0.0/16 or 172.31.0.0/24: %s", strings.TrimSpace(out))
	}
}

// fakeEnvexec stands in for envexec in TestComposeStartsWithDocker: every
// healthcheck probe passes.
const fakeEnvexec = "#!/bin/sh\nexit 0\n"

func TestComposeStartsWithDocker(t *testing.T) {
	requireDocker(t)
	if out, err := docker(t, 5*time.Minute, nil, "pull", "-q", standinImage); err != nil {
		t.Skipf("cannot pull %s: %v %s", standinImage, err, out)
	}
	// Every service runs busybox: sealed-init installs a fake envexec into
	// sealed-bin (so the composed healthchecks pass), the rest sleep. App
	// healthchecks that call image tools (pg_isready) become envexec probes.
	entry := func(svc string) []any {
		if svc == svcInit {
			return []any{"/bin/sh", "-c", "printf '" + fakeEnvexec + "' > " + EnvexecPath + " && chmod 0755 " + EnvexecPath}
		}
		return []any{"sleep", "3600"}
	}
	up := func(t *testing.T, r *Result, project string) (string, error) {
		t.Helper()
		raw := localStack(t, r, project, func(string) string { return standinImage }, entry)
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, s := range doc["services"].(map[string]any) {
			svc := s.(map[string]any)
			if hc, ok := svc["healthcheck"].(map[string]any); ok {
				if test, _ := hc["test"].([]any); len(test) < 2 || test[1] != EnvexecPath {
					hc["test"] = []any{"CMD", EnvexecPath, "probe", "stand-in"}
				}
			}
		}
		raw, _ = json.Marshal(doc)
		file := writeTemp(t, "compose.json", raw)
		t.Cleanup(func() {
			_, _ = docker(t, 2*time.Minute, nil, "compose", "-f", file, "-p", project, "down", "-v", "-t", "1")
		})
		out, err := docker(t, 5*time.Minute, nil, "compose", "-f", file, "-p", project, "up", "-d")
		if err != nil {
			return out, err
		}
		waitStackUp(t, file, project, sortedKeys(doc["services"].(map[string]any)), 2*time.Minute)
		return out, nil
	}
	stacks := composedStacks(t)
	for i, name := range sortedKeys(stacks) {
		t.Run(name, func(t *testing.T) {
			if out, err := up(t, stacks[name], fmt.Sprintf("sealed-st%d", i)); err != nil {
				subnetsBusy(t, out)
				t.Fatalf("docker compose up -d: %v\n%s", err, out)
			}
		})
	}
	// The control: the 1.2.0 layout (read-only sealed-egress with its inline
	// config) is refused by docker compose up (docker-checks bug 1).
	t.Run("read-only egress control", func(t *testing.T) {
		r := stacks["notes"]
		v, _ := cjson.Parse(r.ComposeJSON)
		v.(map[string]any)["services"].(map[string]any)[svcEgress].(map[string]any)["read_only"] = true
		broken, _ := cjson.Encode(v)
		r2 := *r
		r2.ComposeJSON = broken
		out, err := up(t, &r2, "sealed-stro")
		if err == nil || !strings.Contains(out, "in read-only service sealed-egress") {
			subnetsBusy(t, out)
			t.Fatalf("read-only sealed-egress with an inline config started: %v\n%s", err, out)
		}
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "read-only") {
				t.Logf("refused as expected: %s", strings.TrimSpace(l))
				break
			}
		}
	})
}

// waitStackUp waits until every service's container is healthy, or running
// when it has no healthcheck, and sealed-init has exited 0. It returns each
// container's "status exit-code health".
func waitStackUp(t *testing.T, file, project string, services []string, timeout time.Duration) map[string]string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	state := map[string]string{}
	for _, svc := range services {
		for {
			out, _ := docker(t, 30*time.Second, nil, "inspect", "-f",
				"{{.State.Status}} {{.State.ExitCode}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", project+"-"+svc+"-1")
			state[svc] = strings.TrimSpace(out)
			f := strings.Fields(state[svc])
			if len(f) == 3 && (f[2] == "healthy" || (f[2] == "none" && f[0] == "running") || (svc == svcInit && f[0] == "exited" && f[1] == "0")) {
				break
			}
			if time.Now().After(deadline) {
				ps, _ := docker(t, time.Minute, nil, "compose", "-f", file, "-p", project, "ps", "-a")
				logs, _ := docker(t, time.Minute, nil, "compose", "-f", file, "-p", project, "logs", "--no-color", "--tail", "20")
				t.Fatalf("%s is %q after %s\n%s\n%s", svc, state[svc], timeout, ps, tail(logs, 80))
			}
			time.Sleep(time.Second)
		}
	}
	return state
}

func TestComposeUpWithDocker(t *testing.T) {
	if os.Getenv("SEALED_DOCKER_UP") != "1" {
		t.Skip("set SEALED_DOCKER_UP=1 (builds images, needs a disposable Docker VM with internet access)")
	}
	requireDocker(t)
	platform, err := docker(t, 30*time.Second, nil, "version", "-f", "{{.Server.Os}}/{{.Server.Arch}}")
	if err != nil {
		t.Fatalf("docker version: %v %s", err, platform)
	}
	platform = strings.TrimSpace(platform)
	arch := platform[strings.Index(platform, "/")+1:]

	// Build contexts with only what the Dockerfiles copy.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctxDir := t.TempDir()
	for _, p := range []string{"go.mod", "go.sum", "runtime/egress", "runtime/envexec", "runtime/composer/cjson"} {
		if err := copyTree(filepath.Join(root, p), filepath.Join(ctxDir, p)); err != nil {
			t.Fatal(err)
		}
	}
	const egressImg, initImg = "sealed-composer-test/sealed-egress:local", "sealed-composer-test/sealed-init:local"
	for img, df := range map[string]string{egressImg: "runtime/egress/Dockerfile", initImg: "runtime/envexec/Dockerfile"} {
		out, err := docker(t, 15*time.Minute, nil, "buildx", "build", "--load", "--platform", platform, "-f", filepath.Join(ctxDir, df), "-t", img, ctxDir)
		if err != nil {
			t.Fatalf("build %s for %s: %v\n%s", df, platform, err, tail(out, 40))
		}
	}
	// Docker-checks bug 4: the binary must be built for the image platform.
	for img, bin := range map[string]string{egressImg: "/sealed-egress", initImg: "/envexec"} {
		if got := elfArch(t, img, bin); got != arch {
			t.Errorf("%s carries a %s binary in a %s image", img, got, platform)
		}
	}
	if out, err := docker(t, 5*time.Minute, nil, "pull", standinImage); err != nil {
		t.Fatalf("docker pull %s: %v\n%s", standinImage, err, out)
	}

	var bundles []*Bundle
	for _, app := range []string{"alpha", "bravo", "llm-gateway"} {
		b, err := BuildBundle(BuildInput{AppDir: filepath.Join("testdata", "docker", "apps", app), Registry: testRegistry})
		if err != nil {
			t.Fatal(err)
		}
		bundles = append(bundles, b)
	}
	cfg := testConfig(bundles...)
	cfg.EgressAdditions = map[string][]string{"bravo": {"example.org:443"}}
	r := mustCompose(t, cfg, bundles...)

	httpd := func(port int, ready bool) []any {
		script := "mkdir -p /tmp/www/v1 && echo ok > /tmp/www/v1/ready && "
		if ready {
			// sealed-agent stand-in: open the envexec ready gate.
			script = "touch " + ReadyDir + "/ok && " + script
		}
		return []any{"/bin/sh", "-c", script + fmt.Sprintf("exec httpd -f -p %d -h /tmp/www", port)}
	}
	const project = "sealed-up"
	file := writeTemp(t, "compose.json", localStack(t, r, project,
		func(svc string) string {
			switch svc {
			case svcEgress:
				return egressImg
			case svcInit:
				return initImg
			}
			return standinImage
		},
		func(svc string) []any {
			switch svc {
			case svcAgent:
				return httpd(AgentPort, true)
			case svcCaddy:
				return httpd(8081, false)
			case svcPayer:
				return httpd(PayerPort, false)
			case svcVerifierd:
				return httpd(VerifierdPort, false)
			}
			return nil // app services keep the envexec wrapper and their fragment entrypoint
		}))
	compose := func(timeout time.Duration, args ...string) (string, error) {
		return docker(t, timeout, nil, append([]string{"compose", "-f", file, "-p", project}, args...)...)
	}
	_, _ = compose(2*time.Minute, "down", "-v", "-t", "1")
	t.Cleanup(func() { _, _ = compose(2*time.Minute, "down", "-v", "-t", "1") })
	if out, err := compose(5*time.Minute, "up", "-d"); err != nil {
		subnetsBusy(t, out)
		t.Fatalf("docker compose up -d: %v\n%s", err, out)
	}

	// Every container becomes healthy (or, without a healthcheck, keeps
	// running); sealed-init exits 0 after installing envexec.
	services := sortedKeys(composeDoc(t, r)["services"].(map[string]any))
	ctr := func(svc string) string { return project + "-" + svc + "-1" }
	state := waitStackUp(t, file, project, services, 3*time.Minute)
	t.Logf("all %d services up: %v", len(services), state)
	for _, svc := range []string{svcEgress, svcAgent, "alpha-web", "bravo-web", "llm-gateway-proxy"} {
		if !strings.HasSuffix(state[svc], " healthy") {
			t.Errorf("%s has no passing healthcheck: %q", svc, state[svc])
		}
	}

	// exec runs a command in a stand-in container and returns its output.
	// The containers carry the composed proxy variables; busybox wget
	// honours http_proxy but not no_proxy, so direct probes pass -Y off.
	exec := func(svc string, args ...string) (string, error) {
		return docker(t, 30*time.Second, nil, append([]string{"exec", ctr(svc)}, args...)...)
	}
	// D-064, docker-checks bug 5: multi-homed containers do not forward.
	for _, svc := range []string{svcEgress, svcAgent, svcCaddy, svcPayer, "alpha-web"} {
		out, err := docker(t, time.Minute, nil, "run", "--rm", "--network", "container:"+ctr(svc), standinImage, "cat", "/proc/sys/net/ipv4/ip_forward")
		if err != nil || strings.TrimSpace(out) != "0" {
			t.Errorf("%s: ip_forward %q %v", svc, strings.TrimSpace(out), err)
		}
	}
	// sealed-egress runs the composed config: a host off the allowlist is
	// refused by the proxy (no internet needed), and stats are served only
	// to the agent's address.
	if out, err := exec("alpha-web", "wget", "-q", "-T", "5", "-O-", "http://blocked.example.net/"); err == nil || !strings.Contains(out, "403") {
		t.Errorf("alpha-web to a blocked host through egress: %v %q", err, out)
	}
	if out, err := exec(svcAgent, "wget", "-Y", "off", "-q", "-T", "5", "-O-", "http://"+EgressAppsIP+":9100/v1/stats"); err != nil || !strings.Contains(out, `"callers"`) {
		t.Errorf("agent reading egress stats: %v %q", err, out)
	}
	if out, err := exec("alpha-web", "wget", "-Y", "off", "-q", "-T", "5", "-O-", "http://"+EgressAppsIP+":9100/v1/stats"); err == nil {
		t.Errorf("an app primary read egress stats: %q", out)
	}
	// D-061: only the payer reaches sealed-verifierd.
	if out, err := exec(svcPayer, "wget", "-Y", "off", "-q", "-T", "5", "-O-", fmt.Sprintf("http://%s:%d/v1/ready", svcVerifierd, VerifierdPort)); err != nil || strings.TrimSpace(out) != "ok" {
		t.Errorf("payer to verifierd: %v %q", err, out)
	}
	for _, svc := range []string{"alpha-web", "llm-gateway-proxy", svcCaddy} {
		if out, err := exec(svc, "wget", "-Y", "off", "-q", "-T", "3", "-O-", fmt.Sprintf("http://%s:%d/v1/ready", VerifierdIP, VerifierdPort)); err == nil {
			t.Errorf("%s reached verifierd: %q", svc, out)
		}
	}
	// D-041 still holds: a primary cannot reach another app's non-primary.
	if out, err := exec("alpha-web", "wget", "-Y", "off", "-q", "-T", "3", "-O-", "http://172.30.2.17:5432/"); err == nil {
		t.Errorf("alpha-web reached bravo-db: %q", out)
	}

	if os.Getenv("SEALED_DOCKER_HOST_RULES") == "1" {
		checkHostRules(t, r, exec)
	}
}

// checkHostRules installs the composed pre_launch_script in the Docker VM and
// checks D-064: a 0.0.0.0 listener on the VM (standing in for the dstack
// guest agent's 8090) is reachable through every bridge gateway before the
// rules and from nowhere after them, while sealed-egress keeps working.
func checkHostRules(t *testing.T, r *Result, exec func(string, ...string) (string, error)) {
	t.Helper()
	host := func(script string) (string, error) {
		return docker(t, time.Minute, []byte(script), "run", "--rm", "-i", "--privileged", "--pid", "host", "--network", "host",
			standinImage, "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "-p", "--", "/bin/bash", "-s")
	}
	const port = "47090"
	const listener = "sealed-up-hostsvc"
	_, _ = docker(t, time.Minute, nil, "rm", "-f", listener)
	if out, err := docker(t, time.Minute, nil, "run", "-d", "--name", listener, "--network", "host", standinImage,
		"/bin/sh", "-c", "mkdir -p /tmp/www && echo host > /tmp/www/index.html && exec httpd -f -p 0.0.0.0:"+port+" -h /tmp/www"); err != nil {
		t.Fatalf("host listener: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = docker(t, time.Minute, nil, "rm", "-f", listener) })
	cleanup := `for c in FORWARD DOCKER-USER; do
  while iptables -w -D "$c" -s 172.31.0.0/24 -j SEALED-EDGE 2>/dev/null; do :; done
  while iptables -w -D "$c" -i sealed-edge -j SEALED-EDGE 2>/dev/null; do :; done
done
while iptables -w -D INPUT -i sealed-+ -j SEALED-INPUT 2>/dev/null; do :; done
for s in 172.30.0.0/16 172.31.0.0/24; do while iptables -w -D INPUT -s "$s" -j SEALED-INPUT 2>/dev/null; do :; done; done
for c in SEALED-EDGE SEALED-INPUT; do iptables -w -F "$c" 2>/dev/null; iptables -w -X "$c" 2>/dev/null; done
true
`
	t.Cleanup(func() {
		if out, err := host(cleanup); err != nil {
			t.Errorf("removing host rules: %v %s", err, out)
		}
	})
	gateways := map[string]string{"alpha-db": "172.30.1.1", "alpha-web": "172.30.0.1", "llm-gateway-proxy": "172.30.3.1", svcCaddy: "172.31.0.1", svcPayer: "172.30.250.1"}
	probe := func(svc, gw string) error {
		_, err := exec(svc, "wget", "-Y", "off", "-q", "-T", "3", "-O-", "http://"+gw+":"+port+"/")
		return err
	}
	for svc, gw := range gateways {
		if err := probe(svc, gw); err != nil {
			t.Logf("before the host rules %s could not reach %s:%s (%v); the check below then proves less", svc, gw, port, err)
		}
	}
	if out, err := host(r.PreLaunchScript); err != nil {
		t.Fatalf("pre_launch_script: %v\n%s", err, out)
	}
	if out, err := host(r.PreLaunchScript); err != nil {
		t.Fatalf("pre_launch_script, second run: %v\n%s", err, out)
	}
	listing, _ := host("iptables -w -S INPUT; iptables -w -S SEALED-INPUT; iptables -w -S FORWARD | head -5")
	t.Logf("host rules:\n%s", listing)
	if n := strings.Count(listing, "-j SEALED-INPUT"); n != 3 {
		t.Errorf("INPUT has %d jumps to SEALED-INPUT after two runs, want 3", n)
	}
	for svc, gw := range gateways {
		if err := probe(svc, gw); err == nil {
			t.Errorf("%s reaches the VM listener %s:%s through the host rules", svc, gw, port)
		}
	}
	// Egress (proxy and DNS through the embedded resolver) still works.
	if out, err := exec("alpha-web", "wget", "-q", "-T", "5", "-O-", "http://blocked.example.net/"); err == nil || !strings.Contains(out, "403") {
		t.Errorf("egress proxy after the host rules: %v %q", err, out)
	}
	// Docker's embedded DNS answers inside the container and forwards
	// other names to egress, which answers NXDOMAIN for names off the
	// allowlist: an answer (not a timeout) shows the path still works.
	if out, err := exec("alpha-db", "nslookup", "sealed-egress"); err != nil {
		t.Errorf("embedded DNS after the host rules: %v %q", err, out)
	}
	if out, _ := exec("alpha-db", "nslookup", "blocked.example.net"); !strings.Contains(out, "NXDOMAIN") {
		t.Errorf("DNS forwarding to egress after the host rules: %q", out)
	}
}

// elfArch reads the ELF machine of a file in an image: amd64, arm64 or other.
func elfArch(t *testing.T, image, path string) string {
	t.Helper()
	id, err := docker(t, time.Minute, nil, "create", image)
	if err != nil {
		t.Fatalf("docker create %s: %v %s", image, err, id)
	}
	id = strings.TrimSpace(id)
	defer func() { _, _ = docker(t, time.Minute, nil, "rm", "-f", id) }()
	dst := filepath.Join(t.TempDir(), "bin")
	if out, err := docker(t, time.Minute, nil, "cp", id+":"+path, dst); err != nil {
		t.Fatalf("docker cp: %v %s", err, out)
	}
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hdr := make([]byte, 20)
	if _, err := io.ReadFull(f, hdr); err != nil || !bytes.HasPrefix(hdr, []byte("\x7fELF")) {
		return "other"
	}
	switch uint16(hdr[18]) | uint16(hdr[19])<<8 {
	case 62:
		return "amd64"
	case 183:
		return "arm64"
	}
	return "other"
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm())
	})
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// TestDockerChecksBuildThisTree: scripts/docker-checks/run.sh builds the
// composer, sealed-egress and sealed-init it checks from SRC_REF. Its default
// was ws/int-composer while that branch was ahead; after the merge the default
// silently checked composer 1.2.0 without the D-063 and D-064 fixes. The
// default is now HEAD, and the script names no workstream branch.
func TestDockerChecksBuildThisTree(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "docker-checks", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "\nSRC_REF=${SRC_REF:-HEAD}\n") {
		t.Error("run.sh: the SRC_REF default is not HEAD")
	}
	for i, line := range strings.Split(src, "\n") {
		if code, _, _ := strings.Cut(line, "#"); strings.Contains(code, "ws/") {
			t.Errorf("run.sh:%d names a workstream branch: %s", i+1, strings.TrimSpace(line))
		}
	}
}

// TestDockerChecksEgressConfigs runs the docker-checks pipeline up to the
// laptop stack without Docker (compose scripts/docker-checks/fixtures as
// run.sh does, then mkstack.py) and loads every sealed-egress config of that
// stack with runtime/egress/policy, as sealed-egress does when it starts.
// The stack's egress must load. The dc-egress2 control (allowedPrivateCidrs
// 172.16.0.0/12, allow entries on its own app networks) must be refused for
// naming vm-internal destinations (D-064), and run.sh must not wait for it to
// run: after the vm-internal class landed, run.sh at HEAD stopped with "stack
// did not become healthy" because it waited for that refused container.
func TestDockerChecksEgressConfigs(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	dc := filepath.Join("..", "..", "scripts", "docker-checks")
	res := composeDockerChecksFixture(t)
	work := t.TempDir()
	in, out := filepath.Join(work, "docker-compose.json"), filepath.Join(work, "test-compose.json")
	if err := os.WriteFile(in, res.ComposeJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	const egressImg = "sealed-dc/sealed-egress:local"
	mk := exec.Command(py, "-I", "-B", filepath.Join(dc, "mkstack.py"), in, out, "--egress", egressImg,
		"--init", "sealed-dc/sealed-init:local", "--standin", "sealed-dc/standin:local", "--host-port", "47090", "--project", "sealed-dc")
	if b, err := mk.CombinedOutput(); err != nil {
		t.Fatalf("mkstack.py: %v\n%s", err, b)
	}
	var stack struct {
		Services map[string]struct {
			Image   string `json:"image"`
			Configs []struct {
				Source string `json:"source"`
				Target string `json:"target"`
			} `json:"configs"`
			Environment map[string]string `json:"environment"`
		} `json:"services"`
		Configs map[string]struct {
			Content string `json:"content"`
		} `json:"configs"`
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &stack); err != nil {
		t.Fatal(err)
	}
	loads := map[string]error{}
	for name, svc := range stack.Services {
		if svc.Image != egressImg {
			continue
		}
		path := svc.Environment["SEALED_EGRESS_CONFIG"]
		content, found := "", false
		for _, c := range svc.Configs {
			if c.Target == path {
				content, found = strings.ReplaceAll(stack.Configs[c.Source].Content, "$$", "$"), true
			}
		}
		if !found {
			t.Fatalf("%s: no config mounted at SEALED_EGRESS_CONFIG %q", name, path)
		}
		_, loads[name] = policy.Parse([]byte(content))
	}
	if len(loads) != 2 {
		t.Fatalf("sealed-egress services in the laptop stack: %v (want sealed-egress and dc-egress2)", loads)
	}
	if err := loads["sealed-egress"]; err != nil {
		t.Errorf("the composed sealed-egress config does not load: %v", err)
	}
	if err := loads["dc-egress2"]; err == nil {
		t.Error("dc-egress2's config loads; E1 expects sealed-egress to refuse allow entries on its own app networks")
	} else {
		for _, dst := range []string{"172.30.2.17", "172.30.2.1"} {
			if !strings.Contains(err.Error(), "destination "+dst+" is a vm-internal address") {
				t.Errorf("dc-egress2 is not refused for %s as vm-internal (run.sh E1 looks for it): %v", dst, err)
			}
		}
	}
	// run.sh waits only for services that are meant to run.
	script, err := os.ReadFile(filepath.Join(dc, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	name := regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	waits := 0
	for _, line := range strings.Split(string(script), "\n") {
		code, _, _ := strings.Cut(line, "#")
		f := strings.Fields(code)
		for i := 0; i+1 < len(f); i++ {
			if _, err := strconv.Atoi(f[i+1]); f[i] != "wait_healthy" || err != nil {
				continue // not a call: wait_healthy SECONDS SERVICE...
			}
			waits++
			for _, svc := range f[i+2:] {
				svc = strings.TrimSuffix(svc, ";")
				if svc == "then" || !name.MatchString(svc) {
					break
				}
				if _, ok := stack.Services[svc]; !ok {
					t.Errorf("run.sh waits for %s, which is not in the laptop stack", svc)
				}
				if err, egress := loads[svc]; egress && err != nil {
					t.Errorf("run.sh waits for %s, whose egress config is refused: %v", svc, err)
				}
			}
		}
	}
	if waits == 0 {
		t.Error("found no wait_healthy call in run.sh; the pattern no longer matches")
	}
}

// composeDockerChecksFixture composes scripts/docker-checks/fixtures the way
// run.sh does (sealed-compose compose --fill-release-ids with this composer's
// version).
func composeDockerChecksFixture(t *testing.T) *Result {
	t.Helper()
	root := filepath.Join("..", "..")
	dc := filepath.Join(root, "scripts", "docker-checks")
	defs, err := LoadDefaults(filepath.Join(root, "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	var bundles []*Bundle
	for _, app := range []string{"alpha", "bravo"} {
		b, err := BuildBundle(BuildInput{AppDir: filepath.Join(dc, "fixtures", "apps", app), Registry: defs.Catalog.Registry})
		if err != nil {
			t.Fatalf("bundle %s: %v", app, err)
		}
		ids[b.Manifest.ID] = b.ReleaseID.Hex()
		bundles = append(bundles, b)
	}
	raw, err := os.ReadFile(filepath.Join(dc, "fixtures", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["composerVersion"] = Version
	for _, a := range doc["apps"].([]any) {
		m := a.(map[string]any)
		m["releaseId"] = ids[m["id"].(string)]
	}
	raw, _ = json.Marshal(doc)
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Compose(cfg, bundles)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestDockerChecksHostRules runs the composed pre_launch_script (host rules
// v3) twice against a fake iptables with Docker's chains, then run.sh's
// remove_host_rules. run.sh still expected composer 1.2's single edge jump
// ("jump counts FORWARD/DOCKER-USER: 2 2" failed), installed its own proposed
// SEALED-INPUT chain on top of the composer's, and its cleanup removed only
// the subnet jumps, so SEALED-EDGE and SEALED-INPUT stayed referenced and
// were never deleted from the Docker VM.
func TestDockerChecksHostRules(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not on PATH")
	}
	res := composeDockerChecksFixture(t)
	bin, state := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "iptables"), []byte(fakeIptables), 0o755); err != nil {
		t.Fatal(err)
	}
	// Docker's chains before the rules (iptables backend): FORWARD jumps to DOCKER-USER.
	for chain, rules := range map[string]string{"INPUT": "", "FORWARD": "-j DOCKER-USER\n", "DOCKER-USER": ""} {
		if err := os.WriteFile(filepath.Join(state, "chain."+chain), []byte(rules), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name, script string) {
		t.Helper()
		cmd := exec.Command(bash, "-s")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "FAKE_IPT="+state)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
	}
	chains := func() map[string][]string {
		t.Helper()
		st := map[string][]string{}
		files, _ := filepath.Glob(filepath.Join(state, "chain.*"))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			rules := []string{}
			if s := strings.TrimRight(string(b), "\n"); s != "" {
				rules = strings.Split(s, "\n")
			}
			st[strings.TrimPrefix(filepath.Base(f), "chain.")] = rules
		}
		return st
	}
	count := func(rules []string, target string) (n int) {
		for _, r := range rules {
			if strings.HasSuffix(r, "-j "+target) {
				n++
			}
		}
		return n
	}
	run("pre_launch_script", res.PreLaunchScript)
	run("pre_launch_script, second run", res.PreLaunchScript)
	st := chains()
	want := fmt.Sprintf("%d %d %d ", count(st["FORWARD"], "SEALED-EDGE"), count(st["DOCKER-USER"], "SEALED-EDGE"), count(st["INPUT"], "SEALED-INPUT"))

	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "docker-checks", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	if !strings.Contains(script, `[ "$j" = "`+want+`" ]`) {
		t.Errorf("run.sh H3 does not expect the jump counts host rules v3 leaves after two runs (FORWARD DOCKER-USER INPUT: %q)", want)
	}
	if strings.Contains(script, "-N SEALED-INPUT") || strings.Contains(script, "-A SEALED-INPUT") {
		t.Error("run.sh installs a SEALED-INPUT chain of its own; H5 must check the composer's host rules")
	}
	_, after, ok := strings.Cut(script, "\nremove_host_rules() {\n")
	if !ok {
		t.Fatal("run.sh has no remove_host_rules")
	}
	_, after, ok = strings.Cut(after, "<<'EOF'\n")
	body, _, ok2 := strings.Cut(after, "\nEOF\n")
	if !ok || !ok2 {
		t.Fatal("remove_host_rules has no host script heredoc")
	}
	run("remove_host_rules", body)
	st = chains()
	for _, c := range []string{"SEALED-EDGE", "SEALED-INPUT"} {
		if _, left := st[c]; left {
			t.Errorf("after remove_host_rules chain %s is still there (FORWARD %q, DOCKER-USER %q, INPUT %q)", c, st["FORWARD"], st["DOCKER-USER"], st["INPUT"])
		}
	}
	if fmt.Sprint(st["FORWARD"], st["DOCKER-USER"], st["INPUT"]) != "[-j DOCKER-USER] [] []" {
		t.Errorf("after remove_host_rules Docker's chains are not as before: FORWARD %q, DOCKER-USER %q, INPUT %q", st["FORWARD"], st["DOCKER-USER"], st["INPUT"])
	}
}
