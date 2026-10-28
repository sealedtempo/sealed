package composer

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func notesManifest(t *testing.T) *Manifest {
	t.Helper()
	return buildFixture(t, "notes").Manifest
}

const baseService = `services:
  notes-web:
    image: "{{image:notes-web}}"
    entrypoint: ["/usr/local/bin/notes"]
%s
`

func fragmentWith(extra string) []byte {
	return []byte(fmt.Sprintf(baseService, extra))
}

func wantFragmentError(t *testing.T, err error, service, key string) {
	t.Helper()
	var fe *FragmentError
	if !errors.As(err, &fe) {
		t.Fatalf("want FragmentError for key %q, got %v", key, err)
	}
	if fe.App != "notes" || fe.Service != service || fe.Key != key {
		t.Fatalf("want app notes service %q key %q, got %+v", service, key, fe)
	}
	if !strings.Contains(err.Error(), `app "notes"`) || (key != "" && !strings.Contains(err.Error(), fmt.Sprintf("key %q", key))) {
		t.Fatalf("error text must name app, service and key: %v", err)
	}
}

// TestEveryForbiddenKeyIsRejected covers the keys INTERFACES section 14 names
// plus other compose service keys outside the allowlist.
func TestEveryForbiddenKeyIsRejected(t *testing.T) {
	m := notesManifest(t)
	forbidden := map[string]string{
		"privileged":          "true",
		"cap_add":             "[SYS_ADMIN]",
		"cap_drop":            "[ALL]",
		"devices":             `["/dev/sda:/dev/sda"]`,
		"device_cgroup_rules": `["b 8:* rwm"]`,
		"network_mode":        "host",
		"networks":            "[apps]",
		"ports":               `["80:80"]`,
		"expose":              `["80"]`,
		"pid":                 "host",
		"ipc":                 "host",
		"uts":                 "host",
		"userns_mode":         "host",
		"cgroup":              "host",
		"cgroup_parent":       "x",
		"security_opt":        `["seccomp=unconfined"]`,
		"build":               ".",
		"env_file":            ".env",
		"secrets":             "[x]",
		"configs":             "[x]",
		"extra_hosts":         `["a:1.2.3.4"]`,
		"dns":                 "[1.1.1.1]",
		"dns_search":          "[x]",
		"dns_opt":             "[x]",
		"sysctls":             "{net.ipv4.ip_forward: 1}",
		"volumes_from":        "[x]",
		"links":               "[x]",
		"external_links":      "[x]",
		"container_name":      "x",
		"hostname":            "x",
		"domainname":          "x",
		"mac_address":         "x",
		"restart":             "always",
		"logging":             "{driver: json-file}",
		"deploy":              "{}",
		"runtime":             "runc",
		"platform":            "linux/amd64",
		"profiles":            "[x]",
		"init":                "true",
		"isolation":           "x",
		"pull_policy":         "always",
		"stdin_open":          "true",
		"tty":                 "true",
		"oom_kill_disable":    "true",
		"pids_limit":          "10",
		"storage_opt":         "{size: 1G}",
		"group_add":           "[docker]",
		"x-other":             "1",
		"develop":             "{}",
		"gpus":                "all",
		"annotations":         "{a: b}",
	}
	for key, val := range forbidden {
		t.Run(key, func(t *testing.T) {
			_, err := ParseFragment(m, fragmentWith(fmt.Sprintf("    %s: %s", key, val)))
			wantFragmentError(t, err, "notes-web", key)
		})
	}
}

func TestForbiddenMountsAndValues(t *testing.T) {
	m := notesManifest(t)
	cases := []struct {
		name, extra, key string
	}{
		{"docker socket", `    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]`, "volumes"},
		{"dstack socket", `    volumes: ["/var/run/dstack.sock:/var/run/dstack.sock"]`, "volumes"},
		{"relative bind", `    volumes: ["./data:/data"]`, "volumes"},
		{"home bind", `    volumes: ["~/x:/data"]`, "volumes"},
		{"long bind", "    volumes:\n      - {type: bind, source: /, target: /host}", "volumes"},
		{"anonymous", `    volumes: ["/data"]`, "volumes"},
		{"undeclared volume", `    volumes: ["other:/data"]`, "volumes"},
		{"volume options", `    volumes: ["uploads:/data:z"]`, "volumes"},
		{"long volume extra", "    volumes:\n      - {type: volume, source: uploads, target: /d, volume: {nocopy: true}}", "volumes"},
		{"reserved target", `    volumes: ["uploads:/run/sealed/secrets/crm"]`, "volumes"},
		{"tag image", "", "image"},
		{"interpolation", `    environment: {A: "${HOME}"}`, "environment.A"},
		{"bare interpolation", `    command: ["echo", "$HOME"]`, "command"},
		{"host env passthrough map", "    environment: {A: }", "environment"},
		{"host env passthrough list", `    environment: ["A"]`, "environment"},
		{"proxy override", `    environment: {HTTPS_PROXY: "http://evil:1"}`, "environment"},
		{"secret as env", `    environment: {APP_SECRET: "x"}`, "environment"},
		{"undeclared secret", `    x-sealed-secrets: [NOPE]`, "x-sealed-secrets"},
		{"other app dependency", `    depends_on: [crm-db]`, "depends_on"},
		{"float cpus", `    cpus: 0.5`, ""},
		{"bad healthcheck field", "    healthcheck: {test: [CMD, true], bogus: 1}", "healthcheck"},
		{"reserved label", `    labels: {com.docker.compose.project: x}`, "labels"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			frag := fragmentWith(c.extra)
			if c.name == "tag image" {
				frag = []byte("services:\n  notes-web:\n    image: ghcr.io/sealed-dev/notes-web:latest\n    entrypoint: [x]\nvolumes: {uploads: }\n")
			} else {
				frag = append(frag, []byte("volumes: {uploads: }\n")...)
			}
			_, err := ParseFragment(m, frag)
			if err == nil {
				t.Fatal("accepted")
			}
			if c.key != "" {
				wantFragmentError(t, err, "notes-web", c.key)
			}
		})
	}
}

func TestFragmentTopLevelAndNames(t *testing.T) {
	m := notesManifest(t)
	for _, top := range []string{"networks", "configs", "secrets", "name", "include", "version"} {
		_, err := ParseFragment(m, []byte(fmt.Sprintf(baseService, "")+top+": {}\n"))
		wantFragmentError(t, err, "", top)
	}
	_, err := ParseFragment(m, []byte("services:\n  web:\n    image: \"{{image:notes-web}}\"\n    entrypoint: [x]\n"))
	wantFragmentError(t, err, "web", "")
	_, err = ParseFragment(m, []byte("services:\n  notes-web:\n    image: \"{{image:notes-web}}\"\n"))
	wantFragmentError(t, err, "notes-web", "entrypoint")
	_, err = ParseFragment(m, []byte("services:\n  notes-web:\n    image: \"{{image:nope}}\"\n    entrypoint: [x]\n"))
	wantFragmentError(t, err, "notes-web", "image")
	_, err = ParseFragment(m, []byte("services:\n  notes-web:\n    image: \"{{image:notes-web}}\"\n    entrypoint: [x]\nvolumes:\n  data: {driver: local}\n"))
	wantFragmentError(t, err, "", "volumes.data")
	// The manifest's primary service must exist in the fragment.
	_, err = ParseFragment(m, []byte("services:\n  notes-other:\n    image: \"{{image:notes-web}}\"\n    entrypoint: [x]\n"))
	var me *ManifestError
	if !errors.As(err, &me) || me.Field != "primary_service" {
		t.Fatalf("want primary_service error, got %v", err)
	}
	// Cycles.
	cyc := "services:\n" +
		"  notes-web: {image: \"{{image:notes-web}}\", entrypoint: [x], depends_on: [notes-db]}\n" +
		"  notes-db: {image: \"{{image:postgres}}\", entrypoint: [x], depends_on: [notes-web]}\n"
	if _, err := ParseFragment(m, []byte(cyc)); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle accepted: %v", err)
	}
}

func TestFragmentLiteralDollars(t *testing.T) {
	m := notesManifest(t)
	f, err := ParseFragment(m, fragmentWith(`    environment: {PRICE: "costs $$5", LONE: "a $ b"}`))
	if err != nil {
		t.Fatal(err)
	}
	env := f.Service("notes-web").Environment
	if env["PRICE"] != "costs $5" || env["LONE"] != "a $ b" {
		t.Fatalf("env %q", env)
	}
}

func TestFragmentRequiresImagePlaceholders(t *testing.T) {
	m := notesManifest(t)
	img, _ := m.Image("notes-web")
	frag := fmt.Sprintf("services:\n  notes-web:\n    image: %s\n    entrypoint: [x]\n", img.Ref)
	_, err := ParseFragment(m, []byte(frag))
	wantFragmentError(t, err, "notes-web", "image")
	f, err := ParseFragment(m, fragmentWith(""))
	if err != nil || f.Service("notes-web").Image != "notes-web" {
		t.Fatalf("placeholder: %v", err)
	}
}

func TestParseManifestErrors(t *testing.T) {
	b := buildFixture(t, "notes")
	base := string(b.Files[ManifestFile])
	cases := map[string]string{
		"unknown field":    base + "extra: 1\n",
		"float":            strings.Replace(base, "maintainer_share_bps: 2000", "maintainer_share_bps: 20.5", 1),
		"share too high":   strings.Replace(base, "maintainer_share_bps: 2000", "maintainer_share_bps: 6000", 1),
		"bad digest":       strings.Replace(base, "sha256:1111", "sha256:XXXX", 1),
		"primary prefix":   strings.Replace(base, "primary_service: notes-web", "primary_service: web", 1),
		"tokens heartbeat": strings.Replace(base, "{unit: app_hour, source: heartbeat}", "{unit: tokens, source: heartbeat}", 1),
		"reserved secret":  strings.Replace(base, "name: APP_SECRET", "name: GATE_PASSWORD_BCRYPT", 1),
		"two documents":    base + "---\nid: x\n",
		"reserved env":     strings.Replace(base, "NOTES_TELEMETRY: \"0\"", "HTTPS_PROXY: \"x\"", 1),
	}
	for name, src := range cases {
		if _, err := ParseManifest([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseManifest([]byte(base)); err != nil {
		t.Fatal(err)
	}
}

func TestParseEgressPolicy(t *testing.T) {
	good := []byte("version: 1\ndefault_allow: [\"api.example.com:443\", \"*.example.org:443\", \"1.2.3.4:8443\"]\ncustomer_additions_allowed: false\n")
	p, hash, err := ParseEgressPolicy(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.DefaultAllow) != 3 || hash.IsZero() {
		t.Fatalf("%+v", p)
	}
	bad := []string{
		"version: 2\ndefault_allow: []\ncustomer_additions_allowed: true\n",
		"version: 1\ndefault_allow: [\"API.example.com:443\"]\ncustomer_additions_allowed: true\n",
		"version: 1\ndefault_allow: [\"example:443\"]\ncustomer_additions_allowed: true\n",
		"version: 1\ndefault_allow: [\"*.com:443\"]\ncustomer_additions_allowed: true\n",
		"version: 1\ndefault_allow: [\"a.example.com\"]\ncustomer_additions_allowed: true\n",
		"version: 1\ndefault_allow: [\"a.example.com:0443\"]\ncustomer_additions_allowed: true\n",
		"version: 1\ndefault_allow: [\"[::1]:443\"]\ncustomer_additions_allowed: true\n",
		"version: 1\ndefault_allow: [\"a.example.com:443\", \"a.example.com:443\"]\ncustomer_additions_allowed: true\n",
		"version: 1\ndefault_allow: []\n",
		"version: 1\ndefault_allow: []\ncustomer_additions_allowed: true\nextra: 1\n",
	}
	for _, src := range bad {
		if _, _, err := ParseEgressPolicy([]byte(src)); err == nil {
			t.Errorf("accepted %q", src)
		}
	}
}

func TestTmpfsKeyRules(t *testing.T) {
	m := notesManifest(t)
	bad := []string{
		`    tmpfs: ["/run/sealed/ready"]`,
		`    tmpfs: ["/run/sealed"]`,
		`    tmpfs: ["/sealed/bin"]`,
		`    tmpfs: ["/var/run/dstack.sock"]`,
		`    tmpfs: ["/../run/sealed/secrets/notes"]`,
		`    tmpfs: ["/tmp/../run/sealed"]`,
		`    tmpfs: ["relative"]`,
		`    tmpfs: ["/"]`,
		`    tmpfs: ["/tmp:exec"]`,
		`    tmpfs: ["/tmp:exec,suid,dev,size=100g"]`,
		`    tmpfs: ["/tmp:size=1g,size=2g"]`,
		`    tmpfs: ["/tmp:mode=999"]`,
		`    tmpfs: ["/tmp:size=1.5g"]`,
		`    tmpfs: ["/tmp:uid=0"]`,
		`    tmpfs: ["/tmp", "/tmp"]`,
		"    tmpfs: [\"/data\"]\n    volumes: [\"uploads:/data\"]",
		"    volumes:\n      - {type: tmpfs, target: /tmp, tmpfs: {size: [1]}}",
	}
	for _, extra := range bad {
		frag := append(fragmentWith(extra), []byte("volumes: {uploads: }\n")...)
		_, err := ParseFragment(m, frag)
		if err == nil {
			t.Errorf("accepted %q", extra)
			continue
		}
		var fe *FragmentError
		if !errors.As(err, &fe) || fe.Service != "notes-web" || (fe.Key != "tmpfs" && fe.Key != "volumes") {
			t.Errorf("%q: %v", extra, err)
		}
	}
	for _, extra := range []string{`    tmpfs: ["/tmp:size=1g,mode=1777"]`, `    tmpfs: /run/app`, `    tmpfs: ["/tmp:size=65536k", "/var/cache"]`} {
		if _, err := ParseFragment(m, fragmentWith(extra)); err != nil {
			t.Errorf("%q rejected: %v", extra, err)
		}
	}
}

func TestRouteAuthMustBeGate(t *testing.T) {
	notes := buildFixture(t, "notes")
	base := string(notes.Files[ManifestFile])
	for _, auth := range []string{AuthPublic, AuthBearerPassthrough} {
		src := strings.Replace(base, "auth: gate", "auth: "+auth, 1)
		_, err := ParseManifest([]byte(src))
		var me *ManifestError
		if !errors.As(err, &me) || me.Field != "routes[0].auth" {
			t.Errorf("notes route with auth %s: %v", auth, err)
		}
	}
	// The two exceptions: the gateway API and the platform relay.
	gw := buildFixture(t, "llm-gateway").Manifest
	if gw.Routes[0].Auth != AuthBearerPassthrough {
		t.Fatal("fixture changed")
	}
	if err := gw.validate(); err != nil {
		t.Fatal(err)
	}
	gw.Routes[0].Auth = AuthPublic
	if err := gw.validate(); err == nil {
		t.Error("public gateway route accepted")
	}
	relay := *notes.Manifest
	relay.ID, relay.PrimaryService = "inference-relay", "inference-relay-front"
	relay.Healthcheck.Service = "inference-relay-front"
	relay.Routes = []Route{{Name: "relay", Service: "inference-relay-front", InternalPort: 8080, PathOrHost: "relay", Auth: AuthPublic}}
	if err := relay.validate(); err != nil {
		t.Fatalf("relay public route: %v", err)
	}
	relay.Routes[0].Auth = AuthBearerPassthrough
	if err := relay.validate(); err == nil {
		t.Error("relay bearer route accepted")
	}
	relay.Routes[0] = Route{Name: "tools", Service: "inference-relay-front", InternalPort: 8080, PathOrHost: "tools", Auth: AuthPublic}
	if err := relay.validate(); err == nil {
		t.Error("public route under another name accepted")
	}
}

func TestBootstrapDoneFile(t *testing.T) {
	base := string(buildFixture(t, "notes").Files[ManifestFile])
	// notes-db also gets a service-level tmpfs, like the coding-agent bootstrap job.
	frag := []byte(strings.Replace(string(buildFixture(t, "notes").Files[FragmentFile]),
		"    shm_size: 128m", "    shm_size: 128m\n    tmpfs: [\"/run/bootstrap:size=1m,mode=1777\"]", 1))
	parse := func(doneFile, service string) (*Manifest, error) {
		src := base + "bootstrap:\n"
		if service != "" {
			src += "  service: " + service + "\n"
		}
		src += "  done_file: \"" + doneFile + "\"\n"
		m, err := ParseManifest([]byte(src))
		if err != nil {
			return nil, err
		}
		_, err = ParseFragment(m, frag)
		return m, err
	}
	for _, bad := range []struct{ file, service string }{
		{"../../../../etc/shadow", "notes-web"},
		{"pgdata/../../etc/shadow", "notes-web"},
		{"pgdata/./x", "notes-web"},
		{"pgdata//x", "notes-web"},
		{"pgdata/", "notes-web"},
		{"pgdata", "notes-web"},
		{"/done", "notes-web"},
		{"/etc/shadow", "notes-web"},
		{"/run/bootstrap/done", "notes-web"},
		{"/run/sealed/ready/ok", "notes-web"},
		{"/var/lib/notes/uploads/../../../etc/shadow", "notes-web"},
		{"other/done", "notes-web"},
		{"pgdata/x y", "notes-web"},
		{"/var/lib/postgresql/data/done", ""},
	} {
		if _, err := parse(bad.file, bad.service); err == nil {
			t.Errorf("done_file %q accepted", bad.file)
		}
	}
	for _, good := range []struct{ file, service, want string }{
		{"pgdata/bootstrap/done.json", "notes-web", "/mnt/sealed-data/notes/pgdata/bootstrap/done.json"},
		{"uploads/.sealed/done", "", "/mnt/sealed-data/notes/uploads/.sealed/done"},
		{"/var/lib/postgresql/data/sealed.done", "notes-db", "/mnt/sealed-data/notes/pgdata/sealed.done"},
		// On the bootstrap container's own tmpfs: not on the data disk.
		{"/tmp/sealed/done", "notes-web", ""},
		{"/run/bootstrap/done", "notes-db", ""},
	} {
		m, err := parse(good.file, good.service)
		if err != nil {
			t.Errorf("done_file %q: %v", good.file, err)
			continue
		}
		f, _ := ParseFragment(m, frag)
		if p, err := ResolveDoneFile(m, f); err != nil || p != good.want {
			t.Errorf("done_file %q resolved to %q (%v), want %q", good.file, p, err, good.want)
		}
	}
}

func TestEgressRejectsSpecialUseLiterals(t *testing.T) {
	for _, e := range []string{
		"169.254.169.254:80", "127.0.0.1:80", "0.0.0.0:443", "10.0.0.1:443", "172.16.5.4:443", "192.168.1.1:443",
		"100.64.0.1:443", "224.0.0.1:443", "255.255.255.255:443", "240.0.0.1:443", "198.18.0.1:443",
		"192.0.0.8:443", "192.88.99.1:443", "01.2.3.4:443",
	} {
		if _, err := ParseHostPort(e); err == nil {
			t.Errorf("%s accepted", e)
		}
		src := "version: 1\ndefault_allow: [\"" + e + "\"]\ncustomer_additions_allowed: false\n"
		if _, _, err := ParseEgressPolicy([]byte(src)); err == nil {
			t.Errorf("egress.yaml with %s accepted", e)
		}
	}
	for _, e := range []string{"1.2.3.4:443", "8.8.8.8:53", "203.0.113.7:443"} {
		if _, err := ParseHostPort(e); err != nil {
			t.Errorf("%s: %v", e, err)
		}
	}
	vpc := []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}
	if _, err := ParseHostPortIn("10.10.3.4:5432", vpc); err != nil {
		t.Errorf("address inside allowedVpcRanges: %v", err)
	}
	if _, err := ParseHostPortIn("10.11.3.4:5432", vpc); err == nil {
		t.Error("private address outside allowedVpcRanges accepted")
	}
	if _, err := ParseHostPortIn("169.254.169.254:80", []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}); err == nil {
		t.Error("metadata address accepted through a range")
	}
	many := make([]string, MaxEgressAllowEntries+1)
	for i := range many {
		many[i] = fmt.Sprintf("\"h%d.example.com:443\"", i)
	}
	src := "version: 1\ndefault_allow: [" + strings.Join(many, ",") + "]\ncustomer_additions_allowed: false\n"
	if _, _, err := ParseEgressPolicy([]byte(src)); err == nil {
		t.Error("oversized default_allow accepted")
	}
}
