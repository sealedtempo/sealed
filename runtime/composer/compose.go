package composer

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/sealed-dev/sealed/runtime/caddy"
	"github.com/sealed-dev/sealed/runtime/composer/cjson"
)

// Result is a composed stack. Every byte slice is deterministic for the same
// config, bundles and composer version.
type Result struct {
	AppCompose             []byte // exact app-compose.json bytes; stackHash = sha256(AppCompose)
	StackHash              Hash
	ConfigHash             Hash
	DeploymentID           Hash
	ComposeJSON            []byte // the docker compose document (CJSON), docker_compose_file
	ConfigJSON             []byte // CJSON of the normalized public config
	EgressConfig           []byte // CJSON sealed-egress config (INTERFACES section 12)
	Caddyfile              []byte
	CaddyfilePaymentNeeded []byte
	StackInfo              []byte // CJSON sealed-stack/v1 document for sealed-agent
	PreLaunchScript        string // host rules (INTERFACES section 15)
	// Unbuilt lists images whose digest is still the all-zero placeholder.
	// Such a stack cannot boot; release tooling refuses it via RequireBuilt.
	Unbuilt []string
}

// RequireBuilt fails when any image of the stack still has the all-zero
// placeholder digest. Release tooling and approval flows call it; local
// development composes such stacks to inspect them.
func (r *Result) RequireBuilt() error {
	if len(r.Unbuilt) == 0 {
		return nil
	}
	return fmt.Errorf("compose: stack uses unbuilt images (all-zero digests): %s", strings.Join(r.Unbuilt, ", "))
}

// In-VM paths and ports shared with the sidecars (documented in README.md).
const (
	ProjectName          = "sealed"
	ProxyURL             = "http://" + EgressAppsIP + ":3128"
	DataRoot             = "/mnt/sealed-data"
	SecretsRoot          = "/run/sealed/secrets"
	ReadyDir             = "/run/sealed/ready"
	BinDir               = "/sealed/bin"
	EnvexecPath          = BinDir + "/envexec"
	CaddyAdminDir        = "/run/sealed/caddy-admin"
	DstackSocket         = "/var/run/dstack.sock"
	DataDeviceHost       = "/dev/disk/by-id/google-sealed-data"
	DataDevice           = "/dev/sealed-data"
	ConfigPath           = "/etc/sealed/config.json"
	StackPath            = "/etc/sealed/stack.json"
	EgressConfigPath     = "/etc/sealed/egress.json"
	AgentCaddyfilePath   = "/etc/sealed/caddy/Caddyfile"
	AgentCaddyfilePNPath = "/etc/sealed/caddy/Caddyfile.payment-needed"
	CaddyfilePath        = "/etc/caddy/Caddyfile"
	AgentPort            = 7070
	PayerPort            = 8090
	VerifierdPort        = 8088
	GateApp              = "_gate"
	// GateCookieMaxAge is the sealed_gate cookie lifetime (12 h, D-044).
	GateCookieMaxAge = 12 * 3600
	// AgentRunAs is the uid:gid sealed-agent drops to. Caddy's admin socket
	// lives on a tmpfs it owns, so it needs no root helper.
	AgentRunAs = "10001:10001"
	agentUID   = "10001"
	ACMEHost   = "acme-v02.api.letsencrypt.org:443"
	// MaxAppComposeBytes is dstack v0.6.1's cap on app-compose.json (the
	// guest refuses larger files at boot), so a larger stack could be
	// approved but never start.
	MaxAppComposeBytes = 50 << 20
)

// Caddy's ACME account and certificates live on the encrypted data disk.
const (
	caddyDataApp    = "_caddy"
	caddyDataVolume = "data"
)

// Sidecar service names.
const (
	svcInit      = "sealed-init"
	svcEgress    = "sealed-egress"
	svcAgent     = "sealed-agent"
	svcCaddy     = "caddy"
	svcPayer     = "sealed-mpp-payer"
	svcVerifierd = "sealed-verifierd"
	gatewayApp   = "llm-gateway"
)

// Intel PCS hosts the in-VM verifier needs for quote collateral and CRLs.
var intelPCSHosts = []string{"api.trustedservices.intel.com:443", "certificates.trustedservices.intel.com:443"}

// Compose builds the stack for a config and its release bundles using the
// embedded runtime images.
func Compose(cfg *Config, bundles []*Bundle) (*Result, error) {
	ri, err := LoadRuntimeImages()
	if err != nil {
		return nil, err
	}
	return ComposeWith(cfg, bundles, ri)
}

type plannedApp struct {
	id        string
	n         int // app number: network app-<id>, subnet 172.30.<n>.0/24
	bundle    *Bundle
	services  []*plannedService // sorted by name
	additions []string
}

// network is the app's own compose network.
func (a *plannedApp) network() string { return AppNetwork(a.id) }

// egressIP and agentIP are the sidecars' addresses on the app network; the
// app's services use egressIP for DNS and the HTTP(S) proxy.
func (a *plannedApp) egressIP() string { return appNetIP(a.n, appNetEgressHost) }
func (a *plannedApp) agentIP() string  { return appNetIP(a.n, appNetAgentHost) }
func (a *plannedApp) proxyURL() string { return "http://" + a.egressIP() + ":3128" }

type plannedService struct {
	app     *plannedApp
	spec    *ServiceSpec
	netIP   string // address on the app network
	appsIP  string // address on the shared apps network; primary only
	primary bool
}

// networks maps each network the service joins to its address.
func (s *plannedService) networks() map[string]string {
	m := map[string]string{s.app.network(): s.netIP}
	if s.appsIP != "" {
		m["apps"] = s.appsIP
	}
	return m
}

// ips are every address the service owns, sorted.
func (s *plannedService) ips() []string {
	out := []string{s.netIP}
	if s.appsIP != "" {
		out = append(out, s.appsIP)
	}
	sortIPs(out)
	return out
}

func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool { return netip.MustParseAddr(ips[i]).Less(netip.MustParseAddr(ips[j])) })
}

// ComposeWith is Compose with an explicit runtime image set.
func ComposeWith(cfg *Config, bundles []*Bundle, ri *RuntimeImages) (*Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	apps, err := planApps(cfg, bundles)
	if err != nil {
		return nil, err
	}
	if err := checkImageRefs(apps, ri); err != nil {
		return nil, err
	}
	if err := checkSameAs(apps); err != nil {
		return nil, err
	}
	hasGateway := false
	for _, a := range apps {
		if a.id == gatewayApp {
			hasGateway = true
		}
	}
	if hasGateway {
		if cfg.Endpoints.Relay == "" || cfg.Endpoints.RelayAttest == "" || cfg.RelayOwner == "" {
			return nil, fmt.Errorf("config: endpoints.relay, endpoints.relayAttest and relayOwner are required when %s is in the stack", gatewayApp)
		}
		if err := checkRelayOrigin(cfg.Endpoints.Relay, cfg.Endpoints.RelayAttest); err != nil {
			return nil, err
		}
	}
	routes, err := planRoutes(cfg, apps)
	if err != nil {
		return nil, err
	}

	configJSON, err := cfg.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	res := &Result{ConfigJSON: configJSON, ConfigHash: SHA256(configJSON)}

	if res.EgressConfig, err = buildEgressConfig(cfg, apps, hasGateway); err != nil {
		return nil, err
	}
	caddyIn, err := caddyInput(cfg, routes)
	if err != nil {
		return nil, err
	}
	if res.Caddyfile, err = caddy.Render(caddyIn, false); err != nil {
		return nil, err
	}
	if res.CaddyfilePaymentNeeded, err = caddy.Render(caddyIn, true); err != nil {
		return nil, err
	}
	if res.StackInfo, err = buildStackInfo(cfg, apps, routes, hasGateway); err != nil {
		return nil, err
	}
	doc, err := buildComposeDoc(cfg, apps, routes, ri, hasGateway, res)
	if err != nil {
		return nil, err
	}
	escaped := escapeDollars(doc)
	if res.ComposeJSON, err = cjson.Encode(escaped); err != nil {
		return nil, fmt.Errorf("compose: %w", err)
	}
	if res.PreLaunchScript, err = HostRulesScript(EdgeSubnet, EgressEdgeIP); err != nil {
		return nil, err
	}
	if res.AppCompose, err = AppComposeJSON(string(res.ComposeJSON), res.PreLaunchScript, res.ConfigHash); err != nil {
		return nil, err
	}
	if len(res.AppCompose) > MaxAppComposeBytes {
		return nil, fmt.Errorf("compose: app-compose.json is %d bytes, over dstack's %d-byte limit", len(res.AppCompose), MaxAppComposeBytes)
	}
	res.StackHash = SHA256(res.AppCompose)
	customer, _ := ParseAddress(cfg.Customer)
	salt, _ := ParseHash(cfg.Salt)
	res.DeploymentID = DeploymentID(customer, res.StackHash, salt)

	for _, name := range ri.Unbuilt() {
		if (name == imgPayer || name == imgVerifierd) && !hasGateway {
			continue
		}
		res.Unbuilt = append(res.Unbuilt, "runtime/"+name)
	}
	for _, a := range apps {
		for _, img := range a.bundle.Manifest.Images {
			if img.Unbuilt() {
				res.Unbuilt = append(res.Unbuilt, a.id+"/"+img.Name)
			}
		}
	}
	return res, nil
}

// AppComposeJSON returns app-compose.json (dstack v0.6.1, manifest_version 2)
// serialized as CJSON with exactly the INTERFACES section 6 field set.
func AppComposeJSON(composeJSON, preLaunchScript string, configHash Hash) ([]byte, error) {
	return cjson.Encode(map[string]any{
		"allowed_envs":               []any{},
		"docker_compose_file":        composeJSON,
		"gateway_enabled":            false,
		"key_provider":               "tpm",
		"key_provider_id":            "",
		"kms_enabled":                false,
		"local_key_provider_enabled": false,
		"manifest_version":           2,
		"name":                       "sealed-" + configHash.Hex()[2:10],
		"no_instance_id":             false,
		"pre_launch_script":          preLaunchScript,
		"public_logs":                false,
		"public_sysinfo":             false,
		"public_tcbinfo":             true,
		"runner":                     "docker-compose",
		"secure_time":                false,
		"storage_fs":                 "ext4",
	})
}

func planApps(cfg *Config, bundles []*Bundle) ([]*plannedApp, error) {
	byID := map[string]*Bundle{}
	for _, b := range bundles {
		if b == nil {
			return nil, fmt.Errorf("compose: nil bundle")
		}
		if _, dup := byID[b.Manifest.ID]; dup {
			return nil, fmt.Errorf("compose: two bundles for app %q", b.Manifest.ID)
		}
		byID[b.Manifest.ID] = b
	}
	var apps []*plannedApp
	for i, ca := range cfg.Apps {
		b, ok := byID[ca.ID]
		if !ok {
			return nil, fmt.Errorf("compose: no bundle for app %q", ca.ID)
		}
		delete(byID, ca.ID)
		if b.ReleaseID.Hex() != ca.ReleaseID {
			return nil, fmt.Errorf("compose: apps[%d] %q: releaseId %s does not match the bundle (keccak256(abi.encode(appId, %q, %s)) = %s)",
				i, ca.ID, ca.ReleaseID, b.Version(), b.Hash.Hex(), b.ReleaseID.Hex())
		}
		a := &plannedApp{id: ca.ID, bundle: b}
		adds := cfg.EgressAdditions[ca.ID]
		if len(adds) > 0 && !b.Egress.CustomerAdditionsAllowed {
			return nil, fmt.Errorf("config: egressAdditions.%s: app %q does not allow customer egress additions", ca.ID, ca.ID)
		}
		a.additions = adds
		apps = append(apps, a)
	}
	if len(byID) > 0 {
		return nil, fmt.Errorf("compose: bundles for apps not in the config: %s", strings.Join(sortedKeys(byID), ", "))
	}
	// Primary services get .16, .17, ... on the shared apps network in app
	// order. On its own network (app number n = position + 1) each app's
	// primary gets .16 and the other services .17, ... in name order.
	for i, a := range apps {
		a.n = i + 1
		primary := a.bundle.Fragment.Service(a.bundle.Manifest.PrimaryService)
		host := firstAppHost
		next := func() (string, error) {
			if host > lastAppHost {
				return "", fmt.Errorf("compose: app %q has more than %d services", a.id, lastAppHost-firstAppHost+1)
			}
			ip := appNetIP(a.n, host)
			host++
			return ip, nil
		}
		netIP, err := next()
		if err != nil {
			return nil, err
		}
		a.services = append(a.services, &plannedService{app: a, spec: primary, primary: true, netIP: netIP,
			appsIP: "172.30.0." + strconv.Itoa(firstAppHost+i)})
		for _, s := range a.bundle.Fragment.Services {
			if s.Name == a.bundle.Manifest.PrimaryService {
				continue
			}
			ip, err := next()
			if err != nil {
				return nil, err
			}
			a.services = append(a.services, &plannedService{app: a, spec: s, netIP: ip})
		}
		sort.Slice(a.services, func(i, j int) bool { return a.services[i].spec.Name < a.services[j].spec.Name })
	}
	// Names and aliases share Docker's DNS namespace.
	names := map[string]string{}
	for _, s := range []string{svcInit, svcEgress, svcAgent, svcCaddy, svcPayer, svcVerifierd} {
		names[s] = "sidecar"
	}
	claim := func(name, owner string) error {
		if prev, ok := names[name]; ok {
			return fmt.Errorf("compose: name %q is used by both %s and %s", name, prev, owner)
		}
		names[name] = owner
		return nil
	}
	for _, a := range apps {
		if err := claim(a.id, "app "+a.id+" (alias)"); err != nil {
			return nil, err
		}
		for _, s := range a.services {
			if err := claim(s.spec.Name, "app "+a.id); err != nil {
				return nil, err
			}
		}
	}
	return apps, nil
}

// checkImageRefs requires every app image to come from the catalog registry
// of the runtime image set: VMs pull only from there (spec 5.3), and image
// pulls do not go through sealed-egress. Digests already pin the content.
func checkImageRefs(apps []*plannedApp, ri *RuntimeImages) error {
	for _, a := range apps {
		for i, img := range a.bundle.Manifest.Images {
			want := ri.Registry + "/" + img.Name + "@" + img.Digest
			if img.Ref != want {
				return &ManifestError{App: a.id, Field: fmt.Sprintf("images[%d].ref", i),
					Msg: fmt.Sprintf("%q is not %q; bundles must be built for the catalog registry %s", img.Ref, want, ri.Registry)}
			}
		}
	}
	return nil
}

// checkSameAs validates cross-app secret references (D-043): the referenced
// app is in the stack and declares the secret, which is not itself a
// reference, and a required secret does not depend on an optional one.
func checkSameAs(apps []*plannedApp) error {
	byID := map[string]*plannedApp{}
	for _, a := range apps {
		byID[a.id] = a
	}
	for _, a := range apps {
		for i, sec := range a.bundle.Manifest.Secrets {
			refApp, refName, ok := sec.SameAsRef()
			if !ok {
				continue
			}
			field := fmt.Sprintf("secrets[%d].same_as", i)
			fail := func(format string, args ...any) error {
				return &ManifestError{App: a.id, Field: field, Msg: fmt.Sprintf(format, args...)}
			}
			target, ok := byID[refApp]
			if !ok {
				return fail("%q: app %q is not in this stack; deploy it together with %s", sec.SameAs, refApp, a.id)
			}
			ref, ok := target.bundle.Manifest.Secret(refName)
			if !ok {
				return fail("%q: app %q declares no secret %q", sec.SameAs, refApp, refName)
			}
			if ref.SameAs != "" {
				return fail("%q is itself a reference (same_as %q); point at the original secret", sec.SameAs, ref.SameAs)
			}
			if ref.Optional && !sec.Optional {
				return fail("%q is optional in %s, so the required secret %s could be missing", sec.SameAs, refApp, sec.Name)
			}
		}
	}
	return nil
}

// checkRelayOrigin requires endpoints.relay to be exactly the origin of
// endpoints.relayAttest (D-045): the relay is served on its deployment's
// attest host, and the payer pins relay requests to the attested TLS key.
func checkRelayOrigin(relay, relayAttest string) error {
	r, err := url.Parse(relay)
	if err != nil {
		return fmt.Errorf("config: endpoints.relay: %v", err)
	}
	a, err := url.Parse(relayAttest)
	if err != nil {
		return fmt.Errorf("config: endpoints.relayAttest: %v", err)
	}
	if r.Path != "" || r.RawQuery != "" || r.Fragment != "" || r.Opaque != "" {
		return fmt.Errorf("config: endpoints.relay: %q must be an origin (scheme and host, no path or trailing slash)", relay)
	}
	if r.Scheme != a.Scheme || r.Host != a.Host {
		return fmt.Errorf("config: endpoints.relay: %q must equal the origin of endpoints.relayAttest (%s://%s): the relay is served on its deployment's attest host", relay, a.Scheme, a.Host)
	}
	return nil
}

type plannedRoute struct {
	name    string
	host    string
	app     string
	route   Route
	service string
}

// publicURL is the route's public origin, SEALED_PUBLIC_URL_<ROUTE>.
func (r plannedRoute) publicURL() string { return "https://" + r.host }

// PublicURLEnv is the environment variable that carries a route's public
// origin: SEALED_PUBLIC_URL_ plus the route name upper-cased, "-" as "_".
func PublicURLEnv(route string) string {
	return PublicURLEnvPrefix + strings.ToUpper(strings.ReplaceAll(route, "-", "_"))
}

func planRoutes(cfg *Config, apps []*plannedApp) ([]plannedRoute, error) {
	attestHost, err := cfg.Hostname("attest")
	if err != nil {
		return nil, err
	}
	owner := map[string]string{}
	onAttest := map[string]bool{}
	var out []plannedRoute
	for _, a := range apps {
		for _, r := range a.bundle.Manifest.Routes {
			if prev, ok := owner[r.Name]; ok && prev != a.id {
				return nil, fmt.Errorf("compose: route %q is claimed by both %s and %s", r.Name, prev, a.id)
			}
			owner[r.Name] = a.id
			host := attestHost
			if r.OnAttestHost {
				onAttest[r.Name] = true
			} else if host, err = cfg.Hostname(r.Name); err != nil {
				return nil, err
			}
			out = append(out, plannedRoute{name: r.Name, host: host, app: a.id, route: r, service: r.Service})
		}
	}
	for _, r := range out {
		if onAttest[r.name] != r.route.OnAttestHost {
			return nil, fmt.Errorf("compose: route %q: either every entry or none sets on_attest_host", r.name)
		}
	}
	if cfg.Hostnames.Scheme == SchemeCustom {
		for _, route := range sortedKeys(cfg.Hostnames.Domains) {
			if route == "attest" {
				continue
			}
			if _, used := owner[route]; !used {
				return nil, fmt.Errorf("config: hostnames.domains.%s: no app in this stack has that route", route)
			}
			if onAttest[route] {
				return nil, fmt.Errorf("config: hostnames.domains.%s: route %s is served on the attest host and has no domain of its own", route, route)
			}
		}
	}
	return out, nil
}

func caddyInput(cfg *Config, routes []plannedRoute) (caddy.Input, error) {
	attestHost, err := cfg.Hostname("attest")
	if err != nil {
		return caddy.Input{}, err
	}
	sitesByHost := map[string]*caddy.Site{}
	var order []string
	var attestRoutes []caddy.Route
	for _, r := range routes {
		cr := caddy.Route{
			Name:     r.name,
			Path:     r.route.PathPrefix(),
			Upstream: r.service + ":" + strconv.Itoa(r.route.InternalPort),
			Auth:     r.route.Auth,
		}
		if r.route.OnAttestHost {
			attestRoutes = append(attestRoutes, cr)
			continue
		}
		s, ok := sitesByHost[r.host]
		if !ok {
			s = &caddy.Site{Host: r.host}
			sitesByHost[r.host] = s
			order = append(order, r.host)
		}
		s.Routes = append(s.Routes, cr)
	}
	sort.Strings(order)
	in := caddy.Input{
		ComposerVersion: Version,
		AdminSocket:     caddy.DefaultAdminSocket,
		AdminSocketMode: caddy.DefaultAdminSocketMode,
		GateUpstream:    svcAgent + ":" + strconv.Itoa(AgentPort),
		GatePath:        caddy.DefaultGatePath,
		PageDir:         caddy.DefaultPageDir,
		PageFile:        caddy.DefaultPageFile,
		AttestHost:      attestHost,
		AttestUpstream:  svcAgent + ":" + strconv.Itoa(AgentPort),
		AttestRoutes:    attestRoutes,
	}
	for _, h := range order {
		in.Sites = append(in.Sites, *sitesByHost[h])
	}
	return in, nil
}

// Egress caller-name suffixes. A caller is one source address: a service's
// address on its app network keeps the service name, a primary's address on
// the shared apps network adds callerAppsSuffix, and sealed-agent's address
// on an app network adds "--" plus the network name.
const callerAppsSuffix = "--apps"

func buildEgressConfig(cfg *Config, apps []*plannedApp, hasGateway bool) ([]byte, error) {
	hp := endpointHostPort
	keyBroker, err := hp("endpoints.keyBroker", cfg.Endpoints.KeyBroker)
	if err != nil {
		return nil, err
	}
	platformAPI, err := hp("endpoints.platformApi", cfg.Endpoints.PlatformAPI)
	if err != nil {
		return nil, err
	}
	tempoRPC, err := hp("endpoints.tempoRpc", cfg.Endpoints.TempoRPC)
	if err != nil {
		return nil, err
	}
	type caller struct {
		name  string
		ip    string
		allow []string
	}
	agentAllow := []string{keyBroker, platformAPI, tempoRPC}
	callers := []caller{
		{svcAgent, AgentIP, agentAllow},
		{svcCaddy, CaddyIP, []string{ACMEHost}},
	}
	for _, a := range apps {
		callers = append(callers, caller{svcAgent + "--" + a.network(), a.agentIP(), agentAllow})
	}
	if hasGateway {
		relay, err := hp("endpoints.relay", cfg.Endpoints.Relay)
		if err != nil {
			return nil, err
		}
		relayAttest, err := hp("endpoints.relayAttest", cfg.Endpoints.RelayAttest)
		if err != nil {
			return nil, err
		}
		callers = append(callers,
			caller{svcPayer, PayerIP, []string{relay, tempoRPC}},
			caller{svcVerifierd, VerifierdIP, append([]string{tempoRPC, relayAttest}, intelPCSHosts...)})
	}
	for _, a := range apps {
		allow := append(append([]string{}, a.bundle.Egress.DefaultAllow...), a.additions...)
		for _, s := range a.services {
			callers = append(callers, caller{s.spec.Name, s.netIP, allow})
			if s.appsIP != "" {
				callers = append(callers, caller{s.spec.Name + callerAppsSuffix, s.appsIP, allow})
			}
		}
	}
	sort.Slice(callers, func(i, j int) bool {
		return netip.MustParseAddr(callers[i].ip).Less(netip.MustParseAddr(callers[j].ip))
	})
	list := make([]any, 0, len(callers))
	for _, c := range callers {
		list = append(list, map[string]any{"name": c.name, "ip": c.ip, "allow": toAny(sortedStrings(c.allow))})
	}
	return cjson.Encode(map[string]any{
		"listen":              map[string]any{"proxy": ":3128", "dns": ":53", "stats": ":9100"},
		"upstreamDns":         []any{"8.8.8.8:53", "8.8.4.4:53"},
		"callers":             list,
		"allowedPrivateCidrs": toAny(cfg.AllowedVpcRanges),
		"statsReaders":        []any{AgentIP},
	})
}

// secretFile is the in-VM path of one secret file; the same path on the
// host (a tmpfs written by sealed-agent) and in the container.
func secretFile(owner, name string) string { return SecretsRoot + "/" + owner + "/" + name }

// payerSecrets are the files sealed-agent writes for sealed-mpp-payer
// (INTERFACES section 15).
var payerSecrets = []string{"ENCLAVE_KEY", "SPEND_LIMIT_PER_DAY"}

// secretFiles lists every secret file bind-mounted into the stack, sorted:
// sealed-agent writes each one (empty for an optional secret the customer
// did not set) before it opens the ready gate.
func secretFiles(apps []*plannedApp, hasGateway bool) []string {
	var out []string
	for _, a := range apps {
		for _, s := range a.services {
			for _, n := range s.spec.Secrets {
				out = append(out, secretFile(a.id, n))
			}
		}
	}
	if hasGateway {
		for _, n := range payerSecrets {
			out = append(out, secretFile(svcPayer, n))
		}
	}
	return sortedStrings(out)
}

func buildStackInfo(cfg *Config, apps []*plannedApp, routes []plannedRoute, hasGateway bool) ([]byte, error) {
	var appList []any
	for _, a := range apps {
		m := a.bundle.Manifest
		var svcs, secrets, rts []any
		for _, s := range a.services {
			nets := map[string]any{}
			for k, v := range s.networks() {
				nets[k] = v
			}
			svcs = append(svcs, map[string]any{
				"name": s.spec.Name, "ip": s.netIP, "ips": toAny(s.ips()), "networks": nets,
				"primary": s.primary, "secrets": toAny(nonNilStrings(s.spec.Secrets)),
			})
		}
		for _, s := range m.Secrets {
			e := map[string]any{"name": s.Name, "optional": s.Optional}
			if s.SameAs != "" {
				e["sameAs"] = s.SameAs
			}
			secrets = append(secrets, e)
		}
		var vols []any
		for _, v := range a.bundle.Fragment.Volumes {
			e := map[string]any{"name": v, "path": DataPath(a.id, v)}
			if o, ok := a.bundle.Fragment.VolumeOwners[v]; ok {
				e["owner"] = o
			}
			vols = append(vols, e)
		}
		for _, r := range routes {
			if r.app != a.id {
				continue
			}
			rts = append(rts, map[string]any{
				"name": r.name, "host": r.host, "path": r.route.PathPrefix(), "service": r.service,
				"port": r.route.InternalPort, "auth": r.route.Auth, "onAttestHost": r.route.OnAttestHost,
				"publicUrl": r.publicURL(),
			})
		}
		hcPort := m.Healthcheck.Port
		if hcPort == 0 {
			hcPort, _ = routePort(m, m.Healthcheck.Service)
		}
		entry := map[string]any{
			"id":             a.id,
			"appId":          a.bundle.AppID.Hex(),
			"releaseId":      a.bundle.ReleaseID.Hex(),
			"version":        a.bundle.Version(),
			"primaryService": m.PrimaryService,
			"network": map[string]any{
				"name": a.network(), "subnet": AppSubnet(a.n), "egress": a.egressIP(), "agent": a.agentIP(),
			},
			"services":    nonNil(svcs),
			"secrets":     nonNil(secrets),
			"metering":    map[string]any{"unit": m.Metering.Unit, "source": m.Metering.Source},
			"healthcheck": map[string]any{"service": m.Healthcheck.Service, "port": hcPort, "path": m.Healthcheck.HTTP},
			"routes":      nonNil(rts),
			"volumes":     nonNil(vols),
		}
		if m.Bootstrap != nil && m.Bootstrap.Service != "" {
			// donePath is the data-disk path of the done file; "" only when
			// the manifest names no done file (the agent then waits for the
			// bootstrap service to exit 0).
			bs := map[string]any{"service": m.Bootstrap.Service, "doneFile": m.Bootstrap.DoneFile, "donePath": ""}
			if m.Bootstrap.DoneFile != "" {
				p, err := ResolveDoneFile(m, a.bundle.Fragment)
				if err != nil {
					return nil, err
				}
				bs["donePath"] = p
			}
			entry["bootstrap"] = bs
		}
		appList = append(appList, entry)
	}
	dataDirs := []string{DataPath(caddyDataApp, caddyDataVolume)}
	for _, a := range apps {
		for _, v := range a.bundle.Fragment.Volumes {
			dataDirs = append(dataDirs, DataPath(a.id, v))
		}
	}
	attestHost, err := cfg.Hostname("attest")
	if err != nil {
		return nil, err
	}
	sidecars := map[string]any{svcEgress: EgressAppsIP, svcAgent: AgentIP, svcCaddy: CaddyIP}
	if hasGateway {
		sidecars[svcPayer] = PayerIP
		sidecars[svcVerifierd] = VerifierdIP
	}
	return cjson.Encode(map[string]any{
		"schema":          "sealed-stack/v1",
		"composerVersion": Version,
		"apps":            appList,
		"dataRoot":        DataRoot,
		"dataDirs":        toAny(sortedStrings(dataDirs)),
		"secretsRoot":     SecretsRoot,
		"secretFiles":     toAny(nonNilStrings(secretFiles(apps, hasGateway))),
		"sidecars":        sidecars,
		"attestHost":      attestHost,
		"gate": map[string]any{
			"username": caddy.DefaultGateUser, "secretApp": GateApp, "secret": gateSecret,
			"path": caddy.DefaultGatePath, "cookie": caddy.DefaultGateCookie, "cookieMaxAgeSeconds": GateCookieMaxAge,
		},
		"caddy": map[string]any{
			"adminSocket":            caddy.DefaultAdminSocket,
			"adminSocketMode":        caddy.DefaultAdminSocketMode,
			"adminSocketOwner":       AgentRunAs,
			"caddyfile":              AgentCaddyfilePath,
			"caddyfilePaymentNeeded": AgentCaddyfilePNPath,
		},
	})
}

func nonNil(v []any) []any {
	if v == nil {
		return []any{}
	}
	return v
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// escapeDollars doubles every "$" in string values (not keys) so docker
// compose interpolation reproduces the literal, measured text.
func escapeDollars(v any) any {
	switch t := v.(type) {
	case string:
		return strings.ReplaceAll(t, "$", "$$")
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = escapeDollars(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = escapeDollars(e)
		}
		return out
	default:
		return v
	}
}
