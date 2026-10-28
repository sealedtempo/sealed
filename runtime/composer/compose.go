package composer

import (
	"fmt"
	"net/netip"
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
	// Such a stack cannot boot; release tooling must refuse it.
	Unbuilt []string
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
	ACMEHost             = "acme-v02.api.letsencrypt.org:443"
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
	bundle    *Bundle
	services  []*plannedService
	additions []string
}

type plannedService struct {
	app     *plannedApp
	spec    *ServiceSpec
	ip      string
	primary bool
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
	doc, err := buildComposeDoc(cfg, apps, ri, hasGateway, res)
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
	// Primary services get .16, .17, ... in app order, then every other
	// service in app order and name order.
	host := firstAppHost
	next := func() (string, error) {
		if host > lastAppHost {
			return "", fmt.Errorf("compose: more than %d app services", lastAppHost-firstAppHost+1)
		}
		ip := "172.30.0." + strconv.Itoa(host)
		host++
		return ip, nil
	}
	for _, a := range apps {
		primary := a.bundle.Fragment.Service(a.bundle.Manifest.PrimaryService)
		ip, err := next()
		if err != nil {
			return nil, err
		}
		a.services = append(a.services, &plannedService{app: a, spec: primary, ip: ip, primary: true})
	}
	for _, a := range apps {
		for _, s := range a.bundle.Fragment.Services {
			if s.Name == a.bundle.Manifest.PrimaryService {
				continue
			}
			ip, err := next()
			if err != nil {
				return nil, err
			}
			a.services = append(a.services, &plannedService{app: a, spec: s, ip: ip})
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

type plannedRoute struct {
	name    string
	host    string
	app     string
	route   Route
	service string
}

func planRoutes(cfg *Config, apps []*plannedApp) ([]plannedRoute, error) {
	owner := map[string]string{}
	var out []plannedRoute
	for _, a := range apps {
		for _, r := range a.bundle.Manifest.Routes {
			if prev, ok := owner[r.Name]; ok && prev != a.id {
				return nil, fmt.Errorf("compose: route %q is claimed by both %s and %s", r.Name, prev, a.id)
			}
			owner[r.Name] = a.id
			host, err := cfg.Hostname(r.Name)
			if err != nil {
				return nil, err
			}
			out = append(out, plannedRoute{name: r.Name, host: host, app: a.id, route: r, service: r.Service})
		}
	}
	if _, err := cfg.Hostname("attest"); err != nil {
		return nil, err
	}
	if cfg.Hostnames.Scheme == SchemeCustom {
		for _, route := range sortedKeys(cfg.Hostnames.Domains) {
			if _, used := owner[route]; !used && route != "attest" {
				return nil, fmt.Errorf("config: hostnames.domains.%s: no app in this stack has that route", route)
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
	for _, r := range routes {
		s, ok := sitesByHost[r.host]
		if !ok {
			s = &caddy.Site{Host: r.host}
			sitesByHost[r.host] = s
			order = append(order, r.host)
		}
		s.Routes = append(s.Routes, caddy.Route{
			Path:     r.route.PathPrefix(),
			Upstream: r.service + ":" + strconv.Itoa(r.route.InternalPort),
			Auth:     r.route.Auth,
		})
	}
	sort.Strings(order)
	in := caddy.Input{
		ComposerVersion: Version,
		AdminSocket:     caddy.DefaultAdminSocket,
		GateUser:        caddy.DefaultGateUser,
		GateEnv:         caddy.DefaultGateEnv,
		PageDir:         caddy.DefaultPageDir,
		PageFile:        caddy.DefaultPageFile,
		AttestHost:      attestHost,
		AttestUpstream:  svcAgent + ":" + strconv.Itoa(AgentPort),
	}
	for _, h := range order {
		in.Sites = append(in.Sites, *sitesByHost[h])
	}
	return in, nil
}

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
	callers := []caller{
		{svcAgent, AgentIP, []string{keyBroker, platformAPI, tempoRPC}},
		{svcCaddy, CaddyIP, []string{ACMEHost}},
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
			callers = append(callers, caller{s.spec.Name, s.ip, allow})
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

func buildStackInfo(cfg *Config, apps []*plannedApp, routes []plannedRoute, hasGateway bool) ([]byte, error) {
	var appList []any
	for _, a := range apps {
		m := a.bundle.Manifest
		var svcs, secrets, rts []any
		for _, s := range a.services {
			svcs = append(svcs, map[string]any{"name": s.spec.Name, "ip": s.ip, "primary": s.primary})
		}
		for _, s := range m.Secrets {
			secrets = append(secrets, map[string]any{"name": s.Name, "optional": s.Optional})
		}
		for _, r := range routes {
			if r.app != a.id {
				continue
			}
			rts = append(rts, map[string]any{
				"name": r.name, "host": r.host, "path": r.route.PathPrefix(), "service": r.service,
				"port": r.route.InternalPort, "auth": r.route.Auth,
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
			"services":       nonNil(svcs),
			"secrets":        nonNil(secrets),
			"metering":       map[string]any{"unit": m.Metering.Unit, "source": m.Metering.Source},
			"healthcheck":    map[string]any{"service": m.Healthcheck.Service, "port": hcPort, "path": m.Healthcheck.HTTP},
			"routes":         nonNil(rts),
		}
		if m.Bootstrap != nil && m.Bootstrap.Service != "" {
			entry["bootstrap"] = map[string]any{"service": m.Bootstrap.Service, "doneFile": m.Bootstrap.DoneFile}
		}
		appList = append(appList, entry)
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
		"sidecars":        sidecars,
		"attestHost":      attestHost,
		"gate":            map[string]any{"username": caddy.DefaultGateUser, "secretApp": GateApp, "secret": gateSecret},
		"caddy": map[string]any{
			"adminSocket":            caddy.DefaultAdminSocket,
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
