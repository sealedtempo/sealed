package composer

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sealed-dev/sealed/runtime/caddy"
)

// Compose config names (top-level "configs" with inline content).
const (
	cfgConfig      = "sealed-config"
	cfgStack       = "sealed-stack"
	cfgEgress      = "sealed-egress"
	cfgCaddyfile   = "sealed-caddyfile"
	cfgCaddyfilePN = "sealed-caddyfile-payment-needed"
	cfgPaymentPage = "sealed-payment-page"
)

// Docker volume names for sidecar plumbing. App data never uses Docker
// volumes; it is bind-mounted from the encrypted data disk. Secrets are
// bind-mounted file by file from the host tmpfs under SecretsRoot.
const (
	volBin        = "sealed-bin"
	volReady      = "sealed-ready"
	volCaddyAdmin = "sealed-caddy-admin"
)

// agentDeviceCgroupRules let sealed-agent open and mount the device-mapper
// devices cryptsetup creates for the LUKS data disk. The dm major is
// assigned at boot (usually 252 to 254), so all three are allowed for block
// devices only (integration brief item 15).
var agentDeviceCgroupRules = []string{"b 252:* rwm", "b 253:* rwm", "b 254:* rwm"}

func buildComposeDoc(cfg *Config, apps []*plannedApp, routes []plannedRoute, ri *RuntimeImages, hasGateway bool, res *Result) (map[string]any, error) {
	noProxy := noProxyList(apps)
	services := map[string]any{}
	logs := logging(cfg.Debug)

	img := func(name string) string { return ri.Images[name].Ref }

	services[svcInit] = harden(map[string]any{
		"image":        img(imgInit),
		"entrypoint":   []any{"/envexec", "install", BinDir},
		"network_mode": "none",
		"read_only":    true,
		"restart":      "no",
		"logging":      logs,
		"volumes":      []any{volumeMount(volBin, BinDir, false)},
	}, capsNone, nil)

	// sealed-egress and sealed-agent join every app network at fixed
	// addresses (D-041): each app's services reach them without the shared
	// apps network.
	egressNets := map[string]any{
		"apps": map[string]any{"ipv4_address": EgressAppsIP},
		"edge": map[string]any{"ipv4_address": EgressEdgeIP},
	}
	if hasGateway {
		egressNets[VerifierNetwork] = map[string]any{"ipv4_address": EgressVerifierIP}
	}
	agentNets := map[string]any{"apps": map[string]any{"ipv4_address": AgentIP}}
	for _, a := range apps {
		egressNets[a.network()] = map[string]any{"ipv4_address": a.egressIP()}
		agentNets[a.network()] = map[string]any{"ipv4_address": a.agentIP()}
	}
	// No read_only: compose writes inline configs into the container's root
	// filesystem when it creates the container, so "docker compose up"
	// refuses a read-only service with a content config (D-063,
	// docker-checks bug 1). sealed-egress still runs as nonroot from a
	// distroless image with every capability dropped and no-new-privileges.
	services[svcEgress] = harden(map[string]any{
		"image":       img(imgEgress),
		"networks":    egressNets,
		"environment": map[string]any{"SEALED_EGRESS_CONFIG": EgressConfigPath},
		"configs":     []any{configMount(cfgEgress, EgressConfigPath)},
		"volumes":     []any{volumeMount(volBin, BinDir, true)},
		"healthcheck": probe("tcp://127.0.0.1:3128", "2s", "60s"),
		"depends_on":  dependsOn(map[string]string{svcInit: "service_completed_successfully"}),
		"restart":     "unless-stopped",
		"logging":     logs,
	}, capsNone, nil)

	// The agent's DataRoot bind is only the mount point it opens LUKS on, and
	// SecretsRoot is a directory on the host's /run tmpfs where it writes the
	// secret files the app services bind one by one; nothing is written to
	// either before the agent runs, so Docker may create both.
	agentVolumes := []any{
		map[string]any{"type": "bind", "source": DstackSocket, "target": DstackSocket},
		map[string]any{"type": "bind", "source": DataRoot, "target": DataRoot,
			"bind": map[string]any{"propagation": "rshared", "create_host_path": true}},
		map[string]any{"type": "bind", "source": SecretsRoot, "target": SecretsRoot,
			"bind": map[string]any{"create_host_path": true}},
		volumeMount(volBin, BinDir, true),
		volumeMount(volReady, ReadyDir, false),
		volumeMount(volCaddyAdmin, CaddyAdminDir, false),
	}
	agentEnv := proxyEnv(ProxyURL, noProxy)
	for k, v := range map[string]string{
		"PORT":                            strconv.Itoa(AgentPort),
		"SEALED_CONFIG_FILE":              ConfigPath,
		"SEALED_STACK_FILE":               StackPath,
		"SEALED_CADDYFILE":                AgentCaddyfilePath,
		"SEALED_CADDYFILE_PAYMENT_NEEDED": AgentCaddyfilePNPath,
		"SEALED_CADDY_ADMIN_SOCKET":       caddy.DefaultAdminSocket,
		"SEALED_SECRETS_DIR":              SecretsRoot,
		"SEALED_READY_DIR":                ReadyDir,
		"SEALED_DATA_DIR":                 DataRoot,
		"SEALED_DATA_DEVICE":              DataDevice,
		"SEALED_EGRESS_STATS_URL":         "http://" + EgressAppsIP + ":9100/v1/stats",
		"DSTACK_SOCKET":                   DstackSocket,
	} {
		agentEnv[k] = v
	}
	services[svcAgent] = harden(map[string]any{
		"image":       img(imgAgent),
		"networks":    agentNets,
		"dns":         []any{DNSIP},
		"environment": agentEnv,
		"volumes":     agentVolumes,
		"configs": []any{
			configMount(cfgConfig, ConfigPath),
			configMount(cfgStack, StackPath),
			configMount(cfgCaddyfile, AgentCaddyfilePath),
			configMount(cfgCaddyfilePN, AgentCaddyfilePNPath),
		},
		"devices":             []any{DataDeviceHost + ":" + DataDevice, "/dev/mapper/control:/dev/mapper/control"},
		"device_cgroup_rules": toAny(agentDeviceCgroupRules),
		"healthcheck":         probe("http://127.0.0.1:"+strconv.Itoa(AgentPort)+"/v1/ready", "5s", "24h"),
		"depends_on": dependsOn(map[string]string{
			svcInit:   "service_completed_successfully",
			svcEgress: "service_healthy",
		}),
		"restart": "unless-stopped",
		"logging": logs,
	}, capsAgentDrop, []string{"SYS_ADMIN"})

	// Caddy needs no secret: the gate runs in sealed-agent (forward_auth,
	// D-044). Its admin socket is created on a tmpfs owned by the agent's
	// uid with the setgid bit, so the socket belongs to the agent's group and
	// mode 0660 lets the agent connect without a root helper; group_add gives
	// Caddy (root without CAP_DAC_OVERRIDE) the right to create it there.
	caddyEnv := proxyEnv(ProxyURL, noProxy)
	caddyEnv["XDG_DATA_HOME"] = "/data"
	caddyEnv["XDG_CONFIG_HOME"] = "/config"
	services[svcCaddy] = harden(map[string]any{
		"image":      img(imgCaddy),
		"entrypoint": []any{"caddy", "run", "--config", CaddyfilePath, "--adapter", "caddyfile"},
		"networks": map[string]any{
			"apps": map[string]any{"ipv4_address": CaddyIP},
			"edge": map[string]any{"ipv4_address": CaddyEdgeIP},
		},
		"ports":       []any{"80:80/tcp", "443:443/tcp"},
		"dns":         []any{DNSIP},
		"environment": caddyEnv,
		"group_add":   []any{agentUID},
		"volumes": []any{
			volumeMount(volCaddyAdmin, CaddyAdminDir, false),
			dataBind(caddyDataApp, caddyDataVolume, "/data", false),
			map[string]any{"type": "tmpfs", "target": "/config"},
		},
		"configs": []any{
			configMount(cfgCaddyfile, CaddyfilePath),
			configMount(cfgPaymentPage, caddy.DefaultPageDir+"/"+caddy.DefaultPageFile),
		},
		"depends_on": dependsOn(map[string]string{
			svcEgress: "service_healthy",
			svcAgent:  "service_healthy",
		}),
		"restart": "unless-stopped",
		"logging": logs,
	}, capsNone, []string{"NET_BIND_SERVICE"})

	if hasGateway {
		payerEnv := proxyEnv(ProxyURL, noProxy)
		payerEnv["PORT"] = strconv.Itoa(PayerPort)
		payerEnv["SEALED_CONFIG_FILE"] = ConfigPath
		payerEnv["SEALED_SECRETS_DIR"] = SecretsRoot + "/" + svcPayer
		payerEnv["SEALED_AGENT_URL"] = "http://" + svcAgent + ":" + strconv.Itoa(AgentPort)
		payerEnv["SEALED_VERIFIERD_URL"] = "http://" + svcVerifierd + ":" + strconv.Itoa(VerifierdPort)
		payerEnv["STATE_DIR"] = PayerStateDir
		payerVolumes := []any{
			volumeMount(volReady, ReadyDir, true),
			volumeMount(volBin, BinDir, true),
			dataBind(payerDataApp, payerDataVolume, PayerStateDir, false),
		}
		for _, n := range payerSecrets {
			payerVolumes = append(payerVolumes, secretBind(svcPayer, n))
		}
		// The payer reaches verifierd on the verifier network and everything
		// else on apps. On SIGTERM it closes its relay session, which waits
		// up to 30 s for the chain (mppx), so it gets more than Docker's
		// default 10 s (D-067). Its state (the day's debits, the channel
		// journal and the stored session channel) lives on the encrypted
		// data disk, so it survives image updates and VM replacement
		// (fix-payments). sealed-agent creates the directory for the numeric
		// user that mounts it; envexec private makes it 0700 before the
		// image's own command runs.
		payerEntry := append([]any{EnvexecPath, "private", PayerStateDir, "--"}, toAny(payerCommand[:1])...)
		services[svcPayer] = harden(map[string]any{
			"image":      img(imgPayer),
			"user":       PayerRunAs,
			"entrypoint": payerEntry,
			"command":    toAny(payerCommand[1:]),
			"networks": map[string]any{
				"apps":          map[string]any{"ipv4_address": PayerIP},
				VerifierNetwork: map[string]any{"ipv4_address": PayerVerifierIP},
			},
			"dns":               []any{DNSIP},
			"environment":       payerEnv,
			"volumes":           payerVolumes,
			"configs":           []any{configMount(cfgConfig, ConfigPath)},
			"stop_grace_period": PayerStopGracePeriod,
			"depends_on": dependsOn(map[string]string{
				svcInit:      "service_completed_successfully",
				svcAgent:     "service_healthy",
				svcVerifierd: "service_started",
			}),
			"restart": "unless-stopped",
			"logging": logs,
		}, capsNone, nil)
		// sealed-verifierd is only on the verifier network (D-061), so only
		// the payer can reach it, and its DNS and proxy are sealed-egress
		// there. It also serves only the payer's address on that network
		// (SEALED_VERIFIERD_ALLOWED_CLIENTS) and fetches no attest URL
		// itself (the payer submits attestations it fetched); were fetches
		// on, they would be limited to the relay attest host. No read_only,
		// for the same reason as sealed-egress.
		relayAttestHost, err := urlHostname(cfg.Endpoints.RelayAttest)
		if err != nil {
			return nil, err
		}
		vdProxy := "http://" + EgressVerifierIP + ":3128"
		vdEnv := proxyEnv(vdProxy, noProxy)
		vdEnv["PORT"] = strconv.Itoa(VerifierdPort)
		vdEnv["SEALED_CONFIG_FILE"] = ConfigPath
		vdEnv["SEALED_VERIFIERD_ALLOWED_CLIENTS"] = PayerVerifierIP
		vdEnv["SEALED_VERIFIERD_LIVE_FETCH"] = "false"
		vdEnv["SEALED_VERIFIERD_LIVE_HOSTS"] = relayAttestHost
		services[svcVerifierd] = harden(map[string]any{
			"image":       img(imgVerifierd),
			"networks":    map[string]any{VerifierNetwork: map[string]any{"ipv4_address": VerifierdIP}},
			"dns":         []any{EgressVerifierIP},
			"environment": vdEnv,
			"configs":     []any{configMount(cfgConfig, ConfigPath)},
			"depends_on":  dependsOn(map[string]string{svcEgress: "service_healthy"}),
			"restart":     "unless-stopped",
			"logging":     logs,
		}, capsNone, nil)
	}

	publicURLs := map[string]map[string]any{}
	for _, r := range routes {
		if publicURLs[r.app] == nil {
			publicURLs[r.app] = map[string]any{}
		}
		publicURLs[r.app][PublicURLEnv(r.name)] = r.publicURL()
	}
	for _, a := range apps {
		for _, s := range a.services {
			svc, err := appService(a, s, noProxy, publicURLs[a.id], logs)
			if err != nil {
				return nil, err
			}
			services[s.spec.Name] = svc
		}
	}

	networks := map[string]any{
		"apps": network(AppsSubnet, "172.30.0.1", "sealed-apps", true, true),
		"edge": network(EdgeSubnet, "172.31.0.1", "sealed-edge", false, false),
	}
	for _, a := range apps {
		networks[a.network()] = network(AppSubnet(a.n), appNetIP(a.n, 1), "sealed-app"+strconv.Itoa(a.n), true, true)
	}
	if hasGateway {
		networks[VerifierNetwork] = network(VerifierSubnet, "172.30.250.1", verifierBridge, true, true)
	}

	// A container on two or more networks never routes between them
	// (D-064, docker-checks bug 5): IPv4 sysctls of a new network namespace
	// are inherited from the host, where Docker turns forwarding on. Today
	// only Docker's bridge rules stop a container with NET_ADMIN from
	// routing through sealed-egress, Caddy, the agent or a primary.
	for _, name := range sortedKeys(services) {
		svc := services[name].(map[string]any)
		if nets, ok := svc["networks"].(map[string]any); ok && len(nets) > 1 {
			svc["sysctls"] = map[string]any{"net.ipv4.ip_forward": "0"}
		}
	}
	if err := checkInlineConfigsWritable(services); err != nil {
		return nil, err
	}

	return map[string]any{
		"name":     ProjectName,
		"networks": networks,
		"volumes": map[string]any{
			volBin:        map[string]any{},
			volReady:      tmpfsVolume("0755", ""),
			volCaddyAdmin: tmpfsVolume("2770", AgentRunAs),
		},
		"configs": map[string]any{
			cfgConfig:      map[string]any{"content": string(res.ConfigJSON)},
			cfgStack:       map[string]any{"content": string(res.StackInfo)},
			cfgEgress:      map[string]any{"content": string(res.EgressConfig)},
			cfgCaddyfile:   map[string]any{"content": string(res.Caddyfile)},
			cfgCaddyfilePN: map[string]any{"content": string(res.CaddyfilePaymentNeeded)},
			cfgPaymentPage: map[string]any{"content": string(caddy.PaymentNeededHTML)},
		},
		"services": services,
	}, nil
}

func appService(a *plannedApp, s *plannedService, noProxy string, publicURLs map[string]any, logs map[string]any) (map[string]any, error) {
	m := a.bundle.Manifest
	spec := s.spec
	fail := func(format string, args ...any) error {
		return &FragmentError{App: a.id, Service: spec.Name, Msg: fmt.Sprintf(format, args...)}
	}

	img, _ := m.Image(spec.Image)
	image := img.Ref

	entry := []any{EnvexecPath, "--app", a.id}
	for _, name := range spec.Secrets {
		sec, _ := m.Secret(name)
		flag := "--secret"
		if sec.Optional {
			flag = "--optional-secret"
		}
		entry = append(entry, flag, name)
	}
	entry = append(entry, "--")
	entry = append(entry, toAny(spec.Entrypoint)...)

	env := map[string]any{}
	for k, v := range spec.Environment {
		env[k] = v
	}
	for _, k := range sortedKeys(m.TelemetryOffEnv) {
		v := m.TelemetryOffEnv[k]
		if prev, ok := spec.Environment[k]; ok && prev != v {
			return nil, fail("environment %q is %q but telemetry_off_env sets %q", k, prev, v)
		}
		env[k] = v
	}
	for k, v := range proxyEnv(a.proxyURL(), noProxy) {
		env[k] = v
	}
	for k, v := range publicURLs {
		env[k] = v
	}

	// Every service joins its app's network; only the primary also joins
	// the shared apps network, with the app id as an alias (D-041).
	nets := map[string]any{a.network(): map[string]any{"ipv4_address": s.netIP}}
	if s.primary {
		nets["apps"] = map[string]any{"ipv4_address": s.appsIP, "aliases": []any{a.id}}
	}

	volumes := []any{
		volumeMount(volBin, BinDir, true),
		volumeMount(volReady, ReadyDir, true),
	}
	// Exactly the declared secret files, read-only (D-042).
	for _, name := range spec.Secrets {
		volumes = append(volumes, secretBind(a.id, name))
	}
	for _, mnt := range spec.Mounts {
		switch mnt.Type {
		case "volume":
			volumes = append(volumes, dataBind(a.id, mnt.Source, mnt.Target, mnt.ReadOnly))
		case "tmpfs":
			t := map[string]any{"type": "tmpfs", "target": mnt.Target}
			if mnt.ReadOnly {
				t["read_only"] = true
			}
			if mnt.TmpfsSize != nil {
				t["tmpfs"] = map[string]any{"size": mnt.TmpfsSize}
			}
			volumes = append(volumes, t)
		}
	}

	deps := map[string]string{
		svcInit:  "service_completed_successfully",
		svcAgent: "service_healthy",
	}
	for dep, cond := range spec.DependsOn {
		if cond == "service_healthy" && !hasHealthcheck(a, dep) {
			return nil, fail("depends_on %q with service_healthy, but %q has no healthcheck", dep, dep)
		}
		deps[dep] = cond
	}

	restart := "unless-stopped"
	if m.Bootstrap != nil && m.Bootstrap.Service == spec.Name {
		restart = "on-failure"
	}

	svc := map[string]any{
		"image":       image,
		"entrypoint":  entry,
		"networks":    nets,
		"dns":         []any{a.egressIP()},
		"environment": env,
		"volumes":     volumes,
		"depends_on":  dependsOn(deps),
		"restart":     restart,
		"logging":     logs,
	}
	harden(svc, capsAppDrop, nil)
	switch c := spec.Command.(type) {
	case string:
		svc["command"] = c
	case []string:
		svc["command"] = toAny(c)
	}
	if hc := healthcheckFor(a, spec.Name); hc != nil {
		svc["healthcheck"] = hc
	}
	if len(spec.Tmpfs) > 0 {
		svc["tmpfs"] = toAny(spec.Tmpfs)
	}
	if spec.User != "" {
		svc["user"] = spec.User
	}
	if spec.WorkingDir != "" {
		svc["working_dir"] = spec.WorkingDir
	}
	if spec.ReadOnly != nil {
		svc["read_only"] = *spec.ReadOnly
	}
	if spec.StopGracePeriod != "" {
		svc["stop_grace_period"] = spec.StopGracePeriod
	}
	if spec.ShmSize != nil {
		svc["shm_size"] = spec.ShmSize
	}
	if spec.MemLimit != nil {
		svc["mem_limit"] = spec.MemLimit
	}
	if spec.CPUs != nil {
		svc["cpus"] = spec.CPUs
	}
	if spec.Ulimits != nil {
		svc["ulimits"] = spec.Ulimits
	}
	if len(spec.Labels) > 0 {
		labels := map[string]any{}
		for k, v := range spec.Labels {
			labels[k] = v
		}
		svc["labels"] = labels
	}
	return svc, nil
}

// healthcheckFor returns the fragment healthcheck, or for the manifest's
// healthcheck service a generated HTTP probe through envexec.
func healthcheckFor(a *plannedApp, service string) map[string]any {
	spec := a.bundle.Fragment.Service(service)
	if spec != nil && spec.Healthcheck != nil {
		return spec.Healthcheck
	}
	m := a.bundle.Manifest
	if m.Healthcheck.Service != service {
		return nil
	}
	port := m.Healthcheck.Port
	if port == 0 {
		port, _ = routePort(m, service)
	}
	start := "30s"
	if m.Healthcheck.StartPeriodS > 0 {
		start = strconv.Itoa(m.Healthcheck.StartPeriodS) + "s"
	}
	return map[string]any{
		"test":           []any{"CMD", EnvexecPath, "probe", "http://127.0.0.1:" + strconv.Itoa(port) + m.Healthcheck.HTTP},
		"interval":       "15s",
		"timeout":        "5s",
		"retries":        5,
		"start_period":   start,
		"start_interval": "2s",
	}
}

func hasHealthcheck(a *plannedApp, service string) bool {
	hc := healthcheckFor(a, service)
	if hc == nil {
		return false
	}
	disabled, _ := hc["disable"].(bool)
	return !disabled
}

func noProxyList(apps []*plannedApp) string {
	names := []string{svcInit, svcEgress, svcAgent, svcCaddy, svcPayer, svcVerifierd, "localhost", "127.0.0.1"}
	for _, a := range apps {
		names = append(names, a.id)
		for _, s := range a.services {
			names = append(names, s.spec.Name)
		}
	}
	return strings.Join(sortedStrings(names), ",")
}

func proxyEnv(proxyURL, noProxy string) map[string]any {
	return map[string]any{
		"HTTP_PROXY":         proxyURL,
		"HTTPS_PROXY":        proxyURL,
		"http_proxy":         proxyURL,
		"https_proxy":        proxyURL,
		"NO_PROXY":           noProxy,
		"no_proxy":           noProxy,
		"NODE_USE_ENV_PROXY": "1",
	}
}

// logging is the driver every container uses: none in production, local
// when the config sets debug (integration brief item 13).
func logging(debug bool) map[string]any {
	if debug {
		return map[string]any{"driver": "local"}
	}
	return map[string]any{"driver": "none"}
}

// Capability sets. Docker's default set includes NET_RAW, which lets a
// container forge source IPs and ARP replies on the shared apps bridge;
// sealed-egress identifies callers by source IP, so no service keeps it.
// Sidecars we build drop everything. App images are unknown, so apps keep
// the defaults their entrypoints rely on (CHOWN, SETUID, SETGID, ...) and
// drop the ones no app needs. The agent keeps MKNOD because libdevmapper
// creates /dev/mapper nodes itself when udev is absent.
var (
	capsNone      = []string{"ALL"}
	capsAppDrop   = []string{"AUDIT_WRITE", "MKNOD", "NET_RAW", "SETFCAP"}
	capsAgentDrop = []string{"NET_RAW"}
)

// harden sets cap_drop, cap_add and no-new-privileges on a service, so
// setuid binaries and file capabilities cannot raise privileges either.
// Fragments cannot set these keys (INTERFACES section 14).
func harden(svc map[string]any, drop, add []string) map[string]any {
	svc["cap_drop"] = toAny(drop)
	if len(add) > 0 {
		svc["cap_add"] = toAny(add)
	}
	svc["security_opt"] = []any{"no-new-privileges:true"}
	return svc
}

func volumeMount(source, target string, readOnly bool) map[string]any {
	m := map[string]any{"type": "volume", "source": source, "target": target, "volume": map[string]any{"nocopy": true}}
	if readOnly {
		m["read_only"] = true
	}
	return m
}

// dataBind mounts a directory of the encrypted data disk. Docker must not
// create the source: before sealed-agent opens the disk (a reboot restarts
// containers without waiting for depends_on) the path would land on the host
// side of the mount point. A missing source makes the container fail to
// start instead; sealed-agent creates every DataDirs entry after unlocking,
// and compose up starts the app once the agent is healthy.
func dataBind(app, volume, target string, readOnly bool) map[string]any {
	m := map[string]any{
		"type":   "bind",
		"source": DataPath(app, volume),
		"target": target,
		"bind":   map[string]any{"create_host_path": false},
	}
	if readOnly {
		m["read_only"] = true
	}
	return m
}

// secretBind mounts one secret file read-only. The source is the same path
// on the host tmpfs, written by sealed-agent before the ready gate opens;
// Docker must not create it (a missing file would become a directory).
func secretBind(owner, name string) map[string]any {
	p := secretFile(owner, name)
	return map[string]any{
		"type":      "bind",
		"source":    p,
		"target":    p,
		"read_only": true,
		"bind":      map[string]any{"create_host_path": false},
	}
}

func configMount(source, target string) map[string]any {
	return map[string]any{"source": source, "target": target}
}

func dependsOn(deps map[string]string) map[string]any {
	out := map[string]any{}
	for name, cond := range deps {
		out[name] = map[string]any{"condition": cond}
	}
	return out
}

func probe(target, interval, startPeriod string) map[string]any {
	return map[string]any{
		"test":           []any{"CMD", EnvexecPath, "probe", target},
		"interval":       interval,
		"timeout":        "3s",
		"retries":        3,
		"start_period":   startPeriod,
		"start_interval": "2s",
	}
}

// tmpfsVolume is a small tmpfs Docker volume; owner ("<uid>:<gid>") sets
// the owner of its root directory.
func tmpfsVolume(mode, owner string) map[string]any {
	o := "size=1m,mode=" + mode
	if owner != "" {
		uid, gid, _ := strings.Cut(owner, ":")
		o += ",uid=" + uid + ",gid=" + gid
	}
	return map[string]any{
		"driver": "local",
		"driver_opts": map[string]any{
			"type":   "tmpfs",
			"device": "tmpfs",
			"o":      o + ",noexec,nosuid,nodev",
		},
	}
}

func network(subnet, gateway, bridge string, internal, icc bool) map[string]any {
	n := map[string]any{
		"driver":      "bridge",
		"enable_ipv6": false,
		"ipam":        map[string]any{"driver": "default", "config": []any{map[string]any{"subnet": subnet, "gateway": gateway}}},
		"driver_opts": map[string]any{
			"com.docker.network.bridge.name":       bridge,
			"com.docker.network.bridge.enable_icc": strconv.FormatBool(icc),
		},
	}
	if internal {
		n["internal"] = true
	}
	return n
}

// PayerStopGracePeriod is sealed-mpp-payer's stop_grace_period (D-067: at
// least 45 s, above mppx's 30 s confirmation wait for the closing voucher;
// the payer exits by 38 s, fix-payments).
const PayerStopGracePeriod = "60s"

// sealed-mpp-payer's state on the data disk (fix-payments): the directory
// /mnt/sealed-data/_mpp-payer/state is bound at PayerStateDir, the payer's
// STATE_DIR, and belongs to PayerRunAs (the image's node user, uid 1000)
// with mode 0700.
const (
	PayerStateDir   = "/var/lib/sealed-mpp-payer"
	PayerRunAs      = "1000:1000"
	payerDataApp    = "_mpp-payer"
	payerDataVolume = "state"
)

// payerCommand is the sealed-mpp-payer image's ENTRYPOINT and CMD
// (runtime/mpp-payer/Dockerfile). Compose drops an image's CMD when the
// entrypoint is replaced, so the composer runs it after envexec private;
// TestPayerCommandMatchesImage keeps the two equal.
var payerCommand = []string{"node", "/app/dist/main.js"}

// checkInlineConfigsWritable fails when a service that mounts an inline
// (content) config is read_only. Compose injects such configs by copying a
// file into the container at create time, which a read-only root
// filesystem forbids, so the stack would never start (D-063). App services
// get no configs, so an app fragment's read_only is unaffected.
func checkInlineConfigsWritable(services map[string]any) error {
	for _, name := range sortedKeys(services) {
		svc := services[name].(map[string]any)
		ro, _ := svc["read_only"].(bool)
		if cfgs, _ := svc["configs"].([]any); ro && len(cfgs) > 0 {
			return fmt.Errorf("compose: service %s is read_only but mounts inline configs, which docker compose cannot create", name)
		}
	}
	return nil
}

// urlHostname is the host name of an endpoint URL Validate accepted.
func urlHostname(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("config: %q has no host", raw)
	}
	return u.Hostname(), nil
}
