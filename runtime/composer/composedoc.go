package composer

import (
	"fmt"
	"sort"
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
// volumes; it is bind-mounted from the encrypted data disk.
const (
	volBin        = "sealed-bin"
	volReady      = "sealed-ready"
	volCaddyAdmin = "sealed-caddy-admin"
	volSecretsPfx = "sealed-secrets-"
)

func buildComposeDoc(cfg *Config, apps []*plannedApp, ri *RuntimeImages, hasGateway bool, res *Result) (map[string]any, error) {
	noProxy := noProxyList(apps)
	services := map[string]any{}
	secretVolumes := []string{GateApp}
	if hasGateway {
		secretVolumes = append(secretVolumes, svcPayer)
	}
	for _, a := range apps {
		if appHasSecrets(a) {
			secretVolumes = append(secretVolumes, a.id)
		}
	}
	sort.Strings(secretVolumes)

	img := func(name string) string { return ri.Images[name].Ref }

	services[svcInit] = map[string]any{
		"image":        img(imgInit),
		"entrypoint":   []any{"/envexec", "install", BinDir},
		"network_mode": "none",
		"read_only":    true,
		"restart":      "no",
		"logging":      logging(),
		"volumes":      []any{volumeMount(volBin, BinDir, false)},
	}
	services[svcEgress] = map[string]any{
		"image": img(imgEgress),
		"networks": map[string]any{
			"apps": map[string]any{"ipv4_address": EgressAppsIP},
			"edge": map[string]any{"ipv4_address": EgressEdgeIP},
		},
		"environment": map[string]any{"SEALED_EGRESS_CONFIG": EgressConfigPath},
		"configs":     []any{configMount(cfgEgress, EgressConfigPath)},
		"volumes":     []any{volumeMount(volBin, BinDir, true)},
		"read_only":   true,
		"healthcheck": probe("tcp://127.0.0.1:3128", "2s", "60s"),
		"depends_on":  dependsOn(map[string]string{svcInit: "service_completed_successfully"}),
		"restart":     "unless-stopped",
		"logging":     logging(),
	}

	agentVolumes := []any{
		map[string]any{"type": "bind", "source": DstackSocket, "target": DstackSocket},
		map[string]any{"type": "bind", "source": DataRoot, "target": DataRoot,
			"bind": map[string]any{"propagation": "rshared", "create_host_path": true}},
		volumeMount(volBin, BinDir, true),
		volumeMount(volReady, ReadyDir, false),
		volumeMount(volCaddyAdmin, CaddyAdminDir, false),
	}
	for _, v := range secretVolumes {
		agentVolumes = append(agentVolumes, volumeMount(volSecretsPfx+v, SecretsRoot+"/"+v, false))
	}
	agentEnv := proxyEnv(noProxy)
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
	services[svcAgent] = map[string]any{
		"image":       img(imgAgent),
		"networks":    map[string]any{"apps": map[string]any{"ipv4_address": AgentIP}},
		"dns":         []any{DNSIP},
		"environment": agentEnv,
		"volumes":     agentVolumes,
		"configs": []any{
			configMount(cfgConfig, ConfigPath),
			configMount(cfgStack, StackPath),
			configMount(cfgCaddyfile, AgentCaddyfilePath),
			configMount(cfgCaddyfilePN, AgentCaddyfilePNPath),
		},
		"cap_add":     []any{"SYS_ADMIN"},
		"devices":     []any{DataDeviceHost + ":" + DataDevice, "/dev/mapper/control:/dev/mapper/control"},
		"healthcheck": probe("http://127.0.0.1:"+strconv.Itoa(AgentPort)+"/v1/ready", "5s", "24h"),
		"depends_on": dependsOn(map[string]string{
			svcInit:   "service_completed_successfully",
			svcEgress: "service_healthy",
		}),
		"restart": "unless-stopped",
		"logging": logging(),
	}

	caddyEnv := proxyEnv(noProxy)
	caddyEnv["XDG_DATA_HOME"] = "/data"
	caddyEnv["XDG_CONFIG_HOME"] = "/config"
	services[svcCaddy] = map[string]any{
		"image": img(imgCaddy),
		"entrypoint": []any{EnvexecPath, "--app", GateApp, "--secret", gateSecret, "--",
			"caddy", "run", "--config", CaddyfilePath, "--adapter", "caddyfile"},
		"networks": map[string]any{
			"apps": map[string]any{"ipv4_address": CaddyIP},
			"edge": map[string]any{"ipv4_address": CaddyEdgeIP},
		},
		"ports":       []any{"80:80/tcp", "443:443/tcp"},
		"dns":         []any{DNSIP},
		"environment": caddyEnv,
		"volumes": []any{
			volumeMount(volBin, BinDir, true),
			volumeMount(volReady, ReadyDir, true),
			volumeMount(volSecretsPfx+GateApp, SecretsRoot+"/"+GateApp, true),
			volumeMount(volCaddyAdmin, CaddyAdminDir, false),
			dataBind("_caddy", "data", "/data", false),
			map[string]any{"type": "tmpfs", "target": "/config"},
		},
		"configs": []any{
			configMount(cfgCaddyfile, CaddyfilePath),
			configMount(cfgPaymentPage, caddy.DefaultPageDir+"/"+caddy.DefaultPageFile),
		},
		"depends_on": dependsOn(map[string]string{
			svcInit:   "service_completed_successfully",
			svcEgress: "service_healthy",
			svcAgent:  "service_healthy",
		}),
		"restart": "unless-stopped",
		"logging": logging(),
	}

	if hasGateway {
		payerEnv := proxyEnv(noProxy)
		payerEnv["PORT"] = strconv.Itoa(PayerPort)
		payerEnv["SEALED_CONFIG_FILE"] = ConfigPath
		payerEnv["SEALED_SECRETS_DIR"] = SecretsRoot + "/" + svcPayer
		payerEnv["SEALED_AGENT_URL"] = "http://" + svcAgent + ":" + strconv.Itoa(AgentPort)
		payerEnv["SEALED_VERIFIERD_URL"] = "http://" + svcVerifierd + ":" + strconv.Itoa(VerifierdPort)
		services[svcPayer] = map[string]any{
			"image":       img(imgPayer),
			"networks":    map[string]any{"apps": map[string]any{"ipv4_address": PayerIP}},
			"dns":         []any{DNSIP},
			"environment": payerEnv,
			"volumes": []any{
				volumeMount(volReady, ReadyDir, true),
				volumeMount(volSecretsPfx+svcPayer, SecretsRoot+"/"+svcPayer, true),
			},
			"configs": []any{configMount(cfgConfig, ConfigPath)},
			"depends_on": dependsOn(map[string]string{
				svcAgent:     "service_healthy",
				svcVerifierd: "service_started",
			}),
			"restart": "unless-stopped",
			"logging": logging(),
		}
		vdEnv := proxyEnv(noProxy)
		vdEnv["PORT"] = strconv.Itoa(VerifierdPort)
		vdEnv["SEALED_CONFIG_FILE"] = ConfigPath
		services[svcVerifierd] = map[string]any{
			"image":       img(imgVerifierd),
			"networks":    map[string]any{"apps": map[string]any{"ipv4_address": VerifierdIP}},
			"dns":         []any{DNSIP},
			"environment": vdEnv,
			"configs":     []any{configMount(cfgConfig, ConfigPath)},
			"read_only":   true,
			"depends_on":  dependsOn(map[string]string{svcEgress: "service_healthy"}),
			"restart":     "unless-stopped",
			"logging":     logging(),
		}
	}

	for _, a := range apps {
		for _, s := range a.services {
			svc, err := appService(a, s, noProxy)
			if err != nil {
				return nil, err
			}
			services[s.spec.Name] = svc
		}
	}

	volumes := map[string]any{
		volBin:        map[string]any{},
		volReady:      tmpfsVolume("0755"),
		volCaddyAdmin: tmpfsVolume("0750"),
	}
	for _, v := range secretVolumes {
		volumes[volSecretsPfx+v] = tmpfsVolume("0755")
	}

	return map[string]any{
		"name": ProjectName,
		"networks": map[string]any{
			"apps": network(AppsSubnet, "172.30.0.1", "sealed-apps", true, true),
			"edge": network(EdgeSubnet, "172.31.0.1", "sealed-edge", false, false),
		},
		"volumes": volumes,
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

func appHasSecrets(a *plannedApp) bool {
	for _, s := range a.services {
		if len(s.spec.Secrets) > 0 {
			return true
		}
	}
	return false
}

func appService(a *plannedApp, s *plannedService, noProxy string) (map[string]any, error) {
	m := a.bundle.Manifest
	spec := s.spec
	fail := func(format string, args ...any) error {
		return &FragmentError{App: a.id, Service: spec.Name, Msg: fmt.Sprintf(format, args...)}
	}

	image := spec.Image
	if mm := imagePlaceholderRe.FindStringSubmatch(image); mm != nil {
		img, _ := m.Image(mm[1])
		image = img.Ref
	}

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
	for k, v := range proxyEnv(noProxy) {
		env[k] = v
	}

	appsNet := map[string]any{"ipv4_address": s.ip}
	if s.primary {
		appsNet["aliases"] = []any{a.id}
	}

	volumes := []any{
		volumeMount(volBin, BinDir, true),
		volumeMount(volReady, ReadyDir, true),
	}
	if len(spec.Secrets) > 0 {
		volumes = append(volumes, volumeMount(volSecretsPfx+a.id, SecretsRoot+"/"+a.id, true))
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
		"networks":    map[string]any{"apps": appsNet},
		"dns":         []any{DNSIP},
		"environment": env,
		"volumes":     volumes,
		"depends_on":  dependsOn(deps),
		"restart":     restart,
		"logging":     logging(),
	}
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

func proxyEnv(noProxy string) map[string]any {
	return map[string]any{
		"HTTP_PROXY":         ProxyURL,
		"HTTPS_PROXY":        ProxyURL,
		"http_proxy":         ProxyURL,
		"https_proxy":        ProxyURL,
		"NO_PROXY":           noProxy,
		"no_proxy":           noProxy,
		"NODE_USE_ENV_PROXY": "1",
	}
}

func logging() map[string]any { return map[string]any{"driver": "none"} }

func volumeMount(source, target string, readOnly bool) map[string]any {
	m := map[string]any{"type": "volume", "source": source, "target": target, "volume": map[string]any{"nocopy": true}}
	if readOnly {
		m["read_only"] = true
	}
	return m
}

func dataBind(app, volume, target string, readOnly bool) map[string]any {
	m := map[string]any{
		"type":   "bind",
		"source": DataRoot + "/" + app + "/" + volume,
		"target": target,
		"bind":   map[string]any{"create_host_path": true},
	}
	if readOnly {
		m["read_only"] = true
	}
	return m
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

func tmpfsVolume(mode string) map[string]any {
	return map[string]any{
		"driver": "local",
		"driver_opts": map[string]any{
			"type":   "tmpfs",
			"device": "tmpfs",
			"o":      "size=1m,mode=" + mode + ",noexec,nosuid,nodev",
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
