package composer

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// FragmentError names the app, service and key a fragment rule rejected.
// Service is empty for top-level keys.
type FragmentError struct {
	App     string
	Service string
	Key     string
	Msg     string
}

func (e *FragmentError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "fragment: app %q", e.App)
	if e.Service != "" {
		fmt.Fprintf(&b, " service %q", e.Service)
	}
	if e.Key != "" {
		fmt.Fprintf(&b, " key %q", e.Key)
	}
	b.WriteString(": ")
	b.WriteString(e.Msg)
	return b.String()
}

// Fragment is a validated compose.fragment.yaml. All string values are
// literal: compose "$$" escapes have been resolved and interpolation is
// rejected.
type Fragment struct {
	App      string
	Services []*ServiceSpec // sorted by name
	Volumes  []string       // sorted
}

// Service returns the named service.
func (f *Fragment) Service(name string) *ServiceSpec {
	for _, s := range f.Services {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// ServiceSpec holds the allowed keys of one fragment service in normalized form.
type ServiceSpec struct {
	Name            string
	Image           string            // manifest image name from {{image:<name>}}
	Entrypoint      []string          // required
	Command         any               // nil, string or []string
	Environment     map[string]string // public values only
	Healthcheck     map[string]any
	DependsOn       map[string]string // service -> condition
	Mounts          []Mount
	Tmpfs           []string
	User            string
	WorkingDir      string
	ReadOnly        *bool
	StopGracePeriod string
	ShmSize         any
	Ulimits         map[string]any
	MemLimit        any
	CPUs            any
	Labels          map[string]string
	Secrets         []string // x-sealed-secrets
}

// Mount is a named-volume or tmpfs mount of a fragment service.
type Mount struct {
	Type      string // "volume" or "tmpfs"
	Source    string // volume name (type volume)
	Target    string
	ReadOnly  bool
	TmpfsSize any // optional, type tmpfs
}

// allowedServiceKeys is INTERFACES section 14's list plus x-sealed-secrets.
var allowedServiceKeys = map[string]bool{
	"image": true, "command": true, "entrypoint": true, "environment": true, "healthcheck": true,
	"depends_on": true, "volumes": true, "tmpfs": true, "user": true, "working_dir": true,
	"read_only": true, "stop_grace_period": true, "shm_size": true, "ulimits": true,
	"mem_limit": true, "cpus": true, "labels": true, "x-sealed-secrets": true,
}

// reservedEnv is set by the composer on every service.
var reservedEnv = map[string]bool{
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "http_proxy": true, "https_proxy": true,
	"NO_PROXY": true, "no_proxy": true, "NODE_USE_ENV_PROXY": true, "ALL_PROXY": true, "all_proxy": true,
}

var (
	imagePlaceholderRe = regexp.MustCompile(`^\{\{image:([a-z][a-z0-9-]*)\}\}$`)
	digestRefRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$`)
	volumeNameRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	durationRe         = regexp.MustCompile(`^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$`)
	sizeRe             = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[bkmgBKMG]?[bB]?$`)
	cpusRe             = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
	labelKeyRe         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
	healthKeys         = map[string]bool{"test": true, "interval": true, "timeout": true, "retries": true, "start_period": true, "start_interval": true, "disable": true}
	dependConditions   = map[string]bool{"service_started": true, "service_healthy": true, "service_completed_successfully": true}
	ulimitNames        = map[string]bool{"nofile": true, "nproc": true, "memlock": true, "stack": true, "core": true, "fsize": true, "cpu": true, "data": true, "locks": true, "msgqueue": true, "nice": true, "rtprio": true, "sigpending": true, "as": true, "rss": true}
)

// ParseFragment parses compose.fragment.yaml and enforces the section 14
// rules for the given manifest.
func ParseFragment(m *Manifest, data []byte) (*Fragment, error) {
	app := m.ID
	v, err := decodeYAML("compose.fragment.yaml", data)
	if err != nil {
		return nil, &FragmentError{App: app, Msg: err.Error()}
	}
	top, ok := v.(map[string]any)
	if !ok {
		return nil, &FragmentError{App: app, Msg: "top level must be a mapping"}
	}
	for _, k := range sortedKeys(top) {
		if k != "services" && k != "volumes" && !strings.HasPrefix(k, "x-") {
			return nil, &FragmentError{App: app, Key: k, Msg: "only services, volumes and x- anchor blocks are allowed at the top level"}
		}
	}
	f := &Fragment{App: app}
	if raw, ok := top["volumes"]; ok && raw != nil {
		vols, ok := raw.(map[string]any)
		if !ok {
			return nil, &FragmentError{App: app, Key: "volumes", Msg: "must be a mapping of volume names"}
		}
		for _, name := range sortedKeys(vols) {
			if !volumeNameRe.MatchString(name) {
				return nil, &FragmentError{App: app, Key: "volumes." + name, Msg: "invalid volume name"}
			}
			if spec := vols[name]; spec != nil {
				if mm, ok := spec.(map[string]any); !ok || len(mm) > 0 {
					return nil, &FragmentError{App: app, Key: "volumes." + name, Msg: "volume options (driver, external, ...) are not allowed; every volume is a directory on the encrypted data disk"}
				}
			}
			f.Volumes = append(f.Volumes, name)
		}
	}
	svcs, ok := top["services"].(map[string]any)
	if !ok || len(svcs) == 0 {
		return nil, &FragmentError{App: app, Key: "services", Msg: "at least one service is required"}
	}
	declared := map[string]bool{}
	for _, v := range f.Volumes {
		declared[v] = true
	}
	for _, name := range sortedKeys(svcs) {
		if !serviceNameRe.MatchString(name) || !strings.HasPrefix(name, app+"-") {
			return nil, &FragmentError{App: app, Service: name, Msg: fmt.Sprintf("service names must start with %q and be lowercase DNS labels", app+"-")}
		}
		body, ok := svcs[name].(map[string]any)
		if !ok {
			return nil, &FragmentError{App: app, Service: name, Msg: "service must be a mapping"}
		}
		spec, err := parseService(m, name, body, declared)
		if err != nil {
			return nil, err
		}
		f.Services = append(f.Services, spec)
	}
	if err := f.checkReferences(m); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Fragment) checkReferences(m *Manifest) error {
	app := m.ID
	names := map[string]bool{}
	for _, s := range f.Services {
		names[s.Name] = true
	}
	for _, s := range f.Services {
		for dep := range s.DependsOn {
			if !names[dep] {
				return &FragmentError{App: app, Service: s.Name, Key: "depends_on", Msg: fmt.Sprintf("%q is not a service of this app", dep)}
			}
			if dep == s.Name {
				return &FragmentError{App: app, Service: s.Name, Key: "depends_on", Msg: "a service cannot depend on itself"}
			}
		}
	}
	if err := checkDependencyCycles(app, f.Services); err != nil {
		return err
	}
	missing := func(field, svc string) error {
		return &ManifestError{App: app, Field: field, Msg: fmt.Sprintf("service %q is not defined in compose.fragment.yaml", svc)}
	}
	if !names[m.PrimaryService] {
		return missing("primary_service", m.PrimaryService)
	}
	for i, r := range m.Routes {
		if !names[r.Service] {
			return missing(fmt.Sprintf("routes[%d].service", i), r.Service)
		}
	}
	if !names[m.Healthcheck.Service] {
		return missing("healthcheck.service", m.Healthcheck.Service)
	}
	if m.Bootstrap != nil && m.Bootstrap.Service != "" && !names[m.Bootstrap.Service] {
		return missing("bootstrap.service", m.Bootstrap.Service)
	}
	if m.Healthcheck.Port == 0 {
		if _, ok := routePort(m, m.Healthcheck.Service); !ok {
			return &ManifestError{App: app, Field: "healthcheck.port", Msg: fmt.Sprintf("required because service %q has no route", m.Healthcheck.Service)}
		}
	}
	return nil
}

func checkDependencyCycles(app string, svcs []*ServiceSpec) error {
	deps := map[string][]string{}
	for _, s := range svcs {
		for d := range s.DependsOn {
			deps[s.Name] = append(deps[s.Name], d)
		}
		sort.Strings(deps[s.Name])
	}
	state := map[string]int{} // 0 new, 1 visiting, 2 done
	var visit func(n string) error
	visit = func(n string) error {
		switch state[n] {
		case 1:
			return &FragmentError{App: app, Service: n, Key: "depends_on", Msg: "dependency cycle"}
		case 2:
			return nil
		}
		state[n] = 1
		for _, d := range deps[n] {
			if err := visit(d); err != nil {
				return err
			}
		}
		state[n] = 2
		return nil
	}
	for _, s := range svcs {
		if err := visit(s.Name); err != nil {
			return err
		}
	}
	return nil
}

// routePort returns the internal port of the first route of a service.
func routePort(m *Manifest, service string) (int, bool) {
	for _, r := range m.Routes {
		if r.Service == service {
			return r.InternalPort, true
		}
	}
	return 0, false
}

func parseService(m *Manifest, name string, body map[string]any, declared map[string]bool) (*ServiceSpec, error) {
	app := m.ID
	fail := func(key, format string, args ...any) error {
		return &FragmentError{App: app, Service: name, Key: key, Msg: fmt.Sprintf(format, args...)}
	}
	for _, k := range sortedKeys(body) {
		if !allowedServiceKeys[k] {
			return nil, fail(k, "not allowed in app fragments")
		}
	}
	// Resolve compose escapes in every string before looking at values.
	lit, err := literalize(body, "")
	if err != nil {
		return nil, fail(err.key, "%s", err.msg)
	}
	body = lit.(map[string]any)
	s := &ServiceSpec{Name: name}

	img, ok := body["image"].(string)
	if !ok {
		return nil, fail("image", "required, as {{image:<name>}} or a digest reference")
	}
	mm := imagePlaceholderRe.FindStringSubmatch(img)
	switch {
	case mm != nil:
		if _, ok := m.Image(mm[1]); !ok {
			return nil, fail("image", "%q names no image in the manifest", mm[1])
		}
	case digestRefRe.MatchString(img):
		return nil, fail("image", "%q: reference manifest images as {{image:<name>}} so the digest, SBOM and scan come from the manifest", img)
	default:
		return nil, fail("image", "%q must be {{image:<name>}}; tags and untracked images are rejected", img)
	}
	s.Image = mm[1]

	ep, err2 := stringList(body["entrypoint"])
	if body["entrypoint"] == nil || err2 != nil || len(ep) == 0 {
		return nil, fail("entrypoint", "required as a non-empty list of strings: every service runs through envexec, so declare the image's entrypoint explicitly")
	}
	s.Entrypoint = ep

	if c, ok := body["command"]; ok && c != nil {
		switch cv := c.(type) {
		case string:
			s.Command = cv
		default:
			list, err := stringList(cv)
			if err != nil {
				return nil, fail("command", "must be a string or a list of strings")
			}
			s.Command = list
		}
	}

	if raw, ok := body["x-sealed-secrets"]; ok {
		list, err := stringList(raw)
		if err != nil {
			return nil, fail("x-sealed-secrets", "must be a list of secret names")
		}
		seen := map[string]bool{}
		for _, n := range list {
			if _, ok := m.Secret(n); !ok {
				return nil, fail("x-sealed-secrets", "%q is not declared in the manifest's secrets", n)
			}
			if seen[n] {
				return nil, fail("x-sealed-secrets", "duplicate %q", n)
			}
			seen[n] = true
		}
		sort.Strings(list)
		s.Secrets = list
	}

	if s.Environment, err2 = parseEnvironment(m, body["environment"]); err2 != nil {
		return nil, fail("environment", "%v", err2)
	}
	if hc, ok := body["healthcheck"]; ok {
		hm, ok := hc.(map[string]any)
		if !ok {
			return nil, fail("healthcheck", "must be a mapping")
		}
		if err := checkHealthcheck(hm); err != nil {
			return nil, fail("healthcheck", "%v", err)
		}
		s.Healthcheck = hm
	}
	if s.DependsOn, err2 = parseDependsOn(body["depends_on"]); err2 != nil {
		return nil, fail("depends_on", "%v", err2)
	}
	if s.Mounts, err2 = parseVolumes(body["volumes"], declared); err2 != nil {
		return nil, fail("volumes", "%v", err2)
	}
	if raw, ok := body["tmpfs"]; ok {
		list, err := stringOrList(raw)
		if err != nil {
			return nil, fail("tmpfs", "must be a path or a list of paths")
		}
		for _, t := range list {
			p, _, _ := strings.Cut(t, ":")
			if !path.IsAbs(p) {
				return nil, fail("tmpfs", "%q is not an absolute path", t)
			}
		}
		s.Tmpfs = list
	}
	switch u := body["user"].(type) {
	case nil:
	case string:
		s.User = u
	case int64:
		s.User = strconv.FormatInt(u, 10)
	default:
		return nil, fail("user", "must be a string")
	}
	if wd, ok := body["working_dir"]; ok {
		w, ok := wd.(string)
		if !ok || !path.IsAbs(w) {
			return nil, fail("working_dir", "must be an absolute path")
		}
		s.WorkingDir = w
	}
	if ro, ok := body["read_only"]; ok {
		b, ok := ro.(bool)
		if !ok {
			return nil, fail("read_only", "must be a boolean")
		}
		s.ReadOnly = &b
	}
	if sg, ok := body["stop_grace_period"]; ok {
		d, ok := sg.(string)
		if !ok || !durationRe.MatchString(d) {
			return nil, fail("stop_grace_period", "must be a duration such as 30s")
		}
		s.StopGracePeriod = d
	}
	for _, key := range []string{"shm_size", "mem_limit"} {
		raw, ok := body[key]
		if !ok {
			continue
		}
		switch t := raw.(type) {
		case int64:
			if t <= 0 {
				return nil, fail(key, "must be positive")
			}
		case string:
			if !sizeRe.MatchString(t) {
				return nil, fail(key, "%q is not a byte size such as 512m", t)
			}
		default:
			return nil, fail(key, "must be a byte size")
		}
		if key == "shm_size" {
			s.ShmSize = raw
		} else {
			s.MemLimit = raw
		}
	}
	if raw, ok := body["cpus"]; ok {
		switch t := raw.(type) {
		case int64:
			if t <= 0 {
				return nil, fail("cpus", "must be positive")
			}
		case string:
			if !cpusRe.MatchString(t) {
				return nil, fail("cpus", "%q is not a CPU count such as \"0.5\"", t)
			}
		default:
			return nil, fail("cpus", "must be an integer or a quoted decimal such as \"0.5\"")
		}
		s.CPUs = raw
	}
	if raw, ok := body["ulimits"]; ok {
		ul, err := parseUlimits(raw)
		if err != nil {
			return nil, fail("ulimits", "%v", err)
		}
		s.Ulimits = ul
	}
	if raw, ok := body["labels"]; ok {
		lb, err := parseKeyValues(raw, labelKeyRe)
		if err != nil {
			return nil, fail("labels", "%v", err)
		}
		for k := range lb {
			if strings.HasPrefix(k, "com.docker.") || strings.HasPrefix(k, "dev.sealed.") {
				return nil, fail("labels", "%q uses a reserved prefix", k)
			}
		}
		s.Labels = lb
	}
	return s, nil
}

type literalErr struct{ key, msg string }

// literalize applies docker compose escaping rules to every string value
// (not keys): "$$" becomes "$", a lone "$" stays literal, and "$NAME" or
// "${...}" is rejected because interpolation would read unmeasured host
// environment. The composer re-escapes every "$" when it writes the compose.
func literalize(v any, key string) (any, *literalErr) {
	switch t := v.(type) {
	case string:
		out, err := unescapeDollar(t)
		if err != nil {
			return nil, &literalErr{key: key, msg: err.Error()}
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			n, err := literalize(e, key)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			child := k
			if key != "" {
				child = key + "." + k
			}
			n, err := literalize(e, child)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	default:
		return v, nil
	}
}

func unescapeDollar(s string) (string, error) {
	if !strings.Contains(s, "$") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		if i+1 < len(s) {
			n := s[i+1]
			switch {
			case n == '$':
				b.WriteByte('$')
				i++
				continue
			case n == '{' || n == '_' || (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z'):
				return "", fmt.Errorf("variable interpolation %q is not allowed (host environment is not measured); write $$ for a literal dollar sign", interpolationToken(s[i:]))
			}
		}
		b.WriteByte('$')
	}
	return b.String(), nil
}

func interpolationToken(s string) string {
	end := len(s)
	if len(s) > 1 && s[1] == '{' {
		if j := strings.IndexByte(s, '}'); j > 0 {
			end = j + 1
		}
	} else {
		for j := 1; j < len(s); j++ {
			c := s[j]
			if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				end = j
				break
			}
		}
	}
	return s[:end]
}

func stringList(v any) ([]string, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("not a list")
	}
	out := make([]string, len(list))
	for i, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("item %d is not a string", i)
		}
		out[i] = s
	}
	return out, nil
}

func stringOrList(v any) ([]string, error) {
	if s, ok := v.(string); ok {
		return []string{s}, nil
	}
	return stringList(v)
}

func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case int64:
		return strconv.FormatInt(t, 10), true
	case bool:
		return strconv.FormatBool(t), true
	}
	return "", false
}

// parseKeyValues accepts a mapping of scalars or a list of "KEY=value".
func parseKeyValues(v any, keyRe *regexp.Regexp) (map[string]string, error) {
	out := map[string]string{}
	switch t := v.(type) {
	case nil:
		return out, nil
	case map[string]any:
		for _, k := range sortedKeys(t) {
			if !keyRe.MatchString(k) {
				return nil, fmt.Errorf("invalid name %q", k)
			}
			if t[k] == nil {
				return nil, fmt.Errorf("%q has no value; values passed through from the host are not allowed", k)
			}
			s, ok := scalarString(t[k])
			if !ok {
				return nil, fmt.Errorf("%q must be a string, integer or boolean", k)
			}
			out[k] = s
		}
	case []any:
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("item %d is not a string", i)
			}
			k, val, found := strings.Cut(s, "=")
			if !found {
				return nil, fmt.Errorf("%q has no value; values passed through from the host are not allowed", s)
			}
			if !keyRe.MatchString(k) {
				return nil, fmt.Errorf("invalid name %q", k)
			}
			if _, dup := out[k]; dup {
				return nil, fmt.Errorf("duplicate %q", k)
			}
			out[k] = val
		}
	default:
		return nil, fmt.Errorf("must be a mapping or a list of KEY=value")
	}
	return out, nil
}

func parseEnvironment(m *Manifest, v any) (map[string]string, error) {
	env, err := parseKeyValues(v, envNameRe)
	if err != nil {
		return nil, err
	}
	for k := range env {
		if reservedEnv[k] {
			return nil, fmt.Errorf("%q is set by the composer", k)
		}
		if _, ok := m.Secret(k); ok {
			return nil, fmt.Errorf("%q is a declared secret; list it in x-sealed-secrets instead of setting a value", k)
		}
		if k == gateSecret {
			return nil, fmt.Errorf("%q is reserved", k)
		}
	}
	return env, nil
}

func checkHealthcheck(hm map[string]any) error {
	for _, k := range sortedKeys(hm) {
		if !healthKeys[k] {
			return fmt.Errorf("unknown healthcheck field %q", k)
		}
	}
	if t, ok := hm["test"]; ok {
		if _, isStr := t.(string); !isStr {
			if _, err := stringList(t); err != nil {
				return fmt.Errorf("test must be a string or a list of strings")
			}
		}
	}
	for _, k := range []string{"interval", "timeout", "start_period", "start_interval"} {
		if d, ok := hm[k]; ok {
			s, isStr := d.(string)
			if !isStr || !durationRe.MatchString(s) {
				return fmt.Errorf("%s must be a duration such as 10s", k)
			}
		}
	}
	if r, ok := hm["retries"]; ok {
		if n, isInt := r.(int64); !isInt || n < 0 {
			return fmt.Errorf("retries must be a non-negative integer")
		}
	}
	if d, ok := hm["disable"]; ok {
		if _, isBool := d.(bool); !isBool {
			return fmt.Errorf("disable must be a boolean")
		}
	}
	return nil
}

func parseDependsOn(v any) (map[string]string, error) {
	out := map[string]string{}
	switch t := v.(type) {
	case nil:
	case []any:
		names, err := stringList(t)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			out[n] = "service_started"
		}
	case map[string]any:
		for _, n := range sortedKeys(t) {
			spec, ok := t[n].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%q must be a mapping with a condition", n)
			}
			cond := "service_started"
			for _, k := range sortedKeys(spec) {
				switch k {
				case "condition":
					c, ok := spec[k].(string)
					if !ok || !dependConditions[c] {
						return nil, fmt.Errorf("%q: unknown condition %v", n, spec[k])
					}
					cond = c
				default:
					return nil, fmt.Errorf("%q: field %q is not allowed", n, k)
				}
			}
			out[n] = cond
		}
	default:
		return nil, fmt.Errorf("must be a list or a mapping")
	}
	return out, nil
}

func parseVolumes(v any, declared map[string]bool) ([]Mount, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("must be a list")
	}
	var out []Mount
	targets := map[string]bool{}
	for i, e := range list {
		var mnt Mount
		switch t := e.(type) {
		case string:
			parts := strings.Split(t, ":")
			if len(parts) < 2 || len(parts) > 3 {
				return nil, fmt.Errorf("item %d %q: use <volume>:<path>[:ro]; anonymous volumes are not allowed", i, t)
			}
			mnt = Mount{Type: "volume", Source: parts[0], Target: parts[1]}
			if len(parts) == 3 {
				switch parts[2] {
				case "ro":
					mnt.ReadOnly = true
				case "rw":
				default:
					return nil, fmt.Errorf("item %d %q: only the ro or rw option is allowed", i, t)
				}
			}
		case map[string]any:
			typ, _ := t["type"].(string)
			for _, k := range sortedKeys(t) {
				ok := k == "type" || k == "target" || k == "read_only" ||
					(k == "source" && typ == "volume") || (k == "tmpfs" && typ == "tmpfs")
				if !ok {
					return nil, fmt.Errorf("item %d: field %q is not allowed", i, k)
				}
			}
			target, _ := t["target"].(string)
			mnt = Mount{Type: typ, Target: target}
			if ro, ok := t["read_only"]; ok {
				b, isBool := ro.(bool)
				if !isBool {
					return nil, fmt.Errorf("item %d: read_only must be a boolean", i)
				}
				mnt.ReadOnly = b
			}
			switch typ {
			case "volume":
				mnt.Source, _ = t["source"].(string)
			case "tmpfs":
				if opts, ok := t["tmpfs"]; ok {
					om, isMap := opts.(map[string]any)
					if !isMap {
						return nil, fmt.Errorf("item %d: tmpfs options must be a mapping", i)
					}
					for _, k := range sortedKeys(om) {
						if k != "size" {
							return nil, fmt.Errorf("item %d: tmpfs option %q is not allowed", i, k)
						}
					}
					mnt.TmpfsSize = om["size"]
				}
			case "bind":
				return nil, fmt.Errorf("item %d: bind mounts are not allowed", i)
			default:
				return nil, fmt.Errorf("item %d: type must be volume or tmpfs", i)
			}
		default:
			return nil, fmt.Errorf("item %d: must be a string or a mapping", i)
		}
		if mnt.Type == "volume" {
			if strings.HasPrefix(mnt.Source, "/") || strings.HasPrefix(mnt.Source, ".") || strings.HasPrefix(mnt.Source, "~") || strings.Contains(mnt.Source, "/") {
				return nil, fmt.Errorf("item %d: bind mounts are not allowed (%q)", i, mnt.Source)
			}
			if !declared[mnt.Source] {
				return nil, fmt.Errorf("item %d: volume %q is not declared in the fragment's top-level volumes", i, mnt.Source)
			}
		}
		if !path.IsAbs(mnt.Target) || path.Clean(mnt.Target) != mnt.Target || mnt.Target == "/" {
			return nil, fmt.Errorf("item %d: target %q must be a clean absolute path", i, mnt.Target)
		}
		if strings.HasPrefix(mnt.Target+"/", "/run/sealed/") || strings.HasPrefix(mnt.Target+"/", "/sealed/") || mnt.Target == "/var/run/dstack.sock" {
			return nil, fmt.Errorf("item %d: target %q is reserved", i, mnt.Target)
		}
		if targets[mnt.Target] {
			return nil, fmt.Errorf("item %d: duplicate target %q", i, mnt.Target)
		}
		targets[mnt.Target] = true
		out = append(out, mnt)
	}
	return out, nil
}

func parseUlimits(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("must be a mapping")
	}
	for _, k := range sortedKeys(m) {
		if !ulimitNames[k] {
			return nil, fmt.Errorf("unknown ulimit %q", k)
		}
		switch t := m[k].(type) {
		case int64:
		case map[string]any:
			for _, f := range sortedKeys(t) {
				if f != "soft" && f != "hard" {
					return nil, fmt.Errorf("%s: field %q is not allowed", k, f)
				}
				if _, isInt := t[f].(int64); !isInt {
					return nil, fmt.Errorf("%s.%s must be an integer", k, f)
				}
			}
		default:
			return nil, fmt.Errorf("%s must be an integer or {soft, hard}", k)
		}
	}
	return m, nil
}
