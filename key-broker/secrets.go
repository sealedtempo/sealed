package keybroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// Secret Manager naming (INTERFACES.md section 9).
const (
	SecretPrefix = "sealed-"
	// GateSecretID holds the bcrypt hash of the password gate, released as _gate/GATE_PASSWORD_BCRYPT.
	GateSecretID = "sealed-gate-password"
	// GateOwner and GateSecretName are where the gate hash appears in the release plaintext (INTERFACES.md 9, 14).
	GateOwner      = "_gate"
	GateSecretName = "GATE_PASSWORD_BCRYPT"
	// MaxSecretBytes is Secret Manager's limit on one secret version.
	MaxSecretBytes = 64 << 10
)

// ErrSecretNotFound is returned by a SecretStore when the secret (or its latest version) does not exist.
var ErrSecretNotFound = errors.New("secret not found")

// SecretStore reads the latest version of a secret by id. Production: Secret Manager (key-broker/gcp). Locally and
// in tests: MemorySecretStore.
type SecretStore interface {
	Access(ctx context.Context, id string) ([]byte, error)
}

// SecretID returns the Secret Manager id of an app secret: sealed-<appId>-<NAME>. App ids are lowercase with
// hyphens and names are uppercase without hyphens, so the id is unambiguous.
func SecretID(app, name string) string { return SecretPrefix + app + "-" + name }

var (
	secretNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	appIDRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	sameAsRe     = regexp.MustCompile(`^([a-z][a-z0-9-]{1,30}[a-z0-9])/([A-Z][A-Z0-9_]*)$`)
)

// SecretRef is one value of the release plaintext and where it comes from.
type SecretRef struct {
	Owner    string // app id or _gate
	Name     string // name under the owner
	Source   string // Secret Manager id
	Optional bool
}

// manifestSecret is the part of a manifest secrets[] entry the broker needs. same_as (D-043) is read from the raw
// manifest so the broker does not depend on the composer's Manifest struct carrying it.
type manifestSecret struct {
	Name     string `yaml:"name"`
	Optional bool   `yaml:"optional"`
	SameAs   string `yaml:"same_as"`
}

func manifestSecrets(b *composer.Bundle) ([]manifestSecret, error) {
	raw, ok := b.Files[composer.ManifestFile]
	if !ok {
		return nil, fmt.Errorf("bundle of %s has no %s", b.Manifest.ID, composer.ManifestFile)
	}
	var doc struct {
		ID      string           `yaml:"id"`
		Secrets []manifestSecret `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s manifest secrets: %v", b.Manifest.ID, err)
	}
	if doc.ID != b.Manifest.ID {
		return nil, fmt.Errorf("manifest id %q differs from the loaded bundle %q", doc.ID, b.Manifest.ID)
	}
	return doc.Secrets, nil
}

// PlanSecrets lists the values a release carries: every secret named in the manifests of the stack's apps (in
// config.apps order), each under its own app, plus the gate hash. A same_as reference "<appId>/<NAME>" is read from
// the referenced app's secret and returned under the referencing app's name (D-043); the referenced app must be in
// the stack and declare that secret. Nothing outside the manifests is ever released.
func PlanSecrets(apps []string, bundles map[string]*composer.Bundle) ([]SecretRef, error) {
	declared := map[string]map[string]manifestSecret{}
	for _, app := range apps {
		b, ok := bundles[app]
		if !ok || b == nil {
			return nil, fmt.Errorf("no bundle for app %q", app)
		}
		list, err := manifestSecrets(b)
		if err != nil {
			return nil, err
		}
		m := map[string]manifestSecret{}
		for _, s := range list {
			if !secretNameRe.MatchString(s.Name) {
				return nil, fmt.Errorf("%s: secret name %q is invalid", app, s.Name)
			}
			if _, dup := m[s.Name]; dup {
				return nil, fmt.Errorf("%s: secret %s is declared twice", app, s.Name)
			}
			m[s.Name] = s
		}
		declared[app] = m
	}
	// resolve follows same_as chains to the secret that is actually stored.
	var resolve func(app, name string, seen map[string]bool) (string, error)
	resolve = func(app, name string, seen map[string]bool) (string, error) {
		key := app + "/" + name
		if seen[key] {
			return "", fmt.Errorf("same_as cycle through %s", key)
		}
		seen[key] = true
		s, ok := declared[app][name]
		if !ok {
			return "", fmt.Errorf("%s is not declared by app %s in this stack", key, app)
		}
		if s.SameAs == "" {
			return SecretID(app, name), nil
		}
		m := sameAsRe.FindStringSubmatch(s.SameAs)
		if m == nil {
			return "", fmt.Errorf("%s: same_as %q is not <appId>/<NAME>", key, s.SameAs)
		}
		if _, ok := declared[m[1]]; !ok {
			return "", fmt.Errorf("%s: same_as %s names app %s, which is not in the stack", key, s.SameAs, m[1])
		}
		return resolve(m[1], m[2], seen)
	}
	var refs []SecretRef
	for _, app := range apps {
		names := make([]string, 0, len(declared[app]))
		for n := range declared[app] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			src, err := resolve(app, n, map[string]bool{})
			if err != nil {
				return nil, err
			}
			refs = append(refs, SecretRef{Owner: app, Name: n, Source: src, Optional: declared[app][n].Optional})
		}
	}
	refs = append(refs, SecretRef{Owner: GateOwner, Name: GateSecretName, Source: GateSecretID})
	return refs, nil
}

// SecretError is a secret that is missing or unusable. It answers 503: the customer can fix it with
// `sealed secrets set`, and the agent retries.
type SecretError struct {
	Reason string // ReasonSecretMissing or ReasonSecretInvalid
	Ref    string // "<owner>/<NAME> (<secret id>)"
	Msg    string
}

func (e *SecretError) Error() string { return fmt.Sprintf("%s: %s %s", e.Reason, e.Ref, e.Msg) }

// readSecrets reads every planned secret once per source. Missing optional secrets are left out.
func readSecrets(ctx context.Context, store SecretStore, refs []SecretRef) (map[string]map[string]string, []string, error) {
	cache := map[string][]byte{}
	missing := map[string]bool{}
	out := map[string]map[string]string{}
	var released []string
	for _, r := range refs {
		label := fmt.Sprintf("%s/%s (%s)", r.Owner, r.Name, r.Source)
		val, ok := cache[r.Source]
		if !ok && !missing[r.Source] {
			v, err := store.Access(ctx, r.Source)
			switch {
			case errors.Is(err, ErrSecretNotFound):
				missing[r.Source] = true
			case err != nil:
				return nil, nil, fmt.Errorf("read %s: %w", r.Source, err)
			default:
				val, ok = v, true
				cache[r.Source] = v
			}
		}
		if !ok {
			if r.Optional {
				continue
			}
			return nil, nil, &SecretError{Reason: ReasonSecretMissing, Ref: label, Msg: "is not stored; set it with `sealed secrets set`"}
		}
		if len(val) > MaxSecretBytes {
			return nil, nil, &SecretError{Reason: ReasonSecretInvalid, Ref: label, Msg: fmt.Sprintf("is %d bytes, over %d", len(val), MaxSecretBytes)}
		}
		if !utf8.Valid(val) {
			return nil, nil, &SecretError{Reason: ReasonSecretInvalid, Ref: label, Msg: "is not valid UTF-8"}
		}
		if r.Owner == GateOwner {
			if _, err := bcrypt.Cost(val); err != nil {
				return nil, nil, &SecretError{Reason: ReasonSecretInvalid, Ref: label, Msg: "must hold a bcrypt hash of the gate password, not the password itself"}
			}
		}
		if out[r.Owner] == nil {
			out[r.Owner] = map[string]string{}
		}
		out[r.Owner][r.Name] = string(val)
		released = append(released, r.Owner+"/"+r.Name)
	}
	return out, released, nil
}

// MemorySecretStore is an in-memory SecretStore: the local fake of Secret Manager.
type MemorySecretStore struct {
	mu   sync.Mutex
	vals map[string][]byte
	// Reads counts Access calls per id (tests).
	reads map[string]int
	// Fail makes every Access return this error.
	Fail error
}

// NewMemorySecretStore returns a store holding vals (secret id -> value).
func NewMemorySecretStore(vals map[string]string) *MemorySecretStore {
	m := &MemorySecretStore{vals: map[string][]byte{}, reads: map[string]int{}}
	for k, v := range vals {
		m.vals[k] = []byte(v)
	}
	return m
}

// LoadSecretsFile reads a JSON object {"sealed-<app>-<NAME>": "value", ...} into a MemorySecretStore (dev only).
func LoadSecretsFile(path string) (*MemorySecretStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vals map[string]string
	if err := json.Unmarshal(raw, &vals); err != nil {
		return nil, fmt.Errorf("dev secrets file %s: %v", path, err)
	}
	for k := range vals {
		if !strings.HasPrefix(k, SecretPrefix) {
			return nil, fmt.Errorf("dev secrets file %s: %q does not start with %q", path, k, SecretPrefix)
		}
	}
	return NewMemorySecretStore(vals), nil
}

// Set stores a value.
func (m *MemorySecretStore) Set(id, val string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vals[id] = []byte(val)
}

// Delete removes a value.
func (m *MemorySecretStore) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.vals, id)
}

// Reads returns how often id was read.
func (m *MemorySecretStore) Reads(id string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reads[id]
}

// Access implements SecretStore.
func (m *MemorySecretStore) Access(_ context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads[id]++
	if m.Fail != nil {
		return nil, m.Fail
	}
	v, ok := m.vals[id]
	if !ok {
		return nil, ErrSecretNotFound
	}
	return append([]byte(nil), v...), nil
}

// validAppID reports whether s is an app id usable in a secret id.
func validAppID(s string) bool { return appIDRe.MatchString(s) }
