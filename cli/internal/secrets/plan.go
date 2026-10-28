package secrets

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// Prefix starts every Secret Manager name the key broker may read (its IAM condition).
const Prefix = "sealed-"

// GateSecret holds the bcrypt hash of the password gate (released to sealed-agent's gate as _gate/GATE_PASSWORD_BCRYPT).
const GateSecret = "sealed-gate-password"

// GateApp is the pseudo app name of the gate password on the command line.
const GateApp = "gate"

// GateBcryptCost is the bcrypt cost of the stored gate hash.
const GateBcryptCost = 12

// StoredName is the Secret Manager name of an app secret: sealed-<app>-<NAME> (INTERFACES section 9).
func StoredName(app, name string) string { return Prefix + app + "-" + name }

// ParseStoredName splits sealed-<app>-<NAME>. App ids are lowercase and names start with an uppercase letter, so
// the split is unambiguous. The gate secret returns app "gate" and name "".
func ParseStoredName(s string) (app, name string, ok bool) {
	if s == GateSecret {
		return GateApp, "", true
	}
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return "", "", false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] == '-' && i+1 < len(rest) && rest[i+1] >= 'A' && rest[i+1] <= 'Z' {
			app, name = rest[:i], rest[i+1:]
			if appIDRe.MatchString(app) && secretNameRe.MatchString(name) {
				return app, name, true
			}
		}
	}
	return "", "", false
}

// Labels are the Secret Manager labels of an app secret (label values must be lowercase).
func Labels(app, name string) map[string]string {
	l := map[string]string{"managed-by": "sealed-cli", "sealed-app": app}
	if name != "" {
		l["sealed-key"] = strings.ToLower(name)
	}
	return l
}

// Generate creates a value with a manifest generator through runtime/composer's GenerateSecret, the one
// implementation of the schema's generators. rnd defaults to crypto/rand.
//   - hex32: 32 random bytes, lowercase hex (64 characters)
//   - base64-32: 32 random bytes, standard base64 with padding (44 characters)
//   - sk-hex32: "sk-" + hex32 (LiteLLM key format)
//   - password: 24 characters from [A-Za-z0-9], uniform (rejection sampling)
func Generate(kind string, rnd io.Reader) (string, error) {
	if kind == composer.GenerateNone || kind == "" {
		return "", fmt.Errorf("this secret has no generator: supply the value")
	}
	return composer.GenerateSecret(kind, rnd)
}

// GateHash returns the stored form of a gate password: its bcrypt hash. The plaintext never leaves the
// customer's terminal; the VM only ever sees the hash.
func GateHash(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("the gate password must have at least 12 characters")
	}
	if len(password) > 72 {
		return "", errors.New("the gate password can have at most 72 bytes (bcrypt)")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), GateBcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// Entry is one secret a stack needs, after same_as resolution.
type Entry struct {
	App        string // the manifest that declares it
	Name       string
	Stored     string // Secret Manager name holding the value
	Generate   string // generator of the stored value
	Optional   bool   // the declaring manifest's optional flag (a required reference never names an optional secret)
	SameAs     string // "<app>/<NAME>" when the value is another app's secret
	Desc       string
	ReferredBy []string // "<app>/<NAME>" entries that reuse this one
}

// Plan is the set of secrets a stack needs.
type Plan struct {
	Entries []Entry // sorted by app, then name
}

// Stored returns the entries that own a stored value (same_as entries excluded), one per Secret Manager name.
func (p *Plan) Stored() []Entry {
	var out []Entry
	for _, e := range p.Entries {
		if e.SameAs == "" {
			out = append(out, e)
		}
	}
	return out
}

// Find returns the entry of app/name.
func (p *Plan) Find(app, name string) (Entry, bool) {
	for _, e := range p.Entries {
		if e.App == app && e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// NewPlan resolves the secrets of the stack's apps with the composer's rules (D-043, D-059): a same_as reference
// must name an app of the stack that declares the secret, which is not itself a reference (no chains), lists the
// referencing app in its share_with, and is not optional when the reference is required.
func NewPlan(apps []*App) (*Plan, error) {
	byID := map[string]*App{}
	for _, a := range apps {
		if byID[a.ID] != nil {
			return nil, fmt.Errorf("app %s listed twice", a.ID)
		}
		byID[a.ID] = a
	}
	p := &Plan{}
	index := map[string]int{}
	for _, a := range apps {
		for _, s := range a.Secrets {
			e := Entry{App: a.ID, Name: s.Name, Stored: StoredName(a.ID, s.Name), Generate: s.Generate, Optional: s.Optional, SameAs: s.SameAs, Desc: s.Description}
			index[a.ID+"/"+s.Name] = len(p.Entries)
			p.Entries = append(p.Entries, e)
		}
	}
	for i := range p.Entries {
		e := &p.Entries[i]
		if e.SameAs == "" {
			continue
		}
		refApp, refName, _ := strings.Cut(e.SameAs, "/")
		target, ok := byID[refApp]
		if !ok {
			return nil, fmt.Errorf("%s/%s is the same as %s, but %s is not in the stack", e.App, e.Name, e.SameAs, refApp)
		}
		ts, ok := target.Secret(refName)
		if !ok {
			return nil, fmt.Errorf("%s/%s is the same as %s, which %s does not declare", e.App, e.Name, e.SameAs, refApp)
		}
		if ts.SameAs != "" {
			return nil, fmt.Errorf("%s/%s refers to %s, which itself refers to %s (no chains)", e.App, e.Name, e.SameAs, ts.SameAs)
		}
		if !ts.SharedWith(e.App) {
			return nil, fmt.Errorf("%s/%s is the same as %s, but %s does not share it with %s: the key broker would refuse this stack (D-059: %s must list %s in share_with)", e.App, e.Name, e.SameAs, refApp, e.App, e.SameAs, e.App)
		}
		if ts.Optional && !e.Optional {
			return nil, fmt.Errorf("%s/%s is required but refers to %s, which is optional in %s (the composer refuses this stack)", e.App, e.Name, e.SameAs, refApp)
		}
		t := &p.Entries[index[e.SameAs]]
		e.Stored = t.Stored
		e.Generate = t.Generate
		t.ReferredBy = append(t.ReferredBy, e.App+"/"+e.Name)
	}
	sort.SliceStable(p.Entries, func(i, j int) bool {
		if p.Entries[i].App != p.Entries[j].App {
			return p.Entries[i].App < p.Entries[j].App
		}
		return p.Entries[i].Name < p.Entries[j].Name
	})
	return p, nil
}
