package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/sealedtempo/sealed/cli/internal/gcp"
)

// Store is the customer's secret store (Secret Manager). Values are write-only from the CLI: it never reads them
// back.
type Store interface {
	Exists(ctx context.Context, name string) (bool, error)
	Create(ctx context.Context, name string, labels map[string]string, location string) error
	AddVersion(ctx context.Context, name string, value []byte) (string, error)
	List(ctx context.Context, prefix string) ([]gcp.SecretInfo, error)
	Delete(ctx context.Context, name string) error
}

// Manager writes secrets.
type Manager struct {
	Store Store
	// Location pins replication to one region; empty means automatic replication.
	Location string
	Rand     io.Reader
}

// ErrExists is returned when a secret exists and rotation was not requested.
var ErrExists = errors.New("secret already exists")

// Put stores value under stored. An existing secret gets a new version only with rotate (rotating an app's
// encryption key can make its data unreadable, so it is never implicit).
func (m *Manager) Put(ctx context.Context, stored string, labels map[string]string, value []byte, rotate bool) (created bool, err error) {
	if len(value) == 0 {
		return false, errors.New("refusing to store an empty value")
	}
	if len(value) > 64<<10 {
		return false, errors.New("secret values are limited to 64 KiB")
	}
	exists, err := m.Store.Exists(ctx, stored)
	if err != nil {
		return false, err
	}
	if exists && !rotate {
		return false, fmt.Errorf("%s: %w (pass --rotate to add a new version)", stored, ErrExists)
	}
	if !exists {
		if err := m.Store.Create(ctx, stored, labels, m.Location); err != nil && !gcp.IsConflict(err) {
			return false, err
		}
	}
	if _, err := m.Store.AddVersion(ctx, stored, value); err != nil {
		return !exists, err
	}
	return !exists, nil
}

// Status of one planned entry in the store.
type Status struct {
	Entry
	Present bool
}

// Inspect reports, for every entry of plan plus the gate password, whether its stored value exists.
func (m *Manager) Inspect(ctx context.Context, plan *Plan) ([]Status, bool, error) {
	list, err := m.Store.List(ctx, Prefix)
	if err != nil {
		return nil, false, err
	}
	have := map[string]bool{}
	for _, s := range list {
		have[s.Name] = true
	}
	var out []Status
	for _, e := range plan.Entries {
		out = append(out, Status{Entry: e, Present: have[e.Stored]})
	}
	return out, have[GateSecret], nil
}

// FillResult is what FillMissing did.
type FillResult struct {
	Generated []string // stored names generated now
	Supplied  []string // stored names the customer typed now
	Missing   []string // required stored names still without a value
	Skipped   []string // optional stored names left unset
	// GatePassword is the generated gate password, to show once. Empty when the gate was already set or
	// supplied.
	GatePassword string
}

// Asker asks the customer for a value; ok false means no answer (non-interactive).
type Asker func(stored, description string) (value string, ok bool, err error)

// FillMissing gives every required secret without a stored value one: generated when the manifest names a
// generator, otherwise asked (when ask is non-nil). Each stored name is handled once, so a same_as pair is
// asked or generated once (D-043). The gate password is generated when absent.
func (m *Manager) FillMissing(ctx context.Context, plan *Plan, ask Asker, withGate bool) (*FillResult, error) {
	statuses, gatePresent, err := m.Inspect(ctx, plan)
	if err != nil {
		return nil, err
	}
	res := &FillResult{}
	done := map[string]bool{}
	for _, st := range statuses {
		if st.SameAs != "" || done[st.Stored] {
			continue
		}
		done[st.Stored] = true
		if st.Present {
			continue
		}
		if st.Optional {
			res.Skipped = append(res.Skipped, st.Stored)
			continue
		}
		var value string
		if st.Generate != "none" {
			if value, err = Generate(st.Generate, m.Rand); err != nil {
				return res, err
			}
			res.Generated = append(res.Generated, st.Stored)
		} else {
			if ask == nil {
				res.Missing = append(res.Missing, st.Stored)
				continue
			}
			v, ok, err := ask(st.Stored, st.Desc)
			if err != nil {
				return res, err
			}
			if !ok || v == "" {
				res.Missing = append(res.Missing, st.Stored)
				continue
			}
			value = v
			res.Supplied = append(res.Supplied, st.Stored)
		}
		if _, err := m.Put(ctx, st.Stored, Labels(st.App, st.Name), []byte(value), false); err != nil {
			return res, err
		}
	}
	if withGate && !gatePresent {
		pw, err := Generate("password", m.Rand)
		if err != nil {
			return res, err
		}
		h, err := GateHash(pw)
		if err != nil {
			return res, err
		}
		if _, err := m.Put(ctx, GateSecret, Labels(GateApp, ""), []byte(h), false); err != nil {
			return res, err
		}
		res.GatePassword = pw
		res.Generated = append(res.Generated, GateSecret)
	}
	sort.Strings(res.Missing)
	return res, nil
}
