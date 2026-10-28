// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// resource is the gce_instance monitored resource the entries are written under.
type resource struct {
	ProjectID  string
	InstanceID string
	Zone       string
}

// metadataClient reads the instance identity and service account tokens from the GCE metadata server.
type metadataClient struct {
	base string
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (m *metadataClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(m.base, "/")+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata %s: HTTP %d", path, resp.StatusCode)
	}
	return body, nil
}

func (m *metadataClient) resource(ctx context.Context) (resource, error) {
	var r resource
	for _, f := range []struct {
		path string
		dst  *string
	}{
		{"project/project-id", &r.ProjectID},
		{"instance/id", &r.InstanceID},
		{"instance/zone", &r.Zone},
	} {
		b, err := m.get(ctx, f.path)
		if err != nil {
			return resource{}, err
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return resource{}, fmt.Errorf("metadata %s is empty", f.path)
		}
		*f.dst = v
	}
	// instance/zone is "projects/<number>/zones/<zone>".
	r.Zone = r.Zone[strings.LastIndex(r.Zone, "/")+1:]
	return r, nil
}

var errNoServiceAccount = errors.New("the VM has no service account: create debug VMs with a service account that has roles/logging.logWriter and the logging.write scope")

// accessToken returns a cached OAuth token for the default service account, refreshed a minute before expiry.
func (m *metadataClient) accessToken(ctx context.Context) (string, error) {
	now := time.Now
	if m.now != nil {
		now = m.now
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" && now().Before(m.expires) {
		return m.token, nil
	}
	b, err := m.get(ctx, "instance/service-accounts/default/token")
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 404") {
			return "", errNoServiceAccount
		}
		return "", err
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return "", fmt.Errorf("metadata token: %w", err)
	}
	if t.AccessToken == "" {
		return "", errors.New("metadata token: empty access_token")
	}
	m.token = t.AccessToken
	m.expires = now().Add(time.Duration(t.ExpiresIn)*time.Second - time.Minute)
	return m.token, nil
}

// invalidate drops the cached token after the API rejected it.
func (m *metadataClient) invalidate() {
	m.mu.Lock()
	m.token = ""
	m.mu.Unlock()
}
