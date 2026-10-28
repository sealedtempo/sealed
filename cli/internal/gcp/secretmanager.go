package gcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// SecretManager manages one project's secrets.
type SecretManager struct {
	C       *Client
	Project string
	Root    string // default SecretManagerRoot
}

// SecretInfo describes a secret without its value.
type SecretInfo struct {
	Name       string            // short name, for example sealed-crm-APP_SECRET
	CreateTime string            // RFC 3339
	Labels     map[string]string // sealed-app, sealed-key
}

func (s *SecretManager) root() string {
	if s.Root != "" {
		return s.Root
	}
	return SecretManagerRoot
}

func (s *SecretManager) secretURL(name string) string {
	return fmt.Sprintf("%s/projects/%s/secrets/%s", s.root(), url.PathEscape(s.Project), url.PathEscape(name))
}

type smSecret struct {
	Name        string            `json:"name,omitempty"`
	CreateTime  string            `json:"createTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Replication map[string]any    `json:"replication,omitempty"`
}

// Create creates an empty secret with automatic replication, or with user-managed replication in location.
func (s *SecretManager) Create(ctx context.Context, name string, labels map[string]string, location string) error {
	repl := map[string]any{"automatic": map[string]any{}}
	if location != "" {
		repl = map[string]any{"userManaged": map[string]any{"replicas": []map[string]string{{"location": location}}}}
	}
	u := fmt.Sprintf("%s/projects/%s/secrets?secretId=%s", s.root(), url.PathEscape(s.Project), url.QueryEscape(name))
	return s.C.Do(ctx, "POST", u, smSecret{Labels: labels, Replication: repl}, nil)
}

// Exists reports whether the secret exists.
func (s *SecretManager) Exists(ctx context.Context, name string) (bool, error) {
	err := s.C.Do(ctx, "GET", s.secretURL(name), nil, nil)
	if err == nil {
		return true, nil
	}
	if IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// AddVersion stores value as the secret's newest version, with a CRC32C checksum the service verifies.
func (s *SecretManager) AddVersion(ctx context.Context, name string, value []byte) (string, error) {
	sum := crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli))
	body := map[string]any{"payload": map[string]string{
		"data":       base64.StdEncoding.EncodeToString(value),
		"dataCrc32c": strconv.FormatUint(uint64(sum), 10),
	}}
	var out struct {
		Name string `json:"name"`
	}
	if err := s.C.Do(ctx, "POST", s.secretURL(name)+":addVersion", body, &out); err != nil {
		return "", err
	}
	return out.Name, nil
}

// Delete deletes the secret and all its versions.
func (s *SecretManager) Delete(ctx context.Context, name string) error {
	return s.C.Do(ctx, "DELETE", s.secretURL(name), nil, nil)
}

// List returns every secret whose name starts with prefix, sorted by name.
func (s *SecretManager) List(ctx context.Context, prefix string) ([]SecretInfo, error) {
	var all []SecretInfo
	page := ""
	for i := 0; i < 1000; i++ {
		q := url.Values{"pageSize": {"250"}}
		if prefix != "" {
			q.Set("filter", "name:"+prefix)
		}
		if page != "" {
			q.Set("pageToken", page)
		}
		var out struct {
			Secrets       []smSecret `json:"secrets"`
			NextPageToken string     `json:"nextPageToken"`
		}
		u := fmt.Sprintf("%s/projects/%s/secrets?%s", s.root(), url.PathEscape(s.Project), q.Encode())
		if err := s.C.Do(ctx, "GET", u, nil, &out); err != nil {
			return nil, err
		}
		for _, sec := range out.Secrets {
			short := sec.Name[strings.LastIndex(sec.Name, "/")+1:]
			if strings.HasPrefix(short, prefix) {
				all = append(all, SecretInfo{Name: short, CreateTime: sec.CreateTime, Labels: sec.Labels})
			}
		}
		if out.NextPageToken == "" {
			break
		}
		page = out.NextPageToken
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	return all, nil
}
