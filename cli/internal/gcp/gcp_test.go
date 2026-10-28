package gcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const secretToken = "ya29.test-token-never-printed"

func newClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secretToken {
			http.Error(w, `{"error":{"code":401,"message":"no token","status":"UNAUTHENTICATED"}}`, 401)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return &Client{HTTP: srv.Client(), Tokens: StaticToken(secretToken), Sleep: func(time.Duration) {}}, srv
}

func TestDoRetriesAndErrors(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	c, srv := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		switch r.URL.Path {
		case "/flaky":
			if n < 3 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, `{"ok":true}`)
		case "/denied":
			w.WriteHeader(403)
			io.WriteString(w, `{"error":{"code":403,"message":"Permission 'secretmanager.versions.access' denied","status":"PERMISSION_DENIED"}}`)
		}
	})
	var out struct{ OK bool }
	if err := c.Do(context.Background(), "GET", srv.URL+"/flaky", nil, &out); err != nil || !out.OK {
		t.Fatalf("flaky: %v %+v", err, out)
	}
	err := c.Do(context.Background(), "GET", srv.URL+"/denied?key=x", nil, nil)
	if !IsPermissionDenied(err) {
		t.Fatalf("want permission denied, got %v", err)
	}
	if strings.Contains(err.Error(), secretToken) || strings.Contains(err.Error(), "key=x") {
		t.Fatalf("error leaks token or query: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != "PERMISSION_DENIED" {
		t.Fatalf("status: %+v", apiErr)
	}
}

func TestSecretManager(t *testing.T) {
	store := map[string][]string{}
	labels := map[string]map[string]string{}
	c, srv := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		const base = "/projects/acme-prod-4417/secrets"
		switch {
		case r.Method == "POST" && r.URL.Path == base:
			id := r.URL.Query().Get("secretId")
			if _, ok := store[id]; ok {
				w.WriteHeader(409)
				io.WriteString(w, `{"error":{"code":409,"message":"exists","status":"ALREADY_EXISTS"}}`)
				return
			}
			var body smSecret
			json.NewDecoder(r.Body).Decode(&body)
			if _, ok := body.Replication["automatic"]; !ok {
				t.Errorf("replication %v", body.Replication)
			}
			store[id] = nil
			labels[id] = body.Labels
			io.WriteString(w, `{}`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":addVersion"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, base+"/"), ":addVersion")
			var body struct {
				Payload struct{ Data, DataCrc32c string }
			}
			json.NewDecoder(r.Body).Decode(&body)
			data, _ := base64.StdEncoding.DecodeString(body.Payload.Data)
			if strconv.FormatUint(uint64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))), 10) != body.Payload.DataCrc32c {
				w.WriteHeader(400)
				return
			}
			store[id] = append(store[id], string(data))
			io.WriteString(w, `{"name":"projects/1/secrets/`+id+`/versions/`+strconv.Itoa(len(store[id]))+`"}`)
		case r.Method == "GET" && r.URL.Path == base:
			if r.URL.Query().Get("filter") != "name:sealed-" {
				t.Errorf("filter %q", r.URL.Query().Get("filter"))
			}
			// Two pages, plus a secret that only contains the prefix.
			if r.URL.Query().Get("pageToken") == "" {
				io.WriteString(w, `{"secrets":[{"name":"projects/1/secrets/sealed-crm-APP_SECRET","createTime":"2026-10-28T00:00:00Z","labels":{"sealed-app":"crm"}},{"name":"projects/1/secrets/not-sealed-x"}],"nextPageToken":"p2"}`)
				return
			}
			io.WriteString(w, `{"secrets":[{"name":"projects/1/secrets/sealed-gate-password"}]}`)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, base+"/"):
			id := strings.TrimPrefix(r.URL.Path, base+"/")
			if _, ok := store[id]; !ok {
				w.WriteHeader(404)
				io.WriteString(w, `{"error":{"code":404,"message":"not found","status":"NOT_FOUND"}}`)
				return
			}
			io.WriteString(w, `{}`)
		case r.Method == "DELETE":
			delete(store, strings.TrimPrefix(r.URL.Path, base+"/"))
			io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	})
	sm := &SecretManager{C: c, Project: "acme-prod-4417", Root: srv.URL}
	ctx := context.Background()
	if ok, err := sm.Exists(ctx, "sealed-crm-APP_SECRET"); err != nil || ok {
		t.Fatalf("exists before create: %v %v", ok, err)
	}
	if err := sm.Create(ctx, "sealed-crm-APP_SECRET", map[string]string{"sealed-app": "crm"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := sm.Create(ctx, "sealed-crm-APP_SECRET", nil, ""); !IsConflict(err) {
		t.Fatalf("second create: %v", err)
	}
	v, err := sm.AddVersion(ctx, "sealed-crm-APP_SECRET", []byte("s3cr3t\x00bytes"))
	if err != nil || !strings.HasSuffix(v, "/versions/1") {
		t.Fatalf("add version: %q %v", v, err)
	}
	if store["sealed-crm-APP_SECRET"][0] != "s3cr3t\x00bytes" || labels["sealed-crm-APP_SECRET"]["sealed-app"] != "crm" {
		t.Fatalf("store %q labels %v", store, labels)
	}
	list, err := sm.List(ctx, "sealed-")
	if err != nil || len(list) != 2 || list[0].Name != "sealed-crm-APP_SECRET" || list[1].Name != "sealed-gate-password" || list[0].Labels["sealed-app"] != "crm" {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := sm.Delete(ctx, "sealed-crm-APP_SECRET"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := sm.Exists(ctx, "sealed-crm-APP_SECRET"); ok {
		t.Fatal("still exists after delete")
	}
}

func TestComputeEnsureAndOperations(t *testing.T) {
	polls := 0
	var inserted Instance
	addrExists := false
	c, srv := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/projects/acme-prod-4417")
		switch {
		case r.Method == "GET" && p == "/regions/us-central1/addresses/sealed-abc-ip":
			if !addrExists {
				w.WriteHeader(404)
				io.WriteString(w, `{"error":{"code":404,"message":"nf","status":"NOT_FOUND"}}`)
				return
			}
			io.WriteString(w, `{"name":"sealed-abc-ip","address":"34.1.2.3","status":"RESERVED"}`)
		case r.Method == "POST" && p == "/regions/us-central1/addresses":
			var a Address
			json.NewDecoder(r.Body).Decode(&a)
			if a.AddressType != "EXTERNAL" || a.NetworkTier != "PREMIUM" {
				t.Errorf("address %+v", a)
			}
			addrExists = true
			io.WriteString(w, `{"name":"op-a","status":"RUNNING"}`)
		case r.Method == "GET" && p == "/regions/us-central1/operations/op-a":
			io.WriteString(w, `{"name":"op-a","status":"DONE"}`)
		case r.Method == "POST" && p == "/zones/us-central1-a/instances":
			if r.URL.Query().Get("requestId") != "11111111-2222-3333-4444-555555555555" {
				t.Errorf("requestId %q", r.URL.Query().Get("requestId"))
			}
			raw, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(raw), `"serviceAccounts":[]`) {
				t.Errorf("instance body must carry an explicit empty serviceAccounts list: %s", raw)
			}
			json.Unmarshal(raw, &inserted)
			io.WriteString(w, `{"name":"op-i","status":"PENDING"}`)
		case r.Method == "GET" && p == "/zones/us-central1-a/operations/op-i":
			polls++
			if polls < 2 {
				io.WriteString(w, `{"name":"op-i","status":"RUNNING"}`)
				return
			}
			io.WriteString(w, `{"name":"op-i","status":"DONE","error":{"errors":[{"code":"QUOTA_EXCEEDED","message":"C3 CPUs"}]}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	})
	ce := &Compute{C: c, Project: "acme-prod-4417", Root: srv.URL, Sleep: func(time.Duration) {}}
	ctx := context.Background()
	a, err := ce.EnsureAddress(ctx, "us-central1", "sealed-abc-ip", "x")
	if err != nil || a.Address != "34.1.2.3" {
		t.Fatalf("ensure address %+v %v", a, err)
	}
	err = ce.InsertInstance(ctx, "us-central1-a", &Instance{Name: "sealed-abc", ServiceAccounts: []ServiceAccount{}}, "11111111-2222-3333-4444-555555555555")
	if err == nil || !strings.Contains(err.Error(), "QUOTA_EXCEEDED") {
		t.Fatalf("operation error not surfaced: %v", err)
	}
	if inserted.Name != "sealed-abc" || polls != 2 {
		t.Fatalf("inserted %+v polls %d", inserted, polls)
	}
}

func TestGcloudToken(t *testing.T) {
	var args []string
	now := time.Unix(1000, 0)
	g := &GcloudToken{Impersonate: "sealed-deployer@p.iam.gserviceaccount.com", Now: func() time.Time { return now }, Run: func(_ context.Context, name string, a ...string) ([]byte, error) {
		args = append([]string{name}, a...)
		return []byte("tok-1\n"), nil
	}}
	tok, err := g.Token(context.Background())
	if err != nil || tok != "tok-1" {
		t.Fatalf("%q %v", tok, err)
	}
	if strings.Join(args, " ") != "gcloud auth print-access-token --impersonate-service-account=sealed-deployer@p.iam.gserviceaccount.com" {
		t.Fatalf("args %v", args)
	}
	args = nil
	if tok, _ := g.Token(context.Background()); tok != "tok-1" || args != nil {
		t.Fatal("token not cached")
	}
	now = now.Add(time.Hour)
	g.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := g.Token(context.Background()); err == nil {
		t.Fatal("expired token not refreshed")
	}
}

func TestADCToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "rt" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"access_token":"at-1","expires_in":3599}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	f := filepath.Join(dir, "adc.json")
	os.WriteFile(f, []byte(`{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"rt"}`), 0o600)
	a := &ADCToken{File: f, HTTP: srv.Client(), TokenURL: srv.URL}
	if tok, err := a.Token(context.Background()); err != nil || tok != "at-1" {
		t.Fatalf("%q %v", tok, err)
	}
	sa := filepath.Join(dir, "sa.json")
	os.WriteFile(sa, []byte(`{"type":"service_account"}`), 0o600)
	if _, err := (&ADCToken{File: sa}).Token(context.Background()); err == nil {
		t.Fatal("service account key files are not supported")
	}
}

func TestDefaultTokenSource(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	noGcloud := func(string) (string, error) { return "", errors.New("not found") }
	withGcloud := func(string) (string, error) { return "/usr/bin/gcloud", nil }

	env["SEALED_GCP_ACCESS_TOKEN"] = "abc"
	if ts, _ := DefaultTokenSource(getenv, withGcloud, ""); ts != StaticToken("abc") {
		t.Fatalf("env token first: %T", ts)
	}
	delete(env, "SEALED_GCP_ACCESS_TOKEN")
	if ts, _ := DefaultTokenSource(getenv, withGcloud, "x@y.iam.gserviceaccount.com"); ts.(*GcloudToken).Impersonate != "x@y.iam.gserviceaccount.com" {
		t.Fatal("gcloud with impersonation")
	}
	if _, err := DefaultTokenSource(getenv, noGcloud, "x@y.iam.gserviceaccount.com"); err == nil {
		t.Fatal("impersonation without gcloud")
	}
	env["HOME"] = t.TempDir()
	if _, err := DefaultTokenSource(getenv, noGcloud, ""); err == nil {
		t.Fatal("no credentials at all")
	}
	adc := filepath.Join(env["HOME"], ".config", "gcloud", "application_default_credentials.json")
	os.MkdirAll(filepath.Dir(adc), 0o700)
	os.WriteFile(adc, []byte(`{}`), 0o600)
	if ts, err := DefaultTokenSource(getenv, noGcloud, ""); err != nil || ts.(*ADCToken).File != adc {
		t.Fatalf("well-known ADC file: %v", err)
	}
}
