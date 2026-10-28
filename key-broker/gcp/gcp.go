// Package gcp implements the key broker's Google Cloud backends over their REST APIs: Secret Manager (secret
// values), Cloud KMS (HMAC-SHA256 with the bootstrap's MAC key) and Cloud Logging (decision log). Credentials come
// from the Cloud Run metadata server, so the broker uses its own service account and needs no client libraries.
// No secret value, token or MAC ever appears in an error.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TokenSource returns an OAuth2 access token for Google APIs.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// MetadataTokenSource reads the service account's access token from the metadata server and caches it until a
// minute before it expires.
type MetadataTokenSource struct {
	// Host is the metadata server; empty means $GCE_METADATA_HOST or metadata.google.internal.
	Host   string
	Client *http.Client
	Now    func() time.Time

	mu  sync.Mutex
	tok string
	exp time.Time
}

// Token implements TokenSource.
func (m *MetadataTokenSource) Token(ctx context.Context) (string, error) {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tok != "" && now().Before(m.exp) {
		return m.tok, nil
	}
	host := m.Host
	if host == "" {
		host = os.Getenv("GCE_METADATA_HOST")
	}
	if host == "" {
		host = "metadata.google.internal"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client(m.Client).Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata token: HTTP %d", resp.StatusCode)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &t); err != nil || t.AccessToken == "" {
		return "", errors.New("metadata token: malformed response")
	}
	m.tok = t.AccessToken
	m.exp = now().Add(time.Duration(t.ExpiresIn)*time.Second - time.Minute)
	return m.tok, nil
}

// StaticToken is a fixed token (tests).
type StaticToken string

// Token implements TokenSource.
func (s StaticToken) Token(context.Context) (string, error) { return string(s), nil }

var defaultClient = &http.Client{Timeout: 30 * time.Second}

func client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return defaultClient
}

// APIError is a Google API error response.
type APIError struct {
	API     string
	Status  int
	Code    string // google.rpc.Code name, for example NOT_FOUND
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: HTTP %d %s: %s", e.API, e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("%s: HTTP %d", e.API, e.Status)
}

// retryable reports whether a call may succeed if repeated.
func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// call sends one JSON request with a bearer token and decodes the JSON answer into out. It retries transport errors,
// 429 and 5xx up to three times.
func call(ctx context.Context, c *http.Client, tokens TokenSource, api, method, url string, in, out any) error {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return err
		}
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(last, ctx.Err())
			case <-time.After(time.Duration(attempt) * 300 * time.Millisecond):
			}
		}
		tok, err := tokens.Token(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", api, err)
		}
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client(c).Do(req)
		if err != nil {
			last = fmt.Errorf("%s: %w", api, redactErr(err, tok))
			continue
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if rerr != nil {
			last = fmt.Errorf("%s: read response: %w", api, rerr)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			apiErr := &APIError{API: api, Status: resp.StatusCode}
			var e struct {
				Error struct {
					Status  string `json:"status"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(raw, &e) == nil {
				apiErr.Code, apiErr.Message = e.Error.Status, truncate(e.Error.Message, 300)
			}
			if retryable(resp.StatusCode) {
				last = apiErr
				continue
			}
			return apiErr
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s: malformed response", api)
		}
		return nil
	}
	return last
}

func redactErr(err error, tok string) error {
	if tok == "" || !strings.Contains(err.Error(), tok) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), tok, "<token>"))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// crc32c returns the CRC32C checksum Google APIs use for payload integrity.
func crc32c(b []byte) uint32 { return crc32.Checksum(b, castagnoli) }

// MetadataRegion returns the region of this Cloud Run instance from the metadata server
// (instance/region answers projects/<number>/regions/<region>). host empty means $GCE_METADATA_HOST or
// metadata.google.internal.
func MetadataRegion(ctx context.Context, host string, c *http.Client) (string, error) {
	if host == "" {
		host = os.Getenv("GCE_METADATA_HOST")
	}
	if host == "" {
		host = "metadata.google.internal"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/computeMetadata/v1/instance/region", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client(c).Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata region: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata region: HTTP %d", resp.StatusCode)
	}
	v := strings.TrimSpace(string(body))
	i := strings.LastIndex(v, "/regions/")
	if i < 0 || !regionRe.MatchString(v[i+len("/regions/"):]) {
		return "", errors.New("metadata region: malformed answer")
	}
	return v[i+len("/regions/"):], nil
}

var regionRe = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+$`)
