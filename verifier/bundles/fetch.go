package bundles

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultMaxBundleBytes bounds one downloaded bundle. Bundles hold manifests, licenses, SBOMs and scan reports;
// the largest catalog bundle is a few MiB.
const DefaultMaxBundleBytes = 64 << 20

// DefaultFetchTimeout bounds one bundle download (redirects included).
const DefaultFetchTimeout = 60 * time.Second

// Fetcher downloads one URL.
type Fetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// ErrNotFound is returned when the release asset does not exist (HTTP 404 or 410).
var ErrNotFound = errors.New("release asset not found")

// HTTPError is a non-200 answer.
type HTTPError struct {
	URL    string
	Status int
}

func (e *HTTPError) Error() string {
	if errors.Is(e, ErrNotFound) {
		return fmt.Sprintf("GET %s: HTTP %d (%v)", e.URL, e.Status, ErrNotFound)
	}
	return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status)
}

// Unwrap maps 404 and 410 to ErrNotFound.
func (e *HTTPError) Unwrap() error {
	if e.Status == http.StatusNotFound || e.Status == http.StatusGone {
		return ErrNotFound
	}
	return nil
}

// HTTPFetcher fetches over HTTP(S). GitHub release asset URLs redirect to GitHub's asset host, so redirects are
// followed (see CheckRedirect). Requests honor HTTPS_PROXY (sealed-egress inside the CVM).
type HTTPFetcher struct {
	// Client is the HTTP client; nil uses one with DefaultFetchTimeout, the environment's proxy and CheckRedirect.
	Client *http.Client
	// MaxBytes bounds the body; 0 means DefaultMaxBundleBytes.
	MaxBytes int64
	// UserAgent is sent when set.
	UserAgent string
}

var defaultClient = &http.Client{Timeout: DefaultFetchTimeout, CheckRedirect: CheckRedirect}

// CheckRedirect follows at most 10 redirects and never leaves https once a fetch started on https: bundle bytes
// are hash-checked, but a downgrade would still send the request (and its proxy CONNECT) in clear text.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect from https to %s://%s refused", req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// Fetch implements Fetcher.
func (f HTTPFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	client := f.Client
	if client == nil {
		client = defaultClient
	}
	limit := f.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxBundleBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	if f.UserAgent != "" {
		req.Header.Set("User-Agent", f.UserAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, &HTTPError{URL: url, Status: resp.StatusCode}
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("GET %s: %d bytes, limit %d", url, resp.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: more than %d bytes", url, limit)
	}
	return body, nil
}
