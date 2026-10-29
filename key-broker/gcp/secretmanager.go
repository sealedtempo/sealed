package gcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	keybroker "github.com/sealedtempo/sealed/key-broker"
)

// DefaultSecretManagerEndpoint is the Secret Manager REST API.
const DefaultSecretManagerEndpoint = "https://secretmanager.googleapis.com"

var (
	projectRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	secretIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
)

// SecretManager reads the latest version of secrets in the customer's project. The broker's service account has
// roles/secretmanager.secretAccessor on secrets named sealed-* only (spec 5.7).
type SecretManager struct {
	Project  string
	Endpoint string // empty means DefaultSecretManagerEndpoint
	Tokens   TokenSource
	Client   *http.Client
}

// NewSecretManager validates the project id.
func NewSecretManager(project string, tokens TokenSource) (*SecretManager, error) {
	if !projectRe.MatchString(project) {
		return nil, fmt.Errorf("gcp: %q is not a project id", project)
	}
	if tokens == nil {
		return nil, errors.New("gcp: no token source")
	}
	return &SecretManager{Project: project, Tokens: tokens}, nil
}

// Access implements keybroker.SecretStore. A missing secret or a secret without an enabled version is
// keybroker.ErrSecretNotFound.
func (s *SecretManager) Access(ctx context.Context, id string) ([]byte, error) {
	if !secretIDRe.MatchString(id) {
		return nil, fmt.Errorf("secret id %q is invalid", id)
	}
	ep := s.Endpoint
	if ep == "" {
		ep = DefaultSecretManagerEndpoint
	}
	u := fmt.Sprintf("%s/v1/projects/%s/secrets/%s/versions/latest:access", ep, url.PathEscape(s.Project), url.PathEscape(id))
	var resp struct {
		Name    string `json:"name"`
		Payload struct {
			Data       string `json:"data"`
			DataCrc32c string `json:"dataCrc32c"`
		} `json:"payload"`
	}
	err := call(ctx, s.Client, s.Tokens, "secretmanager", http.MethodGet, u, nil, &resp)
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Code == "NOT_FOUND" ||
		// The secret exists but its latest version is disabled or destroyed.
		apiErr.Code == "FAILED_PRECONDITION") {
		return nil, fmt.Errorf("%s: %w", id, keybroker.ErrSecretNotFound)
	}
	if err != nil {
		return nil, err
	}
	val, err := base64.StdEncoding.DecodeString(resp.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("secretmanager: %s: payload is not base64", id)
	}
	if resp.Payload.DataCrc32c != "" {
		want, err := strconv.ParseUint(resp.Payload.DataCrc32c, 10, 32)
		if err != nil || uint32(want) != crc32c(val) {
			return nil, fmt.Errorf("secretmanager: %s: payload checksum mismatch", id)
		}
	}
	return val, nil
}
