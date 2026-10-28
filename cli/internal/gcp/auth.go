// Package gcp talks to the Google Cloud REST APIs the CLI needs (Secret Manager and Compute Engine) with the
// customer's own credentials. It uses net/http only: access tokens come from SEALED_GCP_ACCESS_TOKEN (or
// GOOGLE_OAUTH_ACCESS_TOKEN), from `gcloud auth print-access-token` (Cloud Shell included), or from an
// authorized_user application default credentials file. Tokens are never logged or put in errors.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TokenSource returns OAuth 2.0 access tokens.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed access token (SEALED_GCP_ACCESS_TOKEN, tests).
type StaticToken string

// Token returns the token.
func (s StaticToken) Token(context.Context) (string, error) {
	if s == "" {
		return "", errors.New("empty access token")
	}
	return string(s), nil
}

// Runner runs a command and returns its stdout. Tests replace it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner runs real commands.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return nil, fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return out, nil
}

// GcloudToken asks gcloud for an access token, optionally impersonating a service account. Tokens are cached for
// 45 minutes (gcloud issues one-hour tokens).
type GcloudToken struct {
	Impersonate string
	Run         Runner
	Now         func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Token returns a cached or fresh token.
func (g *GcloudToken) Token(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	if g.token != "" && now().Before(g.expires) {
		return g.token, nil
	}
	run := g.Run
	if run == nil {
		run = ExecRunner
	}
	args := []string{"auth", "print-access-token"}
	if g.Impersonate != "" {
		args = append(args, "--impersonate-service-account="+g.Impersonate)
	}
	out, err := run(ctx, "gcloud", args...)
	if err != nil {
		return "", fmt.Errorf("gcloud auth print-access-token: %w (run gcloud auth login, or set SEALED_GCP_ACCESS_TOKEN)", err)
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" || strings.ContainsAny(tok, " \n\t") {
		return "", errors.New("gcloud auth print-access-token returned no usable token")
	}
	g.token, g.expires = tok, now().Add(45*time.Minute)
	return tok, nil
}

// ADCToken refreshes an authorized_user application default credentials file (gcloud auth application-default
// login).
type ADCToken struct {
	File     string
	HTTP     *http.Client
	TokenURL string // default https://oauth2.googleapis.com/token
	Now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

type adcFile struct {
	Type         string `json:"type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

// Token returns a cached or refreshed token.
func (a *ADCToken) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if a.token != "" && now().Before(a.expires) {
		return a.token, nil
	}
	raw, err := os.ReadFile(a.File)
	if err != nil {
		return "", err
	}
	var f adcFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return "", fmt.Errorf("%s: not a credentials file", a.File)
	}
	if f.Type != "authorized_user" || f.RefreshToken == "" {
		return "", fmt.Errorf("%s: only authorized_user credentials are supported (type %q); use gcloud or SEALED_GCP_ACCESS_TOKEN", a.File, f.Type)
	}
	tokenURL := a.TokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.ClientID},
		"client_secret": {f.ClientSecret},
		"refresh_token": {f.RefreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := a.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("refresh application default credentials: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("refresh application default credentials: HTTP %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("refresh application default credentials: no access token in the response")
	}
	life := time.Duration(tr.ExpiresIn) * time.Second
	if life <= 0 || life > time.Hour {
		life = time.Hour
	}
	a.token, a.expires = tr.AccessToken, now().Add(life-5*time.Minute)
	return a.token, nil
}

// DefaultTokenSource picks, in order: SEALED_GCP_ACCESS_TOKEN or GOOGLE_OAUTH_ACCESS_TOKEN; gcloud when it is on
// PATH; GOOGLE_APPLICATION_CREDENTIALS or the well-known ADC file. With impersonate set, only gcloud can mint
// the impersonated token (and the static token is assumed to already be one).
func DefaultTokenSource(getenv func(string) string, lookPath func(string) (string, error), impersonate string) (TokenSource, error) {
	for _, k := range []string{"SEALED_GCP_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"} {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return StaticToken(v), nil
		}
	}
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if _, err := lookPath("gcloud"); err == nil {
		return &GcloudToken{Impersonate: impersonate}, nil
	}
	if impersonate != "" {
		return nil, errors.New("impersonation needs gcloud on PATH (or an impersonated token in SEALED_GCP_ACCESS_TOKEN)")
	}
	file := getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if file == "" {
		if home := getenv("HOME"); home != "" {
			file = filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		}
	}
	if file != "" {
		if _, err := os.Stat(file); err == nil {
			return &ADCToken{File: file}, nil
		}
	}
	return nil, errors.New("no Google Cloud credentials: install gcloud and run gcloud auth login, or set SEALED_GCP_ACCESS_TOKEN")
}
