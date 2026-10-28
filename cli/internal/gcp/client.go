package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Default API roots. Tests point them at an httptest server.
const (
	SecretManagerRoot = "https://secretmanager.googleapis.com/v1"
	ComputeRoot       = "https://compute.googleapis.com/compute/v1"
)

// Client sends authenticated JSON requests.
type Client struct {
	HTTP   *http.Client
	Tokens TokenSource
	// Retries of 429 and 5xx answers (idempotent GETs and creates that carry a requestId). Default 3.
	Retries int
	Sleep   func(time.Duration)
	// UserAgent identifies the CLI.
	UserAgent string
}

// APIError is a Google API error response.
type APIError struct {
	HTTPStatus int
	Code       int
	Status     string
	Message    string
	Method     string
	URL        string
}

func (e *APIError) Error() string {
	msg := e.Message
	if len(msg) > 400 {
		msg = msg[:400]
	}
	return fmt.Sprintf("%s %s: HTTP %d %s: %s", e.Method, e.URL, e.HTTPStatus, e.Status, msg)
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.HTTPStatus == http.StatusNotFound
}

// IsConflict reports a 409 (already exists).
func IsConflict(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.HTTPStatus == http.StatusConflict
}

// IsPermissionDenied reports a 403.
func IsPermissionDenied(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.HTTPStatus == http.StatusForbidden
}

const maxResponse = 16 << 20

// Do sends method url with body as JSON (nil for none) and decodes the response into out (nil to discard).
func (c *Client) Do(ctx context.Context, method, url string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	retries := c.Retries
	if retries == 0 {
		retries = 3
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}
		tok, err := c.Tokens.Token(ctx)
		if err != nil {
			return err
		}
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.UserAgent != "" {
			req.Header.Set("User-Agent", c.UserAgent)
		}
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%s %s: %w", method, url, err)
			if ctx.Err() != nil {
				return lastErr
			}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(bytes.TrimSpace(data)) > 0 {
				if err := json.Unmarshal(data, out); err != nil {
					return fmt.Errorf("%s %s: decode response: %w", method, url, err)
				}
			}
			return nil
		}
		apiErr := parseAPIError(resp.StatusCode, data)
		apiErr.Method, apiErr.URL = method, stripQuery(url)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = apiErr
			continue
		}
		return apiErr
	}
	return lastErr
}

func parseAPIError(status int, data []byte) *APIError {
	e := &APIError{HTTPStatus: status, Status: http.StatusText(status)}
	var body struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &body) == nil && body.Error.Message != "" {
		e.Code, e.Message = body.Error.Code, body.Error.Message
		if body.Error.Status != "" {
			e.Status = body.Error.Status
		}
		return e
	}
	e.Message = strings.TrimSpace(string(data))
	return e
}

func stripQuery(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}
