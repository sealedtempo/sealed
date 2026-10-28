// Package token encodes and decodes connection tokens: "sct_" + base64url(JSON) (D-032). A token names the
// customer's project, region, deployer service account, key broker URL and wallet address. It holds no secret:
// it only tells the platform which deployer account to impersonate and which key broker the config must name.
package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Prefix starts every connection token.
const Prefix = "sct_"

// Version is the token format version.
const Version = 1

// MaxLen bounds a token so a pasted blob cannot be arbitrarily large.
const MaxLen = 4096

// Connection is the token payload. JSON names match the platform API contract (connection check).
type Connection struct {
	V               int    `json:"v"`
	Project         string `json:"project"`
	Region          string `json:"region"`
	DeployerAccount string `json:"deployerAccount"`
	KeyBrokerURL    string `json:"keyBrokerUrl"`
	Customer        string `json:"customer"`
	// Subnetwork and IssuedAt are informational.
	Subnetwork string `json:"subnetwork,omitempty"`
	IssuedAt   int64  `json:"issuedAt,omitempty"`
}

var (
	projectRe = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	regionRe  = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+$`)
	saRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	addrRe    = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	subnetRe  = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

// Validate checks every field.
func (c *Connection) Validate() error {
	var errs []string
	if c.V != Version {
		errs = append(errs, fmt.Sprintf("version %d, want %d", c.V, Version))
	}
	if !projectRe.MatchString(c.Project) {
		errs = append(errs, fmt.Sprintf("project %q is not a project id", c.Project))
	}
	if !regionRe.MatchString(c.Region) {
		errs = append(errs, fmt.Sprintf("region %q is not a region", c.Region))
	}
	if !saRe.MatchString(c.DeployerAccount) {
		errs = append(errs, fmt.Sprintf("deployerAccount %q is not a service account email", c.DeployerAccount))
	} else if !strings.HasSuffix(c.DeployerAccount, "@"+c.Project+".iam.gserviceaccount.com") {
		errs = append(errs, "deployerAccount must belong to the token's project")
	}
	if err := checkHTTPS(c.KeyBrokerURL); err != nil {
		errs = append(errs, "keyBrokerUrl: "+err.Error())
	}
	if !addrRe.MatchString(c.Customer) {
		errs = append(errs, fmt.Sprintf("customer %q is not a lowercase 0x address", c.Customer))
	}
	if c.Subnetwork != "" && !subnetRe.MatchString(c.Subnetwork) {
		errs = append(errs, fmt.Sprintf("subnetwork %q is not a resource name", c.Subnetwork))
	}
	if c.IssuedAt < 0 {
		errs = append(errs, "issuedAt is negative")
	}
	if len(errs) > 0 {
		return errors.New("connection token: " + strings.Join(errs, "; "))
	}
	return nil
}

func checkHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("%q must be an https origin without credentials, path or query", raw)
	}
	return nil
}

// Encode validates c and returns its token. Field order is fixed by the struct, so equal connections give equal
// tokens.
func Encode(c Connection) (string, error) {
	c.Customer = strings.ToLower(c.Customer)
	c.KeyBrokerURL = strings.TrimRight(c.KeyBrokerURL, "/")
	if err := c.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Decode parses and validates a token. Surrounding whitespace is ignored; padding is accepted.
func Decode(tok string) (*Connection, error) {
	tok = strings.TrimSpace(tok)
	if len(tok) > MaxLen {
		return nil, errors.New("connection token is too long")
	}
	body, ok := strings.CutPrefix(tok, Prefix)
	if !ok {
		return nil, errors.New("not a connection token: tokens start with sct_ and come from sealed bootstrap (or sealed connect gcp)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body, "="))
	if err != nil {
		return nil, fmt.Errorf("connection token is not base64url: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Connection
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("connection token is not valid JSON: %w", err)
	}
	if dec.More() {
		return nil, errors.New("connection token has trailing data")
	}
	c.KeyBrokerURL = strings.TrimRight(c.KeyBrokerURL, "/")
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
