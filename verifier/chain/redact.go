package chain

import (
	"context"
	"math/big"
	"net/url"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum"
)

// RedactURL returns only the scheme and host of an RPC URL. Provider API keys live in the userinfo, the path or the
// query, so those never reach reports, HTTP responses or logs.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<rpc>"
	}
	return u.Scheme + "://" + u.Host
}

// redactor rewrites error messages so they carry no part of the RPC URL beyond its scheme and host.
type redactor struct {
	urls    []string // full URL spellings, replaced by the redacted URL
	secrets []string // fragments replaced by <redacted>, longest first
	short   string
}

func newRedactor(raw string) *redactor {
	r := &redactor{short: RedactURL(raw), urls: []string{raw}}
	u, err := url.Parse(raw)
	if err != nil {
		r.secrets = []string{raw}
		return r
	}
	r.urls = append(r.urls, u.String(), u.Redacted())
	add := func(s string) {
		if len(s) > 1 && s != "/" {
			r.secrets = append(r.secrets, s)
		}
	}
	if u.User != nil {
		add(u.User.String())
		add(u.User.Username())
		if p, ok := u.User.Password(); ok {
			add(p)
		}
	}
	add(u.Path)
	add(u.EscapedPath())
	add(u.RawQuery)
	add(u.Fragment)
	// Longest first, so a fragment that contains another is replaced whole.
	slices.SortFunc(r.urls, func(a, b string) int { return len(b) - len(a) })
	slices.SortFunc(r.secrets, func(a, b string) int { return len(b) - len(a) })
	return r
}

func (r *redactor) redact(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	out := msg
	for _, u := range r.urls {
		if u != "" && u != r.short {
			out = strings.ReplaceAll(out, u, r.short)
		}
	}
	for _, s := range r.secrets {
		out = strings.ReplaceAll(out, s, "<redacted>")
	}
	if out == msg {
		return err
	}
	return &redactedError{msg: out, err: err}
}

// redactedError keeps the original error for errors.Is and errors.As (revert data decoding) but never prints it.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// redactingBackend redacts the RPC URL from every error of inner.
type redactingBackend struct {
	inner Backend
	r     *redactor
}

func (b redactingBackend) CallContract(ctx context.Context, call ethereum.CallMsg, block *big.Int) ([]byte, error) {
	out, err := b.inner.CallContract(ctx, call, block)
	return out, b.r.redact(err)
}

func (b redactingBackend) ChainID(ctx context.Context) (*big.Int, error) {
	id, err := b.inner.ChainID(ctx)
	return id, b.r.redact(err)
}

func (b redactingBackend) BlockNumber(ctx context.Context) (uint64, error) {
	n, err := b.inner.BlockNumber(ctx)
	return n, b.r.redact(err)
}
