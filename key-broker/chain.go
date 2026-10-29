package keybroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// Registry is the onchain state one release decision reads. Every read of a decision comes from one block.
type Registry interface {
	GetImage(ctx context.Context, imageID [32]byte) (*chain.Image, error)
	IsApprovedImage(ctx context.Context, imageID [32]byte) (bool, error)
	GetRelease(ctx context.Context, releaseID [32]byte) (*chain.Release, error)
	IsStackApproved(ctx context.Context, customer common.Address, stackHash [32]byte) (bool, error)
	GetStackApproval(ctx context.Context, customer common.Address, stackHash [32]byte) (*chain.StackApproval, error)
}

// Head is the block every read of one decision is pinned to.
type Head struct {
	Number uint64
	// Time is the block timestamp. The broker refuses a head older than Config.MaxHeadAge (D-060), so a lagging or
	// stuck RPC cannot keep answering from before a revocation.
	Time time.Time
}

// Chain is the Tempo RPC the broker reads (eth_chainId, eth_getBlockByNumber and eth_call only). DialChain and
// NewClientChain adapt the verifier's read-only registry client.
type Chain interface {
	ChainID(ctx context.Context) (uint64, error)
	// Pin returns a Registry whose reads all run against the current head block, and that block's number and time.
	Pin(ctx context.Context) (Registry, Head, error)
}

// HeadReader reads the latest block's number and timestamp.
type HeadReader interface {
	Head(ctx context.Context) (Head, error)
}

type clientChain struct {
	c     *chain.Client
	heads HeadReader
}

// NewClientChain adapts the verifier's registry client; heads reads the latest block (RPCHeads).
func NewClientChain(c *chain.Client, heads HeadReader) Chain { return clientChain{c: c, heads: heads} }

// DialChain connects the registry reader and the head reader to one Tempo RPC URL.
func DialChain(ctx context.Context, rpcURL string, addrs chain.Addresses) (Chain, *chain.Client, error) {
	c, err := chain.Dial(ctx, rpcURL, addrs)
	if err != nil {
		return nil, nil, err
	}
	heads, err := DialRPCHeads(ctx, rpcURL)
	if err != nil {
		return nil, nil, err
	}
	return NewClientChain(c, heads), c, nil
}

func (cc clientChain) ChainID(ctx context.Context) (uint64, error) { return cc.c.ChainID(ctx) }

func (cc clientChain) Pin(ctx context.Context) (Registry, Head, error) {
	h, err := cc.heads.Head(ctx)
	if err != nil {
		return nil, Head{}, err
	}
	return cc.c.AtBlock(h.Number), h, nil
}

// RPCHeads reads the head with a raw eth_getBlockByNumber("latest", false) that decodes only number and timestamp,
// so Tempo's own transaction types (0x76, D-025) in the block never need decoding.
type RPCHeads struct {
	c   *rpc.Client
	red *urlRedactor
}

// DialRPCHeads dials rpcURL. Errors never contain the URL's userinfo, path or query (where provider keys live).
func DialRPCHeads(ctx context.Context, rpcURL string) (*RPCHeads, error) {
	red := newURLRedactor(rpcURL)
	c, err := rpc.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", chain.RedactURL(rpcURL), red.redact(err))
	}
	return &RPCHeads{c: c, red: red}, nil
}

// Head implements HeadReader.
func (h *RPCHeads) Head(ctx context.Context) (Head, error) {
	var raw json.RawMessage
	if err := h.c.CallContext(ctx, &raw, "eth_getBlockByNumber", "latest", false); err != nil {
		return Head{}, fmt.Errorf("eth_getBlockByNumber: %w", h.red.redact(err))
	}
	return parseHead(raw)
}

func parseHead(raw json.RawMessage) (Head, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return Head{}, errors.New("eth_getBlockByNumber: the RPC has no latest block")
	}
	var b struct {
		Number    *hexutil.Uint64 `json:"number"`
		Timestamp *hexutil.Uint64 `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &b); err != nil || b.Number == nil || b.Timestamp == nil {
		return Head{}, errors.New("eth_getBlockByNumber: malformed block header")
	}
	if uint64(*b.Timestamp) > 1<<40 {
		return Head{}, errors.New("eth_getBlockByNumber: block timestamp out of range")
	}
	return Head{Number: uint64(*b.Number), Time: time.Unix(int64(*b.Timestamp), 0).UTC()}, nil
}

// urlRedactor removes everything of an RPC URL but its scheme and host from error messages.
type urlRedactor struct {
	short   string
	secrets []string
}

func newURLRedactor(raw string) *urlRedactor {
	r := &urlRedactor{short: chain.RedactURL(raw)}
	add := func(s string) {
		if len(s) > 1 && s != "/" && s != r.short {
			r.secrets = append(r.secrets, s)
		}
	}
	add(raw)
	if u, err := url.Parse(raw); err == nil {
		add(u.String())
		add(u.Redacted())
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
	}
	slices.SortFunc(r.secrets, func(a, b string) int { return len(b) - len(a) })
	return r
}

// redactedErr keeps the original error for errors.Is and errors.As but never prints it.
type redactedErr struct {
	msg string
	err error
}

func (e *redactedErr) Error() string { return e.msg }
func (e *redactedErr) Unwrap() error { return e.err }

func (r *urlRedactor) redact(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	out := msg
	for _, s := range r.secrets {
		repl := "<redacted>"
		if strings.Contains(s, "://") {
			repl = r.short // a whole URL spelling
		}
		out = strings.ReplaceAll(out, s, repl)
	}
	if out == msg {
		return err
	}
	return &redactedErr{msg: out, err: err}
}

// QuoteVerifier verifies TDX quotes with Intel collateral and the TCB policy. *attest.Verifier implements it.
type QuoteVerifier interface {
	VerifyQuote(ctx context.Context, raw []byte) (*attest.QuoteResult, error)
}
