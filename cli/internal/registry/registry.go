// Package registry reads the Sealed registries on Tempo for the CLI: everything the verifier library reads
// (verify.ChainReader, through verifier/chain) plus the AppRegistry enumeration that `sealed catalog` and `sealed
// deploy` need (appCount/appAt, releaseCount/releaseAt, latestRelease, releaseByVersion, isApprovableRelease). It
// only issues eth_call, eth_chainId and eth_blockNumber and holds no keys (D-025).
package registry

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/sealedtempo/sealed/cli/internal/embedded"
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// Reader is the onchain state the CLI reads.
type Reader interface {
	verify.ChainReader
	GetApp(ctx context.Context, appID [32]byte) (*chain.App, error)
	AppCount(ctx context.Context) (uint64, error)
	AppAt(ctx context.Context, index uint64) ([32]byte, error)
	ReleaseCount(ctx context.Context, appID [32]byte) (uint64, error)
	ReleaseAt(ctx context.Context, appID [32]byte, index uint64) ([32]byte, error)
	LatestRelease(ctx context.Context, appID [32]byte) ([32]byte, error)
	ReleaseByVersion(ctx context.Context, appID [32]byte, version string) ([32]byte, error)
	IsApprovableRelease(ctx context.Context, releaseID [32]byte) (bool, error)
}

// Client implements Reader over a JSON-RPC backend.
type Client struct {
	*chain.Client
	backend chain.Backend
	addrs   chain.Addresses
	app     abi.ABI
	rawURL  string
}

var (
	abiOnce sync.Once
	appABI  abi.ABI
	abiErr  error
)

func loadABI() (abi.ABI, error) {
	abiOnce.Do(func() {
		raw, err := embedded.ABI("AppRegistry")
		if err != nil {
			abiErr = err
			return
		}
		appABI, abiErr = abi.JSON(strings.NewReader(string(raw)))
	})
	return appABI, abiErr
}

// New wraps backend.
func New(backend chain.Backend, addrs chain.Addresses) (*Client, error) {
	inner, err := chain.New(backend, addrs)
	if err != nil {
		return nil, err
	}
	a, err := loadABI()
	if err != nil {
		return nil, err
	}
	return &Client{Client: inner, backend: backend, addrs: addrs, app: a}, nil
}

// Dial connects to a Tempo RPC. Errors never carry the URL's path, query or credentials.
func Dial(ctx context.Context, rpcURL string, addrs chain.Addresses) (*Client, error) {
	ec, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %s", chain.RedactURL(rpcURL), redact(err.Error(), rpcURL))
	}
	c, err := New(redacting{chain.RPCBackend(ec), rpcURL}, addrs)
	if err != nil {
		return nil, err
	}
	c.rawURL = rpcURL
	return c, nil
}

func redact(msg, rawURL string) string {
	if rawURL == "" {
		return msg
	}
	return strings.ReplaceAll(msg, rawURL, chain.RedactURL(rawURL))
}

// redacting strips the RPC URL from backend errors.
type redacting struct {
	inner chain.Backend
	url   string
}

func (r redacting) wrap(err error) error {
	if err == nil {
		return nil
	}
	msg := redact(err.Error(), r.url)
	if msg == err.Error() {
		return err
	}
	return &redactedError{msg: msg, inner: err}
}

type redactedError struct {
	msg   string
	inner error
}

func (e *redactedError) Error() string { return e.msg }

// ErrorData keeps revert data reachable for decoding (rpc.DataError).
func (e *redactedError) ErrorData() any {
	var de interface{ ErrorData() any }
	if errors.As(e.inner, &de) {
		return de.ErrorData()
	}
	return nil
}

func (r redacting) CallContract(ctx context.Context, call ethereum.CallMsg, block *big.Int) ([]byte, error) {
	b, err := r.inner.CallContract(ctx, call, block)
	return b, r.wrap(err)
}

func (r redacting) ChainID(ctx context.Context) (*big.Int, error) {
	id, err := r.inner.ChainID(ctx)
	return id, r.wrap(err)
}

func (r redacting) BlockNumber(ctx context.Context) (uint64, error) {
	n, err := r.inner.BlockNumber(ctx)
	return n, r.wrap(err)
}

// BlockTime implements chain.BlockTimer, so verifications can check the head block's age (D-060).
func (r redacting) BlockTime(ctx context.Context, n uint64) (uint64, error) {
	bt, ok := r.inner.(chain.BlockTimer)
	if !ok {
		return 0, chain.ErrNoBlockTime
	}
	ts, err := bt.BlockTime(ctx, n)
	return ts, r.wrap(err)
}

// Chain returns the verifier's client (it pins every read of a verification to one block).
func (c *Client) Chain() *chain.Client { return c.Client }

func (c *Client) call(ctx context.Context, method string, args ...any) ([]any, error) {
	data, err := c.app.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	to := c.addrs.AppRegistry
	out, err := c.backend.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("AppRegistry.%s: %w", method, err)
	}
	vals, err := c.app.Unpack(method, out)
	if err != nil {
		return nil, fmt.Errorf("AppRegistry.%s: decode: %w", method, err)
	}
	return vals, nil
}

func asUint(v any) (uint64, error) {
	b, ok := v.(*big.Int)
	if !ok || !b.IsUint64() {
		return 0, fmt.Errorf("unexpected value %v", v)
	}
	return b.Uint64(), nil
}

// AppCount is AppRegistry.appCount.
func (c *Client) AppCount(ctx context.Context) (uint64, error) {
	v, err := c.call(ctx, "appCount")
	if err != nil {
		return 0, err
	}
	return asUint(v[0])
}

// AppAt is AppRegistry.appAt.
func (c *Client) AppAt(ctx context.Context, i uint64) ([32]byte, error) {
	v, err := c.call(ctx, "appAt", new(big.Int).SetUint64(i))
	if err != nil {
		return [32]byte{}, err
	}
	return v[0].([32]byte), nil
}

// ReleaseCount is AppRegistry.releaseCount.
func (c *Client) ReleaseCount(ctx context.Context, appID [32]byte) (uint64, error) {
	v, err := c.call(ctx, "releaseCount", appID)
	if err != nil {
		return 0, err
	}
	return asUint(v[0])
}

// ReleaseAt is AppRegistry.releaseAt.
func (c *Client) ReleaseAt(ctx context.Context, appID [32]byte, i uint64) ([32]byte, error) {
	v, err := c.call(ctx, "releaseAt", appID, new(big.Int).SetUint64(i))
	if err != nil {
		return [32]byte{}, err
	}
	return v[0].([32]byte), nil
}

// LatestRelease is AppRegistry.latestRelease (zero when the app has no active release).
func (c *Client) LatestRelease(ctx context.Context, appID [32]byte) ([32]byte, error) {
	v, err := c.call(ctx, "latestRelease", appID)
	if err != nil {
		return [32]byte{}, err
	}
	return v[0].([32]byte), nil
}

// ReleaseByVersion is AppRegistry.releaseByVersion (zero when unknown).
func (c *Client) ReleaseByVersion(ctx context.Context, appID [32]byte, version string) ([32]byte, error) {
	v, err := c.call(ctx, "releaseByVersion", appID, version)
	if err != nil {
		return [32]byte{}, err
	}
	return v[0].([32]byte), nil
}

// IsApprovableRelease is AppRegistry.isApprovableRelease (Active only, D-013).
func (c *Client) IsApprovableRelease(ctx context.Context, id [32]byte) (bool, error) {
	v, err := c.call(ctx, "isApprovableRelease", id)
	if err != nil {
		return false, err
	}
	return v[0].(bool), nil
}

// ParseHash32 parses a 0x-prefixed 32-byte hex value.
func ParseHash32(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 66 || !strings.HasPrefix(s, "0x") {
		return out, fmt.Errorf("%q is not a 0x-prefixed 32-byte hex value", s)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return out, fmt.Errorf("%q is not hex", s)
	}
	copy(out[:], b)
	return out, nil
}
