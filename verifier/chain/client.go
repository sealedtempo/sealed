// Package chain is a read-only client for the Sealed registries on Tempo (PlatformRegistry, AppRegistry,
// DeploymentRegistry). It only issues eth_call and eth_chainId: go-ethereum cannot decode Tempo 0x76
// transactions, so it never fetches blocks or transactions (D-025).
package chain

import (
	"bytes"
	"context"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

//go:generate sh -c "cp ../../contracts/abi/PlatformRegistry.json ../../contracts/abi/AppRegistry.json ../../contracts/abi/DeploymentRegistry.json abi/"

//go:embed abi/*.json
var abiFiles embed.FS

// ErrNotFound is returned when a view reverts with one of the registries' *NotFound errors.
var ErrNotFound = errors.New("not found onchain")

// Backend is the subset of an Ethereum RPC client the reader uses. *ethclient.Client implements it.
type Backend interface {
	CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	ChainID(ctx context.Context) (*big.Int, error)
}

// Client reads the registries. It holds no keys and cannot send transactions.
type Client struct {
	backend Backend
	addrs   Addresses
	abis    map[string]*abi.ABI
}

// RevertError is a decoded custom error from a reverted eth_call.
type RevertError struct {
	Contract string
	Name     string
	Args     []any
}

func (e *RevertError) Error() string {
	return fmt.Sprintf("%s reverted: %s%v", e.Contract, e.Name, e.Args)
}

// Unwrap lets errors.Is(err, ErrNotFound) match ImageNotFound, ReleaseNotFound, AppNotFound, DeploymentNotFound.
func (e *RevertError) Unwrap() error {
	if strings.HasSuffix(e.Name, "NotFound") {
		return ErrNotFound
	}
	return nil
}

// Dial connects to a Tempo JSON-RPC endpoint.
func Dial(ctx context.Context, rpcURL string, addrs Addresses) (*Client, error) {
	ec, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", rpcURL, err)
	}
	return New(ec, addrs)
}

// New returns a reader over backend for the given registry addresses.
func New(backend Backend, addrs Addresses) (*Client, error) {
	if err := addrs.Validate(); err != nil {
		return nil, err
	}
	abis, err := loadABIs()
	if err != nil {
		return nil, err
	}
	return &Client{backend: backend, addrs: addrs, abis: abis}, nil
}

func loadABIs() (map[string]*abi.ABI, error) {
	out := map[string]*abi.ABI{}
	for _, name := range []string{"PlatformRegistry", "AppRegistry", "DeploymentRegistry"} {
		raw, err := abiFiles.ReadFile("abi/" + name + ".json")
		if err != nil {
			return nil, err
		}
		a, err := abi.JSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("parse %s ABI: %w", name, err)
		}
		out[name] = &a
	}
	return out, nil
}

// Addresses returns the registry addresses this client reads.
func (c *Client) Addresses() Addresses { return c.addrs }

// ChainID returns eth_chainId.
func (c *Client) ChainID(ctx context.Context) (uint64, error) {
	id, err := c.backend.ChainID(ctx)
	if err != nil {
		return 0, err
	}
	if !id.IsUint64() {
		return 0, fmt.Errorf("chain id %s out of range", id)
	}
	return id.Uint64(), nil
}

func (c *Client) call(ctx context.Context, contract string, to common.Address, method string, args ...any) ([]any, error) {
	a := c.abis[contract]
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, fmt.Errorf("pack %s.%s: %w", contract, method, err)
	}
	out, err := c.backend.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
	if err != nil {
		if rev := decodeRevert(contract, a, err); rev != nil {
			return nil, rev
		}
		return nil, fmt.Errorf("%s.%s: %w", contract, method, err)
	}
	vals, err := a.Unpack(method, out)
	if err != nil {
		return nil, fmt.Errorf("unpack %s.%s: %w", contract, method, err)
	}
	return vals, nil
}

func decodeRevert(contract string, a *abi.ABI, err error) *RevertError {
	var de rpc.DataError
	if !errors.As(err, &de) {
		return nil
	}
	s, ok := de.ErrorData().(string)
	if !ok {
		return nil
	}
	data, decErr := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if decErr != nil || len(data) < 4 {
		return nil
	}
	for name, e := range a.Errors {
		if bytes.Equal(e.ID[:4], data[:4]) {
			args, _ := e.Inputs.Unpack(data[4:])
			return &RevertError{Contract: contract, Name: name, Args: args}
		}
	}
	return nil
}

// convert copies an ABI-decoded tuple into dst, a pointer to a struct with the same field names and types.
func convert[T any](v any) (out T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode %T: %v", out, r)
		}
	}()
	return *abi.ConvertType(v, new(T)).(*T), nil
}

func one[T any](vals []any, err error) (T, error) {
	var zero T
	if err != nil {
		return zero, err
	}
	if len(vals) != 1 {
		return zero, fmt.Errorf("want 1 return value, got %d", len(vals))
	}
	return convert[T](vals[0])
}

// GetImage returns PlatformRegistry.getImage. Unknown ids return an error wrapping ErrNotFound.
func (c *Client) GetImage(ctx context.Context, imageID [32]byte) (*Image, error) {
	img, err := one[Image](c.call(ctx, "PlatformRegistry", c.addrs.PlatformRegistry, "getImage", imageID))
	if err != nil {
		return nil, err
	}
	return &img, nil
}

// IsApprovedImage returns PlatformRegistry.isApprovedImage (Active and not debug).
func (c *Client) IsApprovedImage(ctx context.Context, imageID [32]byte) (bool, error) {
	return one[bool](c.call(ctx, "PlatformRegistry", c.addrs.PlatformRegistry, "isApprovedImage", imageID))
}

// GetApp returns AppRegistry.getApp.
func (c *Client) GetApp(ctx context.Context, appID [32]byte) (*App, error) {
	app, err := one[App](c.call(ctx, "AppRegistry", c.addrs.AppRegistry, "getApp", appID))
	if err != nil {
		return nil, err
	}
	return &app, nil
}

// GetRelease returns AppRegistry.getRelease.
func (c *Client) GetRelease(ctx context.Context, releaseID [32]byte) (*Release, error) {
	r, err := one[Release](c.call(ctx, "AppRegistry", c.addrs.AppRegistry, "getRelease", releaseID))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// IsActiveRelease returns AppRegistry.isActiveRelease (Active or Deprecated, D-013).
func (c *Client) IsActiveRelease(ctx context.Context, releaseID [32]byte) (bool, error) {
	return one[bool](c.call(ctx, "AppRegistry", c.addrs.AppRegistry, "isActiveRelease", releaseID))
}

// IsStackApproved returns DeploymentRegistry.isStackApproved.
func (c *Client) IsStackApproved(ctx context.Context, customer common.Address, stackHash [32]byte) (bool, error) {
	return one[bool](c.call(ctx, "DeploymentRegistry", c.addrs.DeploymentRegistry, "isStackApproved", customer, stackHash))
}

// GetStackApproval returns DeploymentRegistry.getStackApproval. A missing approval has ApprovedAt == 0.
func (c *Client) GetStackApproval(ctx context.Context, customer common.Address, stackHash [32]byte) (*StackApproval, error) {
	vals, err := c.call(ctx, "DeploymentRegistry", c.addrs.DeploymentRegistry, "getStackApproval", customer, stackHash)
	if err != nil {
		return nil, err
	}
	if len(vals) != 5 {
		return nil, fmt.Errorf("getStackApproval: want 5 values, got %d", len(vals))
	}
	ids, ok1 := vals[0].([][32]byte)
	img, ok2 := vals[1].([32]byte)
	exp, ok3 := vals[2].(uint64)
	rev, ok4 := vals[3].(bool)
	at, ok5 := vals[4].(uint64)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return nil, fmt.Errorf("getStackApproval: unexpected return types %T %T %T %T %T", vals[0], vals[1], vals[2], vals[3], vals[4])
	}
	return &StackApproval{ReleaseIDs: ids, ImageID: img, Expiry: exp, Revoked: rev, ApprovedAt: at}, nil
}

// GetDeployment returns DeploymentRegistry.getDeployment. Unknown ids return an error wrapping ErrNotFound.
func (c *Client) GetDeployment(ctx context.Context, deploymentID [32]byte) (*Deployment, error) {
	d, err := one[Deployment](c.call(ctx, "DeploymentRegistry", c.addrs.DeploymentRegistry, "getDeployment", deploymentID))
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// RecordDigest returns DeploymentRegistry.recordDigest(r), the EIP-712 digest the oracle signs.
func (c *Client) RecordDigest(ctx context.Context, r Record) ([32]byte, error) {
	return one[[32]byte](c.call(ctx, "DeploymentRegistry", c.addrs.DeploymentRegistry, "recordDigest", r))
}
