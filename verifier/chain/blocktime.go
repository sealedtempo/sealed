package chain

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// BlockTimer is a Backend that can also read a block's timestamp. The backend of Dial implements it. Verifiers use
// it to refuse a stale or lagging RPC, which could otherwise hide a revocation (D-060).
type BlockTimer interface {
	BlockTime(ctx context.Context, n uint64) (uint64, error)
}

// ErrNoBlockTime is returned by Client.BlockTime when the backend cannot read block timestamps.
var ErrNoBlockTime = errors.New("chain backend cannot read block timestamps")

// BlockTime returns the timestamp (unix seconds) of block n.
func (c *Client) BlockTime(ctx context.Context, n uint64) (uint64, error) {
	bt, ok := c.backend.(BlockTimer)
	if !ok {
		return 0, ErrNoBlockTime
	}
	return bt.BlockTime(ctx, n)
}

// rpcBackend is the ethclient backend plus block timestamps read with eth_getBlockByNumber(n, false). Only the
// number and timestamp fields are decoded: go-ethereum cannot decode Tempo's 0x76 transactions or every Tempo
// header field (D-025), and the verifier needs nothing else.
type rpcBackend struct {
	*ethclient.Client
	rpc *rpc.Client
}

func newRPCBackend(ec *ethclient.Client) rpcBackend { return rpcBackend{Client: ec, rpc: ec.Client()} }

// RPCBackend returns ec as a Backend that is also a BlockTimer. Callers that wrap the backend (for example to redact
// errors) use it so the wrapped backend can still read block timestamps (D-060).
func RPCBackend(ec *ethclient.Client) Backend { return newRPCBackend(ec) }

// BlockTime implements BlockTimer.
func (b rpcBackend) BlockTime(ctx context.Context, n uint64) (uint64, error) {
	return blockTime(ctx, b.rpc, n)
}

type rpcCaller interface {
	CallContext(ctx context.Context, result any, method string, args ...any) error
}

func blockTime(ctx context.Context, c rpcCaller, n uint64) (uint64, error) {
	var head *struct {
		Number    *hexutil.Uint64 `json:"number"`
		Timestamp *hexutil.Uint64 `json:"timestamp"`
	}
	if err := c.CallContext(ctx, &head, "eth_getBlockByNumber", hexutil.EncodeUint64(n), false); err != nil {
		return 0, fmt.Errorf("eth_getBlockByNumber(%d): %w", n, err)
	}
	switch {
	case head == nil:
		return 0, fmt.Errorf("eth_getBlockByNumber(%d): block not found", n)
	case head.Number == nil || head.Timestamp == nil:
		return 0, fmt.Errorf("eth_getBlockByNumber(%d): number or timestamp missing", n)
	case uint64(*head.Number) != n:
		return 0, fmt.Errorf("eth_getBlockByNumber(%d) answered block %d", n, uint64(*head.Number))
	}
	return uint64(*head.Timestamp), nil
}

// BlockTime implements BlockTimer when the wrapped backend does.
func (b redactingBackend) BlockTime(ctx context.Context, n uint64) (uint64, error) {
	bt, ok := b.inner.(BlockTimer)
	if !ok {
		return 0, ErrNoBlockTime
	}
	ts, err := bt.BlockTime(ctx, n)
	return ts, b.r.redact(err)
}
