package keybroker

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// Registry is the onchain state one release decision reads. Every read of a decision comes from one block.
type Registry interface {
	GetImage(ctx context.Context, imageID [32]byte) (*chain.Image, error)
	IsApprovedImage(ctx context.Context, imageID [32]byte) (bool, error)
	GetRelease(ctx context.Context, releaseID [32]byte) (*chain.Release, error)
	IsStackApproved(ctx context.Context, customer common.Address, stackHash [32]byte) (bool, error)
	GetStackApproval(ctx context.Context, customer common.Address, stackHash [32]byte) (*chain.StackApproval, error)
}

// Chain is the Tempo RPC the broker reads (eth_call only). *chain.Client is adapted by NewClientChain.
type Chain interface {
	ChainID(ctx context.Context) (uint64, error)
	// Pin returns a Registry whose reads all run against the current head block, and that block's number.
	Pin(ctx context.Context) (Registry, uint64, error)
}

type clientChain struct{ c *chain.Client }

// NewClientChain adapts the verifier's read-only registry client.
func NewClientChain(c *chain.Client) Chain { return clientChain{c: c} }

func (cc clientChain) ChainID(ctx context.Context) (uint64, error) { return cc.c.ChainID(ctx) }

func (cc clientChain) Pin(ctx context.Context) (Registry, uint64, error) {
	n, err := cc.c.BlockNumber(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("eth_blockNumber: %w", err)
	}
	return cc.c.AtBlock(n), n, nil
}

// QuoteVerifier verifies TDX quotes with Intel collateral and the TCB policy. *attest.Verifier implements it.
type QuoteVerifier interface {
	VerifyQuote(ctx context.Context, raw []byte) (*attest.QuoteResult, error)
}
