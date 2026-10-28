package keybroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/verifier/chain"
)

// Config is what the customer sets at bootstrap (spec 5.7, 8.4). The platform never sets any of it.
type Config struct {
	// Customer is the customer's Tempo address. Only stacks whose config.customer is this address and that this
	// address approved onchain get secrets.
	Customer common.Address
	// ChainID is the Tempo chain the RPC must serve (4217 on mainnet).
	ChainID uint64
	// Contracts are the registries the broker reads; config.contracts must name the same ones.
	Contracts chain.Addresses
	// AllowSimulated accepts dev simulator quotes. Only a dev build (tag sealeddev) with SEALED_DEV_SIM=1 sets it;
	// the production image cannot (key-broker/cmd/key-broker).
	AllowSimulated bool
	// ReleaseTimeout bounds one release; 0 means 90 s (the agent waits 120 s).
	ReleaseTimeout time.Duration
	// LogTimeout bounds writing one decision; 0 means 15 s.
	LogTimeout time.Duration
}

// Deps are the broker's backends. Every one is an interface with a local fake.
type Deps struct {
	Nonces  *NonceStore
	Quotes  QuoteVerifier
	Chain   Chain
	Bundles BundleSource
	Secrets SecretStore
	MAC     MACSigner
	Log     DecisionLog
	// OpLog receives operational messages (never secrets); nil discards them.
	OpLog *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Broker runs the release pipeline. It is safe for concurrent use.
type Broker struct {
	cfg  Config
	deps Deps

	chainMu sync.Mutex
	chainOK bool
}

// New validates the configuration and backends.
func New(cfg Config, deps Deps) (*Broker, error) {
	if cfg.Customer == (common.Address{}) {
		return nil, errors.New("keybroker: customer address is not set")
	}
	if cfg.ChainID == 0 {
		return nil, errors.New("keybroker: chain id is not set")
	}
	if err := cfg.Contracts.Validate(); err != nil {
		return nil, fmt.Errorf("keybroker: %w", err)
	}
	for name, v := range map[string]any{"Nonces": deps.Nonces, "Quotes": deps.Quotes, "Chain": deps.Chain, "Bundles": deps.Bundles,
		"Secrets": deps.Secrets, "MAC": deps.MAC, "Log": deps.Log} {
		if isNil(v) {
			return nil, fmt.Errorf("keybroker: Deps.%s is nil", name)
		}
	}
	if cfg.ReleaseTimeout <= 0 {
		cfg.ReleaseTimeout = 90 * time.Second
	}
	if cfg.LogTimeout <= 0 {
		cfg.LogTimeout = 15 * time.Second
	}
	if deps.OpLog == nil {
		deps.OpLog = slog.New(slog.DiscardHandler)
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Broker{cfg: cfg, deps: deps}, nil
}

func isNil(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case *NonceStore:
		return t == nil
	}
	return false
}

// Config returns the broker's configuration.
func (b *Broker) Config() Config { return b.cfg }

// IssueNonce hands out a single-use nonce (GET /v1/nonce).
func (b *Broker) IssueNonce() (NonceResponse, error) {
	n, exp, err := b.deps.Nonces.Issue()
	if err != nil {
		return NonceResponse{}, err
	}
	return NonceResponse{Nonce: hex0x(n[:]), ExpiresAt: exp.Unix()}, nil
}

// CheckChain confirms the RPC serves the configured chain. The answer is cached once it succeeds.
func (b *Broker) CheckChain(ctx context.Context) error {
	b.chainMu.Lock()
	defer b.chainMu.Unlock()
	if b.chainOK {
		return nil
	}
	id, err := b.deps.Chain.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("eth_chainId: %w", err)
	}
	if id != b.cfg.ChainID {
		return fmt.Errorf("the Tempo RPC serves chain %d, this key broker is configured for chain %d", id, b.cfg.ChainID)
	}
	b.chainOK = true
	return nil
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
