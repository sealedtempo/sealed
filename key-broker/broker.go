package keybroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
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
	// FeeSplitter and FeeToken are the contracts the enclave signer and the access key pay; config.contracts.feeSplitter
	// and config.feeToken must name them.
	FeeSplitter common.Address
	FeeToken    common.Address
	// AllowedImages, when not empty, is the customer's own allowlist of imageIds on top of
	// PlatformRegistry.isApprovedImage, so the platform alone cannot make an image count as production.
	AllowedImages [][32]byte
	// MaxHeadAge bounds how far the pinned head block's timestamp may be from the broker's clock (D-060); 0 means
	// DefaultMaxHeadAge, at most MaxMaxHeadAge.
	MaxHeadAge time.Duration
	// AllowSimulated accepts dev simulator quotes. Only a dev build (tag sealeddev) with SEALED_DEV_SIM=1 sets it;
	// the production image cannot (key-broker/cmd/key-broker). It is refused on Tempo mainnet.
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

// Chain freshness bounds (D-060).
const (
	DefaultMaxHeadAge = 60 * time.Second
	MaxMaxHeadAge     = 300 * time.Second
	// MainnetChainID is Tempo mainnet. Simulated quotes are never accepted on it.
	MainnetChainID = 4217
)

// Broker runs the release pipeline. It is safe for concurrent use.
type Broker struct {
	cfg  Config
	deps Deps
	logs *logQueue
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
	if cfg.FeeSplitter == (common.Address{}) || cfg.FeeToken == (common.Address{}) {
		return nil, errors.New("keybroker: fee splitter and fee token addresses are not set")
	}
	if cfg.AllowSimulated && cfg.ChainID == MainnetChainID {
		return nil, errors.New("keybroker: simulated quotes are never accepted on Tempo mainnet (chain 4217)")
	}
	switch {
	case cfg.MaxHeadAge == 0:
		cfg.MaxHeadAge = DefaultMaxHeadAge
	case cfg.MaxHeadAge < time.Second || cfg.MaxHeadAge > MaxMaxHeadAge:
		return nil, fmt.Errorf("keybroker: max head age %s must be between 1s and %s", cfg.MaxHeadAge, MaxMaxHeadAge)
	}
	cfg.AllowedImages = append([][32]byte(nil), cfg.AllowedImages...)
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
	return &Broker{cfg: cfg, deps: deps, logs: newLogQueue(deps.Log, deps.OpLog, cfg.LogTimeout)}, nil
}

// Flush waits until every decision queued for the log was written (tests, shutdown).
func (b *Broker) Flush(ctx context.Context) error { return b.logs.flush(ctx) }

// Close stops the background decision log after writing what is queued.
func (b *Broker) Close(ctx context.Context) error { return b.logs.close(ctx) }

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

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
