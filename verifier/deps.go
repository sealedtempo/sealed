// Package verify checks Sealed evidence bundles and live attestations end to end: TDX quote and TCB, image
// measurements against PlatformRegistry, RTMR3 replay, stack recomputation, releases, the customer's onchain
// approval and the deployment record (spec 8.4, INTERFACES.md sections 3, 6, 8 and 9, D-014).
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// ChainReader is the onchain state the verifier reads. *chain.Client implements it.
type ChainReader interface {
	ChainID(ctx context.Context) (uint64, error)
	Addresses() chain.Addresses
	GetImage(ctx context.Context, imageID [32]byte) (*chain.Image, error)
	IsApprovedImage(ctx context.Context, imageID [32]byte) (bool, error)
	GetRelease(ctx context.Context, releaseID [32]byte) (*chain.Release, error)
	IsActiveRelease(ctx context.Context, releaseID [32]byte) (bool, error)
	IsStackApproved(ctx context.Context, customer common.Address, stackHash [32]byte) (bool, error)
	GetStackApproval(ctx context.Context, customer common.Address, stackHash [32]byte) (*chain.StackApproval, error)
	GetDeployment(ctx context.Context, deploymentID [32]byte) (*chain.Deployment, error)
	RecordDigest(ctx context.Context, r chain.Record) ([32]byte, error)
}

// BlockPinner is a ChainReader that can pin every read of one verification to the current head block. *chain.Client
// is pinned through BlockNumber and AtBlock without implementing it.
type BlockPinner interface {
	PinHead(ctx context.Context) (ChainReader, uint64, error)
}

// BlockTimer reads a block's timestamp (unix seconds). *chain.Client implements it. A verification reads the
// timestamp of the head block its reads are pinned to and fails the chain check when that head is stale (D-060), so a
// reader that cannot be pinned, or whose pinned reader is not a BlockTimer, fails the chain check.
type BlockTimer interface {
	BlockTime(ctx context.Context, n uint64) (uint64, error)
}

// WithHead wraps an in-memory reader that has no blocks (tests and tools) so verifications see the head block
// number with the timestamp at() returns. Production verifications use *chain.Client, which reads the real head.
func WithHead(r ChainReader, number uint64, at func() time.Time) ChainReader {
	return &fixedHead{ChainReader: r, number: number, at: at}
}

type fixedHead struct {
	ChainReader
	number uint64
	at     func() time.Time
}

func (f *fixedHead) PinHead(context.Context) (ChainReader, uint64, error) { return f, f.number, nil }

func (f *fixedHead) BlockTime(_ context.Context, n uint64) (uint64, error) {
	if n != f.number {
		return 0, fmt.Errorf("block %d is not the head %d", n, f.number)
	}
	return uint64(f.at().Unix()), nil
}

// pinHead returns a reader pinned to the head block, and false when r cannot be pinned.
func pinHead(ctx context.Context, r ChainReader) (ChainReader, uint64, bool, error) {
	switch c := r.(type) {
	case BlockPinner:
		pinned, n, err := c.PinHead(ctx)
		return pinned, n, true, err
	case *chain.Client:
		n, err := c.BlockNumber(ctx)
		if err != nil {
			return r, 0, true, err
		}
		return c.AtBlock(n), n, true, nil
	}
	return r, 0, false, nil
}

// Composer recomputes a stack deterministically (runtime/composer, D-006). The adapter fetches each release
// bundle by its onchain bundleHash, checks sha256 against it, and runs the composer with the given config.
type Composer interface {
	Compose(ctx context.Context, in ComposeInput) (*ComposeOutput, error)
}

// ComposeInput is the public config plus the onchain releases it names, in config.apps order.
type ComposeInput struct {
	Config   json.RawMessage
	Releases []ComposeRelease
}

// ComposeRelease is one release as recorded in AppRegistry.
type ComposeRelease struct {
	App        string // config.apps[].id, the app slug
	ReleaseID  [32]byte
	AppID      [32]byte
	Version    string
	BundleHash [32]byte
}

// ComposeOutput is what the composer produced.
type ComposeOutput struct {
	AppCompose   []byte
	StackHash    [32]byte
	ConfigHash   [32]byte
	DeploymentID [32]byte
	// Unbuilt lists images still at the all-zero placeholder digest (runtime/composer Result.Unbuilt). Such a stack
	// cannot boot; approval flows refuse it.
	Unbuilt []string
}

// ErrComposerNotConfigured is returned by a nil Composer. Verification then fails closed.
var ErrComposerNotConfigured = errors.New("composer not configured")

// Deps are the verifier's collaborators.
type Deps struct {
	Quotes   *attest.Verifier
	Chain    ChainReader
	Composer Composer // nil: stack_recompute fails
	Now      func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d Deps) validate() error {
	if d.Quotes == nil {
		return errors.New("verify: Deps.Quotes is nil")
	}
	if d.Chain == nil {
		return errors.New("verify: Deps.Chain is nil")
	}
	return nil
}

// Options tune a verification.
type Options struct {
	// ChainID is the chain the RPC, the bundle and the config must be on; 0 means Tempo mainnet (4217). Local runs
	// set their own chain (D-060).
	ChainID uint64
	// MaxChainHeadAge bounds the age of the head block every chain read is pinned to (D-060): a stale or lagging RPC
	// could otherwise hide a revocation, so an older head (or one further in the future) fails the chain check. Zero
	// or negative means DefaultMaxChainHeadAge; values above MaxChainHeadAgeLimit are capped to it.
	MaxChainHeadAge time.Duration
	// AcceptSimulated lets a dev simulator quote pass, when the quote verifier allows simulated quotes at all
	// (attest.VerifierOptions.AllowSimulated). Without it a simulated quote fails the quote check, so a consumer that
	// only reads Report.OK never accepts one; dev use is an opt-in per verification.
	AcceptSimulated bool
	// RequireOnchainRecord fails when the deployment is not registered. The oracle verifies evidence before it
	// registers, so it leaves this false; `sealed verify` sets it.
	RequireOnchainRecord bool
	// MaxEvidenceAge, when non-zero, bounds now - attestedAt (the oracle uses 15 minutes).
	MaxEvidenceAge time.Duration
	// ExpectedDeploymentID, when set, must equal the verified deployment id (sealed verify --deployment), in
	// evidence and live mode.
	ExpectedDeploymentID *[32]byte
	// ExpectedCustomer, when set, must equal config.customer (for example the operator for the relay).
	ExpectedCustomer *common.Address
	// ExpectedAppIDs, when set, must all be among config.apps[].id (for example inference-relay for the payer).
	ExpectedAppIDs []string
	// Heartbeat verifies evidence for DeploymentRegistry.heartbeat: the deployment must be registered and Active
	// with the same identity, and the bundle must carry a new quote (quoteHash differs from the record) attested
	// after the record's lastAttestedAt. Without it, evidence must be the record's latest (same quoteHash and
	// attestedAt).
	Heartbeat bool
}

// maxFutureSkew matches DeploymentRegistry.MAX_FUTURE_SKEW.
const maxFutureSkew = 5 * time.Minute

// Chain head freshness bounds (D-060).
const (
	DefaultMaxChainHeadAge = 60 * time.Second
	MaxChainHeadAgeLimit   = 300 * time.Second
)

func (o Options) chainID() uint64 {
	if o.ChainID == 0 {
		return chain.MainnetChainID
	}
	return o.ChainID
}

func (o Options) maxChainHeadAge() time.Duration {
	switch {
	case o.MaxChainHeadAge <= 0:
		return DefaultMaxChainHeadAge
	case o.MaxChainHeadAge > MaxChainHeadAgeLimit:
		return MaxChainHeadAgeLimit
	}
	return o.MaxChainHeadAge
}

// DeploymentID is keccak256(abi.encode(customer, stackHash, salt)) (INTERFACES.md section 2).
func DeploymentID(customer common.Address, stackHash, salt [32]byte) [32]byte {
	addrT, _ := abi.NewType("address", "", nil)
	b32T, _ := abi.NewType("bytes32", "", nil)
	enc, err := abi.Arguments{{Type: addrT}, {Type: b32T}, {Type: b32T}}.Pack(customer, stackHash, salt)
	if err != nil {
		panic(err) // fixed types; cannot fail
	}
	return crypto.Keccak256Hash(enc)
}
