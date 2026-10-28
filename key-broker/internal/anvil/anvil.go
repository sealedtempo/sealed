// Package anvil runs a throwaway local Tempo node (anvil --network tempo) and deploys the Sealed registries into it,
// built from the contracts sources with forge into the repository's tmp/ directory. Tests skip when anvil, forge or
// the contracts sources are missing, unless SEALED_REQUIRE_ANVIL=1. Only anvil's public dev keys are used; nothing
// touches a public network.
//
// It follows verifier/internal/anviltest, which the key broker cannot import (Go internal package rule).
package anvil

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Anvil's default dev keys (mnemonic "test test ... junk"). Public; local use only.
var devKeys = []string{
	"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
	"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
	"5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
	"7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
	"47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
	"8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
}

// Roles of the dev accounts (as in contracts/script/local-e2e.sh).
const (
	Owner = iota
	Ops
	Oracle
	Customer
	Maintainer
	OtherCustomer
)

// Key returns dev account i's private key.
func Key(i int) *ecdsa.PrivateKey {
	k, err := crypto.HexToECDSA(devKeys[i])
	if err != nil {
		panic(err)
	}
	return k
}

// Addr returns dev account i's address.
func Addr(i int) common.Address { return crypto.PubkeyToAddress(Key(i).PublicKey) }

// AccountOf returns the dev account index of addr, or -1.
func AccountOf(addr common.Address) int {
	for i := range devKeys {
		if Addr(i) == addr {
			return i
		}
	}
	return -1
}

// RequireEnv set to "1" (CI) turns every skip for a missing anvil, forge or contracts tree into a failure.
const RequireEnv = "SEALED_REQUIRE_ANVIL"

// SkipOrFail skips the test, or fails it when RequireEnv is "1".
func SkipOrFail(t testing.TB, reason string) {
	t.Helper()
	if os.Getenv(RequireEnv) == "1" {
		t.Fatalf("%s=1 but %s", RequireEnv, reason)
	}
	t.Skip(reason)
}

// Node is a running anvil instance.
type Node struct {
	URL     string
	ChainID *big.Int
	Client  *ethclient.Client
}

// Start launches anvil --network tempo on a free port and stops it when the test ends.
func Start(t testing.TB) *Node {
	t.Helper()
	bin, err := exec.LookPath("anvil")
	if err != nil {
		SkipOrFail(t, "anvil not installed")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	// Block gas limit 500M as on mainnet: Foundry 1.7.1's T4 rules charge about 27M gas for DeploymentRegistry.
	cmd := exec.Command(bin, "--network", "tempo", "--hardfork", "T4", "--port", fmt.Sprint(port), "--gas-limit", "500000000", "--silent")
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start anvil: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(20 * time.Second)
	for {
		ec, err := ethclient.Dial(url)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			id, err := ec.ChainID(ctx)
			cancel()
			if err == nil {
				t.Cleanup(ec.Close)
				return &Node{URL: url, ChainID: id, Client: ec}
			}
			ec.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("anvil did not start: %s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Artifact is a compiled contract.
type Artifact struct {
	ABI      abi.ABI
	Bytecode []byte
}

var (
	buildOnce sync.Once
	buildArts map[string]Artifact
	buildErr  error
	buildSkip string
)

// RepoRoot finds the directory holding go.mod above the working directory.
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

// ContractsDir locates the Foundry project: $SEALED_CONTRACTS_DIR or <repo>/contracts. Its soldeer dependencies must
// be installed (`forge soldeer install` in contracts/).
func ContractsDir() (string, error) {
	if d := os.Getenv("SEALED_CONTRACTS_DIR"); d != "" {
		return d, nil
	}
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	d := filepath.Join(root, "contracts")
	if _, err := os.Stat(filepath.Join(d, "src", "DeploymentRegistry.sol")); err != nil {
		return "", fmt.Errorf("contracts sources not found (set SEALED_CONTRACTS_DIR)")
	}
	if _, err := os.Stat(filepath.Join(d, "dependencies")); err != nil {
		return "", fmt.Errorf("contracts/dependencies missing: run `forge soldeer install` in contracts/")
	}
	return d, nil
}

// BuildContracts compiles the registries with forge into <repo>/tmp/forge-key-broker (the contracts tree is only
// read) and returns the artifacts by name. It builds once per test binary.
func BuildContracts(t testing.TB) map[string]Artifact {
	t.Helper()
	buildOnce.Do(func() {
		forge, err := exec.LookPath("forge")
		if err != nil {
			buildSkip = "forge not installed"
			return
		}
		dir, err := ContractsDir()
		if err != nil {
			buildSkip = err.Error()
			return
		}
		root, err := RepoRoot()
		if err != nil {
			buildErr = err
			return
		}
		cwd, _ := os.Getwd()
		out := filepath.Join(root, "tmp", "forge-key-broker-"+filepath.Base(cwd))
		if err := os.MkdirAll(out, 0o755); err != nil {
			buildErr = err
			return
		}
		cmd := exec.Command(forge, "build", "--root", dir, "--out", filepath.Join(out, "out"),
			"--cache-path", filepath.Join(out, "cache"), "--skip", "test", "--skip", "script")
		if msg, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("forge build: %v\n%s", err, msg)
			return
		}
		buildArts = map[string]Artifact{}
		for _, name := range []string{"PlatformRegistry", "AppRegistry", "OracleSignatureVerifier", "DeploymentRegistry"} {
			raw, err := os.ReadFile(filepath.Join(out, "out", name+".sol", name+".json"))
			if err != nil {
				buildErr = err
				return
			}
			var f struct {
				ABI      json.RawMessage `json:"abi"`
				Bytecode struct {
					Object string `json:"object"`
				} `json:"bytecode"`
			}
			if err := json.Unmarshal(raw, &f); err != nil {
				buildErr = err
				return
			}
			a, err := abi.JSON(bytes.NewReader(f.ABI))
			if err != nil {
				buildErr = err
				return
			}
			buildArts[name] = Artifact{ABI: a, Bytecode: common.FromHex(f.Bytecode.Object)}
		}
	})
	if buildSkip != "" {
		SkipOrFail(t, buildSkip)
	}
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return buildArts
}

// Send signs and sends a type-2 transaction from dev account `from` and waits for its receipt.
func (n *Node) Send(from int, to *common.Address, data []byte) (*types.Receipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sender := Addr(from)
	nonce, err := n.Client.PendingNonceAt(ctx, sender)
	if err != nil {
		return nil, err
	}
	gas, err := n.Client.EstimateGas(ctx, ethereum.CallMsg{From: sender, To: to, Data: data})
	if err != nil {
		return nil, err
	}
	price, err := n.Client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: n.ChainID, Nonce: nonce, GasTipCap: big.NewInt(0), GasFeeCap: new(big.Int).Mul(price, big.NewInt(2)),
		Gas: gas * 13 / 10, To: to, Data: data,
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(n.ChainID), Key(from))
	if err != nil {
		return nil, err
	}
	if err := n.Client.SendTransaction(ctx, signed); err != nil {
		return nil, err
	}
	for {
		r, err := n.Client.TransactionReceipt(ctx, signed.Hash())
		if err == nil {
			if r.Status != types.ReceiptStatusSuccessful {
				return r, fmt.Errorf("tx %s reverted", signed.Hash())
			}
			return r, nil
		}
		if !strings.Contains(err.Error(), "not found") {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Call sends method(args...) on `to` from dev account `from` and fails the test on revert.
func (n *Node) Call(t testing.TB, from int, to common.Address, a abi.ABI, method string, args ...any) {
	t.Helper()
	data, err := a.Pack(method, args...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Send(from, &to, data); err != nil {
		t.Fatalf("%s: %v", method, err)
	}
}

func (n *Node) deploy(t testing.TB, from int, art Artifact, args ...any) common.Address {
	t.Helper()
	ctorArgs, err := art.ABI.Pack("", args...)
	if err != nil {
		t.Fatal(err)
	}
	r, err := n.Send(from, nil, append(bytes.Clone(art.Bytecode), ctorArgs...))
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return r.ContractAddress
}

// Registries is a deployed and wired set of Sealed registries.
type Registries struct {
	Node               *Node
	Artifacts          map[string]Artifact
	PlatformRegistry   common.Address
	AppRegistry        common.Address
	OracleVerifier     common.Address
	DeploymentRegistry common.Address
}

// DeployRegistries deploys PlatformRegistry, AppRegistry, OracleSignatureVerifier and DeploymentRegistry from Owner
// and wires them like contracts/script/Deploy.s.sol: Ops is registrar, Oracle an allowed signer, method 1 the
// oracle verifier.
func DeployRegistries(t testing.TB, n *Node) *Registries {
	t.Helper()
	arts := BuildContracts(t)
	owner := Addr(Owner)
	r := &Registries{Node: n, Artifacts: arts}
	r.PlatformRegistry = n.deploy(t, Owner, arts["PlatformRegistry"], owner)
	r.AppRegistry = n.deploy(t, Owner, arts["AppRegistry"], owner)
	r.OracleVerifier = n.deploy(t, Owner, arts["OracleSignatureVerifier"], owner)
	r.DeploymentRegistry = n.deploy(t, Owner, arts["DeploymentRegistry"], owner, r.PlatformRegistry, r.AppRegistry)
	n.Call(t, Owner, r.AppRegistry, arts["AppRegistry"].ABI, "grantRegistrar", Addr(Ops))
	n.Call(t, Owner, r.OracleVerifier, arts["OracleSignatureVerifier"].ABI, "addSigner", Addr(Oracle))
	n.Call(t, Owner, r.DeploymentRegistry, arts["DeploymentRegistry"].ABI, "setVerifier", uint8(1), r.OracleVerifier)
	return r
}

func (r *Registries) abi(name string) abi.ABI { return r.Artifacts[name].ABI }

// AddImage registers an image (owner) and returns its imageId.
func (r *Registries) AddImage(t testing.TB, name, version string, mrtd, rtmr0, rtmr1, rtmr2 [48]byte, isDebug bool) [32]byte {
	t.Helper()
	mh := crypto.Keccak256Hash(mrtd[:], rtmr0[:], rtmr1[:], rtmr2[:])
	id := ImageID(name, version, mh)
	r.Node.Call(t, Owner, r.PlatformRegistry, r.abi("PlatformRegistry"), "addImage", id, name, version,
		mrtd[:], rtmr0[:], rtmr1[:], rtmr2[:], isDebug, "https://example.invalid/"+name)
	return id
}

// RevokeImage revokes an image (owner).
func (r *Registries) RevokeImage(t testing.TB, imageID [32]byte) {
	t.Helper()
	r.Node.Call(t, Owner, r.PlatformRegistry, r.abi("PlatformRegistry"), "revokeImage", imageID, "test")
}

// RegisterApp registers slug with the Maintainer account (owner) and returns its appId.
func (r *Registries) RegisterApp(t testing.TB, slug string) [32]byte {
	t.Helper()
	id := crypto.Keccak256Hash([]byte(slug))
	r.Node.Call(t, Owner, r.AppRegistry, r.abi("AppRegistry"), "registerApp", id, slug, slug, "MIT", Addr(Maintainer),
		uint16(2000), "https://example.invalid/"+slug)
	return id
}

// PublishRelease publishes a release (ops) and returns its releaseId.
func (r *Registries) PublishRelease(t testing.TB, appID [32]byte, version string, bundleHash [32]byte) [32]byte {
	t.Helper()
	r.Node.Call(t, Ops, r.AppRegistry, r.abi("AppRegistry"), "publishRelease", appID, version, bundleHash,
		crypto.Keccak256Hash([]byte("egress")), crypto.Keccak256Hash([]byte("sbom")), "", "")
	return ReleaseID(appID, version, bundleHash)
}

// RevokeRelease revokes a release (owner).
func (r *Registries) RevokeRelease(t testing.TB, releaseID [32]byte) {
	t.Helper()
	r.Node.Call(t, Owner, r.AppRegistry, r.abi("AppRegistry"), "revokeRelease", releaseID, "test")
}

// ApproveStack approves (stackHash, releaseIds, imageId) as dev account `customer` with no expiry.
func (r *Registries) ApproveStack(t testing.TB, customer int, stackHash [32]byte, releaseIDs [][32]byte, imageID [32]byte) {
	t.Helper()
	r.Node.Call(t, customer, r.DeploymentRegistry, r.abi("DeploymentRegistry"), "approveStack", stackHash, releaseIDs, imageID, uint64(0))
}

// RevokeStack revokes the approval of stackHash as dev account `customer`.
func (r *Registries) RevokeStack(t testing.TB, customer int, stackHash [32]byte) {
	t.Helper()
	r.Node.Call(t, customer, r.DeploymentRegistry, r.abi("DeploymentRegistry"), "revokeStack", stackHash)
}

// ImageID is keccak256(abi.encode(name, version, measurementsHash)).
func ImageID(name, version string, measurementsHash [32]byte) [32]byte {
	strT, _ := abi.NewType("string", "", nil)
	b32T, _ := abi.NewType("bytes32", "", nil)
	enc, err := abi.Arguments{{Type: strT}, {Type: strT}, {Type: b32T}}.Pack(name, version, measurementsHash)
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(enc)
}

// ReleaseID is keccak256(abi.encode(appId, version, bundleHash)).
func ReleaseID(appID [32]byte, version string, bundleHash [32]byte) [32]byte {
	strT, _ := abi.NewType("string", "", nil)
	b32T, _ := abi.NewType("bytes32", "", nil)
	enc, err := abi.Arguments{{Type: b32T}, {Type: strT}, {Type: b32T}}.Pack(appID, version, bundleHash)
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(enc)
}
