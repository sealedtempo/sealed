// Package anviltest runs a throwaway local Tempo node (anvil --network tempo) and deploys the Sealed registries
// into it, built from the contracts sources with forge into a private temp directory. Tests skip when anvil, forge
// or the contracts sources are missing. Only anvil's public dev keys are used; nothing touches a public network.
package anviltest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/sealedtempo/sealed/internal/localtempo"
)

// Anvil's default dev keys (mnemonic "test test ... junk"). Public; local use only.
var devKeys = []string{
	"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
	"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
	"5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
	"7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
	"47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
	"8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
	"92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
}

// Roles of the dev accounts, matching contracts/script/local-e2e.sh.
const (
	Owner = iota
	Ops
	Oracle
	Customer
	Maintainer
	Treasury
	Enclave
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

// RequireEnv set to "1" (in CI) turns every skip for a missing anvil, forge or contracts tree into a failure, so the
// end-to-end and tamper tests on the real contracts cannot be skipped silently.
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
	port := freePort(t)
	// Mainnet's hardfork (D-053) and its 500M block gas limit.
	cmd := exec.Command(bin, "--network", "tempo", "--hardfork", localtempo.Hardfork, "--port", fmt.Sprint(port),
		"--gas-limit", "500000000", "--silent")
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

func freePort(t testing.TB) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
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

// ContractsDir locates the Foundry project: $SEALED_CONTRACTS_DIR, <repo>/contracts, or the sibling contracts
// worktree used during the parallel build (<repo>/../contracts/contracts).
func ContractsDir() (string, error) {
	if d := os.Getenv("SEALED_CONTRACTS_DIR"); d != "" {
		return d, nil
	}
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	for _, d := range []string{filepath.Join(root, "contracts"), filepath.Join(root, "..", "contracts", "contracts")} {
		if _, err := os.Stat(filepath.Join(d, "foundry.toml")); err == nil {
			if _, err := os.Stat(filepath.Join(d, "src", "DeploymentRegistry.sol")); err == nil {
				return d, nil
			}
		}
	}
	return "", fmt.Errorf("contracts sources not found (set SEALED_CONTRACTS_DIR)")
}

func repoRoot() (string, error) {
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

// BuildContracts compiles the contracts with forge into a private temp directory (the contracts tree is only
// read) and returns the artifacts by contract name. It builds once per test binary.
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
		// <repo>/tmp is gitignored. One output dir per test package, so parallel package runs do not race and
		// forge's cache keeps rebuilds fast.
		root, err := repoRoot()
		if err != nil {
			buildErr = err
			return
		}
		cwd, _ := os.Getwd()
		out := filepath.Join(root, "tmp", "forge-"+filepath.Base(cwd))
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
			a, err := readArtifact(filepath.Join(out, "out", name+".sol", name+".json"))
			if err != nil {
				buildErr = err
				return
			}
			buildArts[name] = a
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

func readArtifact(path string) (Artifact, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, err
	}
	var f struct {
		ABI      json.RawMessage `json:"abi"`
		Bytecode struct {
			Object string `json:"object"`
		} `json:"bytecode"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return Artifact{}, err
	}
	a, err := abi.JSON(bytes.NewReader(f.ABI))
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{ABI: a, Bytecode: common.FromHex(f.Bytecode.Object)}, nil
}

// Send signs and sends a type-2 transaction from dev account `from` and waits for its receipt. It returns an error
// when gas estimation fails (a revert) or the receipt status is not 1.
func (n *Node) Send(from int, to *common.Address, data []byte) (*types.Receipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key := Key(from)
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
		ChainID:   n.ChainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(0),
		GasFeeCap: new(big.Int).Mul(price, big.NewInt(2)),
		Gas:       gas * 13 / 10,
		To:        to,
		Data:      data,
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(n.ChainID), key)
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

// Deploy deploys art with constructor args from dev account `from`.
func (n *Node) Deploy(t testing.TB, from int, art Artifact, args ...any) common.Address {
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

// Call sends method(args...) on contract `to` from dev account `from` and fails the test on revert.
func (n *Node) Call(t testing.TB, from int, to common.Address, a abi.ABI, method string, args ...any) *types.Receipt {
	t.Helper()
	r, err := n.Try(from, to, a, method, args...)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return r
}

// Try is Call without failing the test.
func (n *Node) Try(from int, to common.Address, a abi.ABI, method string, args ...any) (*types.Receipt, error) {
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	return n.Send(from, &to, data)
}

// RevertName returns the name of the custom error of a reverted call or gas estimate, decoded with a, or "".
func RevertName(a abi.ABI, err error) string {
	var de rpc.DataError
	if !errors.As(err, &de) {
		return ""
	}
	s, ok := de.ErrorData().(string)
	if !ok {
		return ""
	}
	data, decErr := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if decErr != nil || len(data) < 4 {
		return ""
	}
	for name, e := range a.Errors {
		if bytes.Equal(e.ID[:4], data[:4]) {
			return name
		}
	}
	return ""
}

// Registries is a deployed and wired set of Sealed contracts.
type Registries struct {
	Artifacts          map[string]Artifact
	PlatformRegistry   common.Address
	AppRegistry        common.Address
	OracleVerifier     common.Address
	DeploymentRegistry common.Address
}

// DeployRegistries deploys PlatformRegistry, AppRegistry, OracleSignatureVerifier and DeploymentRegistry from the
// Owner account and wires them as contracts/script/Deploy.s.sol does: Ops is registrar, Oracle is an allowed
// signer, method 1 is the oracle verifier.
func DeployRegistries(t testing.TB, n *Node) *Registries {
	t.Helper()
	arts := BuildContracts(t)
	owner := Addr(Owner)
	r := &Registries{Artifacts: arts}
	r.PlatformRegistry = n.Deploy(t, Owner, arts["PlatformRegistry"], owner)
	r.AppRegistry = n.Deploy(t, Owner, arts["AppRegistry"], owner)
	r.OracleVerifier = n.Deploy(t, Owner, arts["OracleSignatureVerifier"], owner)
	r.DeploymentRegistry = n.Deploy(t, Owner, arts["DeploymentRegistry"], owner, r.PlatformRegistry, r.AppRegistry)
	n.Call(t, Owner, r.AppRegistry, arts["AppRegistry"].ABI, "grantRegistrar", Addr(Ops))
	n.Call(t, Owner, r.OracleVerifier, arts["OracleSignatureVerifier"].ABI, "addSigner", Addr(Oracle))
	n.Call(t, Owner, r.DeploymentRegistry, arts["DeploymentRegistry"].ABI, "setVerifier", uint8(1), r.OracleVerifier)
	return r
}

func t0() context.Context { return context.Background() }

func callMsg(to common.Address, data []byte) ethereum.CallMsg {
	return ethereum.CallMsg{To: &to, Data: data}
}
