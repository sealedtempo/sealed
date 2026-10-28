// Package testchain runs a throwaway local Tempo node (anvil --network tempo) with the Sealed registries built
// from contracts/ by forge, for the CLI's integration tests. Only anvil's public dev keys are used and nothing
// touches a public network. Tests skip when anvil, forge or the contracts (with dependencies) are missing;
// SEALED_REQUIRE_ANVIL=1 turns the skip into a failure. It follows verifier/internal/anviltest, which the CLI
// cannot import.
package testchain

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
	"runtime"
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

	"github.com/sealed-dev/sealed/internal/localtempo"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// Anvil's default dev keys (mnemonic "test test ... junk"). Public; local use only.
var devKeys = []string{
	"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
	"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
	"5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
	"7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
}

// Roles of the dev accounts.
const (
	Owner = iota
	Ops
	Oracle
	Customer
)

// Key returns dev account i's key.
func Key(i int) *ecdsa.PrivateKey {
	k, err := crypto.HexToECDSA(devKeys[i])
	if err != nil {
		panic(err)
	}
	return k
}

// Addr returns dev account i's address.
func Addr(i int) common.Address { return crypto.PubkeyToAddress(Key(i).PublicKey) }

func skipOrFail(t testing.TB, reason string) {
	t.Helper()
	if os.Getenv("SEALED_REQUIRE_ANVIL") == "1" {
		t.Fatalf("SEALED_REQUIRE_ANVIL=1 but %s", reason)
	}
	t.Skip(reason)
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// Node is a running anvil with the registries deployed.
type Node struct {
	URL     string
	ChainID *big.Int
	Client  *ethclient.Client
	Addrs   chain.Addresses
	ABIs    map[string]abi.ABI
}

// Start launches anvil, builds and deploys PlatformRegistry, AppRegistry, OracleSignatureVerifier and
// DeploymentRegistry, and wires them like contracts/script/Deploy.s.sol (Ops is registrar, Oracle a signer, method
// 1 the oracle verifier).
func Start(t testing.TB) *Node {
	t.Helper()
	if testing.Short() {
		t.Skip("-short")
	}
	arts := build(t)
	bin, err := exec.LookPath("anvil")
	if err != nil {
		skipOrFail(t, "anvil not installed")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	// Chain id 4217 as on mainnet, so configs and evidence carry the production chain id.
	cmd := exec.Command(bin, "--network", "tempo", "--hardfork", localtempo.Hardfork, "--chain-id", "4217", "--port", fmt.Sprint(port), "--gas-limit", "500000000", "--silent")
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start anvil: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	n := &Node{URL: fmt.Sprintf("http://127.0.0.1:%d", port), ABIs: map[string]abi.ABI{}}
	for deadline := time.Now().Add(20 * time.Second); ; {
		if ec, err := ethclient.Dial(n.URL); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			id, err := ec.ChainID(ctx)
			cancel()
			if err == nil {
				n.Client, n.ChainID = ec, id
				break
			}
			ec.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("anvil did not start: %s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	for k, a := range arts {
		n.ABIs[k] = a.abi
	}
	owner := Addr(Owner)
	n.Addrs.PlatformRegistry = n.deploy(t, arts["PlatformRegistry"], owner)
	n.Addrs.AppRegistry = n.deploy(t, arts["AppRegistry"], owner)
	oracle := n.deploy(t, arts["OracleSignatureVerifier"], owner)
	n.Addrs.DeploymentRegistry = n.deploy(t, arts["DeploymentRegistry"], owner, n.Addrs.PlatformRegistry, n.Addrs.AppRegistry)
	n.Call(t, Owner, n.Addrs.AppRegistry, "AppRegistry", "grantRegistrar", Addr(Ops))
	n.Call(t, Owner, oracle, "OracleSignatureVerifier", "addSigner", Addr(Oracle))
	n.Call(t, Owner, n.Addrs.DeploymentRegistry, "DeploymentRegistry", "setVerifier", uint8(1), oracle)
	return n
}

type artifact struct {
	abi      abi.ABI
	bytecode []byte
}

var (
	once     sync.Once
	arts     map[string]artifact
	buildErr error
	skipWhy  string
)

func build(t testing.TB) map[string]artifact {
	t.Helper()
	once.Do(func() {
		forge, err := exec.LookPath("forge")
		if err != nil {
			skipWhy = "forge not installed"
			return
		}
		dir := os.Getenv("SEALED_CONTRACTS_DIR")
		if dir == "" {
			dir = filepath.Join(repoRoot(), "contracts")
		}
		if _, err := os.Stat(filepath.Join(dir, "dependencies")); err != nil {
			skipWhy = "contracts dependencies missing (make -C contracts deps, or set SEALED_CONTRACTS_DIR)"
			return
		}
		out := filepath.Join(repoRoot(), "tmp", "forge-cli")
		cmd := exec.Command(forge, "build", "--root", dir, "--out", filepath.Join(out, "out"), "--cache-path", filepath.Join(out, "cache"), "--skip", "test", "--skip", "script")
		if msg, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("forge build: %v\n%s", err, msg)
			return
		}
		arts = map[string]artifact{}
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
			arts[name] = artifact{abi: a, bytecode: common.FromHex(f.Bytecode.Object)}
		}
	})
	if skipWhy != "" {
		skipOrFail(t, skipWhy)
	}
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return arts
}

// Send signs a type-2 transaction from dev account from and waits for a successful receipt.
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
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: n.ChainID, Nonce: nonce, GasTipCap: big.NewInt(0),
		GasFeeCap: new(big.Int).Mul(price, big.NewInt(2)), Gas: gas * 13 / 10, To: to, Data: data})
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

func (n *Node) deploy(t testing.TB, a artifact, args ...any) common.Address {
	t.Helper()
	ctor, err := a.abi.Pack("", args...)
	if err != nil {
		t.Fatal(err)
	}
	r, err := n.Send(Owner, nil, append(bytes.Clone(a.bytecode), ctor...))
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return r.ContractAddress
}

// Call sends contract.method(args) from dev account from and fails the test on a revert.
func (n *Node) Call(t testing.TB, from int, to common.Address, contract, method string, args ...any) *types.Receipt {
	t.Helper()
	data, err := n.ABIs[contract].Pack(method, args...)
	if err != nil {
		t.Fatal(err)
	}
	r, err := n.Send(from, &to, data)
	if err != nil {
		t.Fatalf("%s.%s: %v", contract, method, err)
	}
	return r
}

// BlockTime is the latest block's timestamp (read raw: go-ethereum does not decode every Tempo header field).
func (n *Node) BlockTime(t testing.TB) uint64 {
	t.Helper()
	var blk struct {
		Timestamp string `json:"timestamp"`
	}
	if err := n.Client.Client().CallContext(context.Background(), &blk, "eth_getBlockByNumber", "latest", false); err != nil {
		t.Fatal(err)
	}
	v, ok := new(big.Int).SetString(strings.TrimPrefix(blk.Timestamp, "0x"), 16)
	if !ok {
		t.Fatalf("block timestamp %q", blk.Timestamp)
	}
	return v.Uint64()
}
