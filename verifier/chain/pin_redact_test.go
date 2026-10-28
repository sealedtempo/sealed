package chain

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/rpc"
)

func TestAtBlockPinsEveryRead(t *testing.T) {
	c, fb := newFake(t)
	fb.head = 1234
	fb.respond(c, "PlatformRegistry", "isApprovedImage", true)
	fb.respond(c, "AppRegistry", "isActiveRelease", true)
	ctx := context.Background()
	if _, ok := c.Block(); ok {
		t.Fatal("new client is pinned")
	}
	head, err := c.BlockNumber(ctx)
	if err != nil || head != 1234 {
		t.Fatalf("BlockNumber %d %v", head, err)
	}
	pinned := c.AtBlock(head)
	if n, ok := pinned.Block(); !ok || n != 1234 {
		t.Fatalf("Block %d %v", n, ok)
	}
	pinned.IsApprovedImage(ctx, [32]byte{})
	pinned.IsActiveRelease(ctx, [32]byte{})
	c.IsApprovedImage(ctx, [32]byte{})
	if len(fb.blocks) != 3 || fb.blocks[0].Uint64() != 1234 || fb.blocks[1].Uint64() != 1234 || fb.blocks[2] != nil {
		t.Fatalf("blocks %v", fb.blocks)
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://rpc.tempo.xyz":                        "https://rpc.tempo.xyz",
		"https://user:pw@rpc.example/v2/KEY?token=abc": "https://rpc.example",
		"http://127.0.0.1:8545/":                       "http://127.0.0.1:8545",
		"not a url":                                    "<rpc>",
		"wss://eth.provider.io/ws/v3/0123456789abcdef": "wss://eth.provider.io",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDialRedactsErrors: go-ethereum errors embed the full endpoint URL (*url.Error); none of its secret parts may
// reach reports, HTTP bodies or logs.
func TestDialRedactsErrors(t *testing.T) {
	const raw = "http://alice:hunter2@127.0.0.1:1/v2/SECRET-API-KEY?token=abc"
	c, err := Dial(context.Background(), raw, testAddrs)
	if err != nil {
		t.Fatal(err)
	}
	_, idErr := c.ChainID(context.Background())
	_, callErr := c.GetImage(context.Background(), [32]byte{})
	_, blockErr := c.BlockNumber(context.Background())
	for name, err := range map[string]error{"eth_chainId": idErr, "eth_call": callErr, "eth_blockNumber": blockErr} {
		if err == nil {
			t.Fatalf("%s: no error from a closed port", name)
		}
		msg := err.Error()
		for _, secret := range []string{"SECRET-API-KEY", "token=abc", "hunter2", "alice", "/v2/"} {
			if strings.Contains(msg, secret) {
				t.Fatalf("%s error leaks %q: %s", name, secret, msg)
			}
		}
		if !strings.Contains(msg, "127.0.0.1:1") {
			t.Fatalf("%s error lost the host: %s", name, msg)
		}
	}
	if _, err := Dial(context.Background(), "ftp://x/KEY", testAddrs); err == nil || strings.Contains(err.Error(), "KEY") {
		t.Fatalf("dial error: %v", err)
	}
}

type urlDataErr struct{ dataErr }

func (e urlDataErr) Error() string {
	return `Post "https://rpc.example/v2/KEY": execution reverted`
}

func TestRedactedErrorsStillDecodeReverts(t *testing.T) {
	c, fb := newFake(t)
	fb.revert(c, "DeploymentRegistry", "getDeployment", "DeploymentNotFound", [32]byte{1})
	r := newRedactor("https://rpc.example/v2/KEY")
	inner := fb.reverts
	for sel, err := range inner {
		var de rpc.DataError
		errors.As(err, &de)
		inner[sel] = r.redact(urlDataErr{dataErr{de.ErrorData().(string)}})
		if strings.Contains(inner[sel].Error(), "KEY") {
			t.Fatalf("not redacted: %v", inner[sel])
		}
	}
	_, err := c.GetDeployment(context.Background(), [32]byte{1})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("revert lost through redaction: %v", err)
	}
	var rev *RevertError
	if !errors.As(err, &rev) || rev.Name != "DeploymentNotFound" {
		t.Fatalf("revert %v", err)
	}
	if got := r.redact(fmt.Errorf("plain")); got.Error() != "plain" {
		t.Fatal("unrelated error changed")
	}
	if r.redact(nil) != nil {
		t.Fatal("nil")
	}
}
