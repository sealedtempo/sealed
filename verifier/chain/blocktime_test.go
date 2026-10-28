package chain

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeRPC answers eth_getBlockByNumber with a fixed JSON result.
type fakeRPC struct {
	result string
	err    error
	args   []any
}

func (f *fakeRPC) CallContext(_ context.Context, result any, method string, args ...any) error {
	if method != "eth_getBlockByNumber" {
		return errors.New("unexpected method " + method)
	}
	f.args = args
	if f.err != nil {
		return f.err
	}
	return json.Unmarshal([]byte(f.result), result)
}

func TestBlockTimeDecodesOnlyNumberAndTimestamp(t *testing.T) {
	// A Tempo-like header with fields go-ethereum's Header decoder does not know; transactions are hashes only.
	f := &fakeRPC{result: `{"number":"0x2c2a","timestamp":"0x6a1b2c3d","hash":"0x01","mainBlockGeneralGasLimit":"0x1",` +
		`"transactions":["0xaa"],"timestampMillisPart":"0x1f4"}`}
	ts, err := blockTime(context.Background(), f, 0x2c2a)
	if err != nil || ts != 0x6a1b2c3d {
		t.Fatalf("blockTime = %d, %v", ts, err)
	}
	if len(f.args) != 2 || f.args[0] != "0x2c2a" || f.args[1] != false {
		t.Fatalf("args %v: must ask for block 0x2c2a without full transactions", f.args)
	}
	for name, tc := range map[string]struct {
		rpc  *fakeRPC
		want string
	}{
		"unknown block":   {&fakeRPC{result: `null`}, "block not found"},
		"another block":   {&fakeRPC{result: `{"number":"0x1","timestamp":"0x2"}`}, "answered block 1"},
		"no timestamp":    {&fakeRPC{result: `{"number":"0x2c2a"}`}, "timestamp missing"},
		"transport error": {&fakeRPC{err: errors.New("connection refused")}, "connection refused"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := blockTime(context.Background(), tc.rpc, 0x2c2a); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestClientBlockTimeNeedsABlockTimer(t *testing.T) {
	c, _ := newFake(t) // fakeBackend has no BlockTime
	if _, err := c.BlockTime(context.Background(), 1); !errors.Is(err, ErrNoBlockTime) {
		t.Fatalf("err %v, want ErrNoBlockTime", err)
	}
	if _, err := (redactingBackend{inner: &fakeBackend{t: t}, r: newRedactor("http://x")}).BlockTime(context.Background(), 1); !errors.Is(err, ErrNoBlockTime) {
		t.Fatalf("redacting backend: %v", err)
	}
}

// TestDialBlockTimeRedactsErrors: the block timestamp read goes through the same URL redaction as every other call.
func TestDialBlockTimeRedactsErrors(t *testing.T) {
	const raw = "http://alice:hunter2@127.0.0.1:1/v2/SECRET-API-KEY?token=abc"
	c, err := Dial(context.Background(), raw, testAddrs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.BlockTime(context.Background(), 7)
	if err == nil || errors.Is(err, ErrNoBlockTime) {
		t.Fatalf("BlockTime on a closed port: %v", err)
	}
	for _, secret := range []string{"SECRET-API-KEY", "token=abc", "hunter2", "alice", "/v2/"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks %q: %v", secret, err)
		}
	}
}
