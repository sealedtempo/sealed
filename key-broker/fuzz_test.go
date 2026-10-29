package keybroker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/verify"

	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/runtime/composer/cjson"
	"github.com/sealedtempo/sealed/verifier/attest"
)

// Fuzz targets for what an unauthenticated caller sends the key broker: the
// POST /v1/release body, the TDX quote in it (the PCK gate runs before any
// collateral fetch) and, on the agent side, the HPKE release it gets back.

func fuzzQuotes(f *testing.F) [][]byte {
	var out [][]byte
	for _, name := range []string{"v4_gce_cos113", "v5_sample"} {
		raw, err := os.ReadFile(filepath.Join("testdata", "tdx", "quotes", name+".dat"))
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, raw)
		if trimmed, err := attest.TrimQuote(raw); err == nil && len(trimmed) != len(raw) {
			out = append(out, trimmed)
		}
	}
	return out
}

func releaseBodySeed(f *testing.F, quote []byte) []byte {
	ac := `{"docker_compose_file":"{}","manifest_version":2,"name":"sealed"}`
	stackHash := composer.SHA256([]byte(ac))
	evs := attest.ExpectedRuntimeEvents(attest.RuntimeParams{ComposeHash: stackHash})
	cfgRaw, err := os.ReadFile(filepath.Join("..", "runtime", "composer", "testdata", "config.json"))
	if err != nil {
		f.Fatal(err)
	}
	var cfg any
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		f.Fatal(err)
	}
	h := func(b byte) string { return "0x" + strings.Repeat(hex.EncodeToString([]byte{b}), 32) }
	body := map[string]any{
		"nonce": h(0xab), "ephemeralPub": h(0x41), "imageId": h(0x1d), "quote": "0x" + hex.EncodeToString(quote),
		"eventLog": evs, "config": cfg, "appCompose": ac, "releaseIds": []string{h(0x01), h(0x02)},
	}
	b, err := json.Marshal(body)
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// FuzzReleaseRequest decodes arbitrary POST /v1/release bodies as admit does.
// Properties: no panic; allocation stays within a fixed multiple of the body
// size (the handler caps the body at DefaultMaxBodyBytes); an accepted request
// respects every documented bound and carries canonical JSON for the event log
// and the config, which the broker hashes.
func FuzzReleaseRequest(f *testing.F) {
	for _, q := range fuzzQuotes(f) {
		f.Add(releaseBodySeed(f, q))
	}
	f.Add(releaseBodySeed(f, attest.NewSimQuote(attest.SimQuoteParams{})))
	f.Add([]byte(`{"config":[` + strings.Repeat("0,", 512) + `0]}`))
	f.Add([]byte(`{"nonce":"0x` + strings.Repeat("ab", 32) + `","eventLog":[{"imr":3,"digest":"","event":"x","event_type":1,"event_payload":"","version":1,"extra":1}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > DefaultMaxBodyBytes {
			return
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		m, err := parseEnvelope(body)
		var req *releaseRequest
		if err == nil {
			if _, nerr := requestNonce(m); nerr == nil {
				req, err = parseRequest(m)
			}
		}
		runtime.ReadMemStats(&after)
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > uint64(64*len(body))+256<<10 {
			t.Fatalf("decoding a %d-byte body allocated %d bytes", len(body), alloc)
		}
		if req == nil || err != nil {
			return
		}
		switch {
		case len(req.Quote) > MaxQuoteBytes:
			t.Fatalf("quote of %d bytes accepted", len(req.Quote))
		case len(req.ReleaseIDs) == 0 || len(req.ReleaseIDs) > composer.MaxConfigApps:
			t.Fatalf("%d release ids accepted", len(req.ReleaseIDs))
		case len(req.Config) > composer.MaxConfigBytes:
			t.Fatalf("config of %d bytes accepted", len(req.Config))
		case len(req.AppCompose) == 0 || len(req.AppCompose) > composer.MaxAppComposeBytes:
			t.Fatalf("appCompose of %d bytes accepted", len(req.AppCompose))
		}
		for name, doc := range map[string][]byte{"eventLog": req.EventLog, "config": req.Config} {
			canon, err := cjson.Canonicalize(doc)
			if err != nil || !bytes.Equal(canon, doc) {
				t.Fatalf("%s is not canonical JSON (%v)", name, err)
			}
		}
		var evs []map[string]any
		if err := json.Unmarshal(req.EventLog, &evs); err != nil || len(evs) > MaxEventLogEntries {
			t.Fatalf("event log of %d entries (%v)", len(evs), err)
		}
		// The nonce the broker consumed is the one it releases against.
		if n, _ := requestNonce(m); n != req.Nonce {
			t.Fatal("parsed nonce differs from the consumed nonce")
		}
	})
}

type gateInner struct{ called int }

func (g *gateInner) VerifyQuote(context.Context, []byte) (*attest.QuoteResult, error) {
	g.called++
	return nil, errors.New("inner verifier reached")
}

// FuzzPCKGate feeds arbitrary quote bytes to the PCK gate and readTDConfig.
// Properties: no panic; a non-simulated quote reaches the inner verifier
// (which fetches Intel collateral) only with a PCK certificate chain that
// verifies to the Intel SGX Root CA, and since nobody but Intel can issue one,
// that leaf is one of the seed quotes' leaves; readTDConfig returns fields of
// the TDX sizes or an error.
func FuzzPCKGate(f *testing.F) {
	leaves := map[string]bool{}
	for _, q := range fuzzQuotes(f) {
		f.Add(q)
		if p, err := abi.QuoteToProto(q); err == nil {
			if ch, err := verify.ExtractChainFromQuote(p); err == nil {
				leaves[string(ch.PCKCertificate.Raw)] = true
			}
		}
	}
	f.Add(attest.NewSimQuote(attest.SimQuoteParams{}))
	if len(leaves) == 0 {
		f.Fatal("no PCK leaf in the seed quotes")
	}
	roots, err := IntelRootPool()
	if err != nil {
		f.Fatal(err)
	}
	inner := &gateInner{}
	g := &PCKGate{Inner: inner, Roots: roots}
	f.Fuzz(func(t *testing.T, raw []byte) {
		inner.called = 0
		_, err := g.VerifyQuote(context.Background(), raw)
		if err == nil {
			t.Fatal("gate returned no error although the inner verifier always fails")
		}
		if inner.called > 0 && !attest.IsSimulatedQuote(raw) {
			p, perr := abi.QuoteToProto(raw)
			if perr != nil {
				t.Fatalf("gate passed a quote that does not parse: %v", perr)
			}
			ch, cerr := verify.ExtractChainFromQuote(p)
			if cerr != nil || !leaves[string(ch.PCKCertificate.Raw)] {
				t.Fatalf("gate passed a PCK leaf that is not one of Intel's seed leaves (%v)", cerr)
			}
		}
		if inner.called == 0 && attest.IsSimulatedQuote(raw) {
			t.Fatal("simulated quote did not pass through to the inner verifier")
		}
		td, err := readTDConfig(raw)
		if err != nil {
			return
		}
		if len(td.XFAM) != 8 || len(td.MrConfigID) != 48 || len(td.MrOwner) != 48 || len(td.MrOwnerConfig) != 48 {
			t.Fatalf("readTDConfig field sizes %d %d %d %d", len(td.XFAM), len(td.MrConfigID), len(td.MrOwner), len(td.MrOwnerConfig))
		}
	})
}

type hpkeVector struct {
	RecipientIKM string `json:"recipientIkm"`
	EphemeralPub string `json:"ephemeralPub"`
	Nonce        string `json:"nonce"`
	Plaintext    string `json:"plaintext"`
	Enc          string `json:"enc"`
	Ciphertext   string `json:"ciphertext"`
}

func fuzzHex(f *testing.F, s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// FuzzOpenRelease feeds arbitrary enc, ciphertext and nonce to the agent-side
// decapsulation with the fixed vector key. Properties: no panic for any
// length; only the exact sealed (enc, ciphertext, nonce) opens, to exactly
// its plaintext. SealRelease never panics on any ephemeral public key.
func FuzzOpenRelease(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("testdata", "hpke-kb-release-vector.json"))
	if err != nil {
		f.Fatal(err)
	}
	var v hpkeVector
	if err := json.Unmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	priv, pub, err := DeriveEphemeralKey(fuzzHex(f, v.RecipientIKM))
	if err != nil {
		f.Fatal(err)
	}
	type sealed struct{ enc, ct, nonce, pt []byte }
	var good []sealed
	good = append(good, sealed{fuzzHex(f, v.Enc), fuzzHex(f, v.Ciphertext), fuzzHex(f, v.Nonce), []byte(v.Plaintext)})
	for i, pt := range [][]byte{nil, []byte("{}"), bytes.Repeat([]byte("x"), 300)} {
		nonce := [32]byte{byte(i), 0xab}
		enc, ct, err := SealRelease(pub, nonce, pt)
		if err != nil {
			f.Fatal(err)
		}
		good = append(good, sealed{enc, ct, nonce[:], pt})
	}
	for _, g := range good {
		f.Add(g.enc, g.ct, g.nonce)
	}
	var low [32]byte // the all-zero point has small order
	f.Add(low[:], []byte{}, low[:])
	f.Fuzz(func(t *testing.T, enc, ct, nonceBytes []byte) {
		var nonce [32]byte
		copy(nonce[:], nonceBytes)
		pt, err := OpenRelease(priv, nonce, enc, ct)
		if err == nil {
			ok := false
			for _, g := range good {
				if bytes.Equal(g.enc, enc) && bytes.Equal(g.ct, ct) && bytes.Equal(g.nonce, nonce[:]) && bytes.Equal(g.pt, pt) {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("a modified release opened: enc %x ct %x nonce %x -> %q", enc, ct, nonce, pt)
			}
		}
		// The broker side: any 32 bytes as the agent's ephemeral key.
		var eph [32]byte
		copy(eph[:], enc)
		if e2, c2, err := SealRelease(eph, nonce, ct); err == nil {
			if len(e2) != 32 || len(c2) != len(ct)+16 {
				t.Fatalf("SealRelease sizes enc %d ct %d for %d plaintext bytes", len(e2), len(c2), len(ct))
			}
		} else if !errors.Is(err, ErrBadEphemeralKey) {
			t.Fatalf("SealRelease error not classified: %v", err)
		}
	})
}
