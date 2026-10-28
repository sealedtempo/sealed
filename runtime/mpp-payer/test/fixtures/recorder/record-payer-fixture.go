//go:build ignore

// Command record-payer-fixture serves the real sealed-verifierd HTTP handler over a simulated
// relay world, for recording sealed-mpp-payer's contract fixture. It imports verifier/internal
// packages, so it builds only inside verifier/: copy it to verifier/cmd/record-payer-fixture/ of a
// checkout that has ws/verifier without the build constraint above, `go build` it, then run
// record.mjs (see there).
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/ethereum/go-ethereum/common"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/httpapi"
	"github.com/sealed-dev/sealed/verifier/internal/fixture"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

type offline struct{}

func (offline) Get(string) (map[string][]string, []byte, error) { return nil, nil, errors.New("offline") }

func jsonTags(v any) []string {
	var out []string
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumField(); i++ {
		if tag := t.Field(i).Tag.Get("json"); tag != "" && tag != "-" {
			name := tag
			for j, c := range tag {
				if c == ',' {
					name = tag[:j]
					break
				}
			}
			out = append(out, name)
		}
	}
	return out
}

func main() {
	addrs := chain.Addresses{
		PlatformRegistry:   common.HexToAddress("0x00000000000000000000000000000000000000a1"),
		AppRegistry:        common.HexToAddress("0x00000000000000000000000000000000000000a2"),
		DeploymentRegistry: common.HexToAddress("0x00000000000000000000000000000000000000a3"),
	}
	owner := common.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906")
	w := fixture.NewWorld(4217, addrs, owner, common.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9"), fixture.SimImageID(false))
	w.Apps = []fixture.App{{Slug: "inference-relay", Version: "0.1.0", BundleHash: sha256.Sum256([]byte("bundle inference-relay 0.1.0"))}}
	m := fixture.NewMemChain(4217, addrs)
	b := w.Bundle(m.Now)
	w.Populate(m, b, true)
	q, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: true, Getter: offline{}})
	if err != nil {
		panic(err)
	}
	srv := &httpapi.Server{
		Deps:    verify.Deps{Quotes: q, Chain: m, Composer: fixture.Composer{}, Now: func() time.Time { return time.Unix(int64(m.Now)+5, 0) }},
		ChainID: 4217, LiveTimeout: 5 * time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", srv.Handler())
	mux.HandleFunc("GET /fixture/attest", func(rw http.ResponseWriter, r *http.Request) {
		nonce, err1 := hexb.Decode32(r.URL.Query().Get("nonce"))
		spki, err2 := hexb.Decode32(r.URL.Query().Get("spki"))
		if err := errors.Join(err1, err2); err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		_ = json.NewEncoder(rw).Encode(w.LiveResponse(nonce, spki))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	type liveReqShape struct {
		URL                   string                 `json:"url"`
		Options               httpapi.RequestOptions `json:"options"`
		AttestURL             string                 `json:"attestUrl"`
		Nonce                 string                 `json:"nonce"`
		Attest                json.RawMessage        `json:"attest"`
		ObservedTLSPubKeyHash string                 `json:"observedTlsPubKeyHash"`
		ExpectedCustomer      string                 `json:"expectedCustomer"`
		ExpectedAppIDs        []string               `json:"expectedAppIds"`
	}
	info := map[string]any{
		"base":           "http://" + ln.Addr().String(),
		"relayOwner":     "0x" + fmt.Sprintf("%x", owner.Bytes()),
		"requestFields":  jsonTags(liveReqShape{}),
		"optionFields":   jsonTags(httpapi.RequestOptions{}),
		"reportFields":   jsonTags(verify.Report{}),
		"checkFields":    jsonTags(verify.Check{}),
	}
	_ = json.NewEncoder(os.Stdout).Encode(info)
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); os.Exit(0) }()
	panic(http.Serve(ln, mux))
}
