// Command pcsrecord records the Intel PCS collateral a TDX quote needs (TCB info, QE identity, PCK CRL, root CA
// CRL) into a collateral cache directory, so tests can verify real quotes offline at a fixed time.
//
//	go run ./verifier/internal/tools/pcsrecord -out verifier/attest/testdata/pcs/<name> <quote.dat>...
//
// It runs the real verifier with a recording cache. Verification errors (for example an expired PCK certificate
// in an old sample quote) are printed but do not stop the recording; the fetch happens before verification.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/sealedtempo/sealed/verifier/attest"
)

func main() {
	out := flag.String("out", "", "collateral cache directory to write")
	flag.Parse()
	if *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: pcsrecord -out DIR QUOTE...")
		os.Exit(2)
	}
	now := time.Now().UTC().Truncate(time.Second)
	getter, err := attest.NewCachingGetter(attest.CacheOptions{
		Dir:   *out,
		TTL:   100 * 365 * 24 * time.Hour,
		Inner: &trust.SimpleHTTPSGetter{},
		Now:   func() time.Time { return now },
	})
	if err != nil {
		fatal(err)
	}
	v, err := attest.NewVerifier(attest.VerifierOptions{
		Getter:    getter,
		TCBPolicy: attest.TCBPolicy{AllowedStatuses: []string{"UpToDate", "SWHardeningNeeded", "OutOfDate", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded", "Revoked", "RelaunchAdvisedConfigurationNeeded"}},
		Now:       func() time.Time { return now },
	})
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, path := range flag.Args() {
		raw, err := os.ReadFile(path)
		if err != nil {
			fatal(err)
		}
		res, err := v.VerifyQuote(ctx, raw)
		if err != nil {
			fmt.Printf("%s: %v\n", path, err)
			continue
		}
		fmt.Printf("%s: verified, TDX TCB %s, QE TCB %s, FMSPC %s, advisories %v\n", path, res.TCBStatus, res.QETCBStatus, res.FMSPC, res.AdvisoryIDs)
	}
	meta, _ := json.MarshalIndent(map[string]any{
		"recordedAt":    now.Unix(),
		"recordedAtUTC": now.Format(time.RFC3339),
		"source":        "Intel PCS (api.trustedservices.intel.com, certificates.trustedservices.intel.com), fetched by pcsrecord",
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "recorded.json"), append(meta, '\n'), 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
