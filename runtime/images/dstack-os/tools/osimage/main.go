// SPDX-License-Identifier: Apache-2.0

// Command osimage holds the build and measurement helpers of the Sealed dstack OS image pipeline
// (runtime/images/dstack-os). build.sh and import-and-measure.sh call it; it never talks to GCP itself.
//
//	osimage authenticode -alg sha256|sha384 FILE    PE/COFF Authenticode digest of the UKI
//	osimage identity -dir D -variant V ...          image-identity.json for a built image
//	osimage nonce                                   64 random bytes as hex (report_data of a measurement boot)
//	osimage compose -report-data HEX                app-compose.json of a measurement boot
//	osimage sys-config -identity FILE               .sys-config.json of a measurement boot
//	osimage measure -serial FILE -report-data HEX   verify the quote a measurement boot printed, extract MRs
//	osimage image-json -identity FILE -boot MT=F    RegisterCatalog images file from measurement results
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "osimage: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: osimage authenticode|identity|nonce|compose|sys-config|measure|image-json [flags]")
	}
	rest := args[1:]
	switch args[0] {
	case "authenticode":
		return cmdAuthenticode(rest, stdout)
	case "identity":
		return cmdIdentity(rest, stdout)
	case "nonce":
		return cmdNonce(rest, stdout)
	case "compose":
		return cmdCompose(rest, stdout)
	case "sys-config":
		return cmdSysConfig(rest, stdout)
	case "measure":
		return cmdMeasure(rest, stdout, stderr)
	case "image-json":
		return cmdImageJSON(rest, stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
