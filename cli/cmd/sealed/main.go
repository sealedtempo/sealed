// Command sealed is the Sealed CLI (spec 8.4): bootstrap a customer project (alias: connect gcp), manage secrets,
// deploy a stack, verify a deployment, browse the catalog and reproduce release bundles.
package main

import (
	"os"

	"github.com/sealed-dev/sealed/cli/internal/app"
)

func main() {
	os.Exit(app.Main(os.Args[1:], app.OSEnv()))
}
