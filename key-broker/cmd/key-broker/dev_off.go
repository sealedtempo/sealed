//go:build !sealeddev

package main

import "flag"

// devBuild is false in the production build: no dev flag exists, and simulated quotes and local fakes cannot be
// enabled by any flag or environment variable.
const devBuild = false

func registerDevFlags(*flag.FlagSet, *devOptions) {}
