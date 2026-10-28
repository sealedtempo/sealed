//go:build sealeddev

package main

import "flag"

// devBuild is true only in binaries built with -tags sealeddev, which are never published as the key broker image.
const devBuild = true

func registerDevFlags(fs *flag.FlagSet, d *devOptions) {
	fs.BoolVar(&d.AllowSimulated, "dev-allow-simulated", false, "DEV ONLY: accept dev simulator quotes; requires SEALED_DEV_SIM=1")
	fs.StringVar(&d.SecretsFile, "dev-secrets-file", "", "DEV ONLY: read secrets from this JSON file instead of Secret Manager; requires SEALED_DEV_SIM=1")
	fs.StringVar(&d.KMSKeyFile, "dev-kms-key-file", "", "DEV ONLY: file-backed HMAC key instead of Cloud KMS (created if missing); requires SEALED_DEV_SIM=1")
	fs.StringVar(&d.DecisionLog, "dev-decision-log", "", "DEV ONLY: append decisions to this JSON-lines file instead of Cloud Logging; requires SEALED_DEV_SIM=1")
}
