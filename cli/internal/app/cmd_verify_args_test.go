package app

import (
	"strings"
	"testing"
)

// envWith returns a minimal Env whose getenv is backed by the given map, so parseVerifyFlags can read
// SEALED_PLATFORM_API without touching the real process environment.
func envWith(env map[string]string) *Env {
	return &Env{Getenv: func(k string) string { return env[k] }}
}

// splitCommand turns a command line like the console builds ("sealed verify 0x...") into the args
// parseVerifyFlags receives, i.e. everything after "sealed verify".
func splitCommand(t *testing.T, command string) []string {
	t.Helper()
	fields := strings.Fields(command)
	if len(fields) < 2 || fields[0] != "sealed" || fields[1] != "verify" {
		t.Fatalf("not a sealed verify command: %q", command)
	}
	return fields[2:]
}

// TestVerifyLonePositionalIsTheDeployment: the exact strings the console and website copy
// (ui console/src/lib/product.ts:50 cli.verify, which builds "sealed verify <id>") parse, with the single
// positional taken as the deployment id, for both a 0x id and a dep_ alias.
func TestVerifyLonePositionalIsTheDeployment(t *testing.T) {
	const id0x = "0x1234567890123456789012345678901234567890123456789012345678901234"
	const alias = "dep_abcd1234"
	for _, id := range []string{id0x, alias} {
		f, err := parseVerifyFlags(envWith(nil), splitCommand(t, "sealed verify "+id))
		if err != nil {
			t.Fatalf("sealed verify %s: unexpected error %v", id, err)
		}
		if f.deployment != id {
			t.Fatalf("sealed verify %s: deployment = %q, want %q", id, f.deployment, id)
		}
	}
}

// TestVerifyPositionalAndDeploymentConflict: giving the id both as the positional argument and with
// --deployment is a usage error, so neither silently wins.
func TestVerifyPositionalAndDeploymentConflict(t *testing.T) {
	const id = "0x1234567890123456789012345678901234567890123456789012345678901234"
	_, err := parseVerifyFlags(envWith(nil), []string{id, "--deployment", id})
	if err == nil {
		t.Fatal("expected a usage error when both the positional and --deployment are given")
	}
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("want a usageError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Fatalf("error does not explain the conflict: %v", err)
	}

	// --deployment on its own still works (the positional form is additive, not a replacement).
	f, err := parseVerifyFlags(envWith(nil), []string{"--deployment", id})
	if err != nil {
		t.Fatalf("--deployment alone: unexpected error %v", err)
	}
	if f.deployment != id {
		t.Fatalf("--deployment alone: deployment = %q, want %q", f.deployment, id)
	}

	// Neither form is a usage error too.
	if _, err := parseVerifyFlags(envWith(nil), nil); err == nil {
		t.Fatal("expected a usage error when no deployment id is given")
	}
	// More than one positional is a usage error.
	if _, err := parseVerifyFlags(envWith(nil), []string{id, id}); err == nil {
		t.Fatal("expected a usage error for two positional arguments")
	}
}

// TestVerifyAPIDefault: --api defaults to the built-in platform URL when neither --api nor SEALED_PLATFORM_API
// is set, falls back to SEALED_PLATFORM_API when that is set, and --api always wins over both.
func TestVerifyAPIDefault(t *testing.T) {
	const id = "dep_abcd1234"

	// Unset: the built-in platform URL.
	f, err := parseVerifyFlags(envWith(nil), []string{id})
	if err != nil {
		t.Fatal(err)
	}
	if f.api != DefaultPlatformAPI {
		t.Fatalf("api with nothing set = %q, want the built-in %q", f.api, DefaultPlatformAPI)
	}
	if f.api == "" {
		t.Fatal("the built-in platform api must not be empty")
	}

	// SEALED_PLATFORM_API set: it is used over the built-in default.
	const fromEnv = "https://api.platform.test"
	f, err = parseVerifyFlags(envWith(map[string]string{"SEALED_PLATFORM_API": fromEnv}), []string{id})
	if err != nil {
		t.Fatal(err)
	}
	if f.api != fromEnv {
		t.Fatalf("api from SEALED_PLATFORM_API = %q, want %q", f.api, fromEnv)
	}

	// --api wins over SEALED_PLATFORM_API and the built-in default.
	const fromFlag = "https://api.flag.test"
	f, err = parseVerifyFlags(envWith(map[string]string{"SEALED_PLATFORM_API": fromEnv}), []string{"--api", fromFlag, id})
	if err != nil {
		t.Fatal(err)
	}
	if f.api != fromFlag {
		t.Fatalf("api from --api = %q, want %q", f.api, fromFlag)
	}
}
