package lint

import (
	"reflect"
	"testing"
)

// testdata/syft-image/release-scan-excerpt.spdx.json holds packages, verbatim, from real scans with the
// release's syft settings (scripts/release/syft-env.sh, review policy-1): gosu and its modules in
// postgres 16.15, the binary-cataloged postgresql of postgres 17.11-alpine and valkey-server of valkey
// 9.0.7, postgrest v12.2.12's OpenSSL nix output, and in local-model the ollama v0.40.12 binary (a few of
// its modules) and sealed-ollama-gate. Go module licenses come from the module proxy; the packages below
// are what that still leaves without a usable license.
const releaseExcerpt = "testdata/syft-image/release-scan-excerpt.spdx.json"

func TestReleaseScanExcerpt(t *testing.T) {
	raw := readFixture(t, releaseExcerpt)
	if fs := runSBOM(t, raw, compileAll(t, nil, DefaultEnterprisePatterns), nil, true); len(fs) != 0 {
		t.Fatalf("with the reviewed overrides, release lint must pass: %v", fs)
	}
	fs := runSBOM(t, raw, nil, []LicenseOverride{}, true)
	if got, want := fieldsOf(fs, CodeSBOMNoLicense, Error), []string{
		"github.com/ollama/ollama@v0.40.12", "github.com/tianon/gosu@v1.19.0", "openssl-static-x86_64-unknown-linux-musl@3.0.13",
		"postgresql@17.11", "sealed.local/ollama-gate@UNKNOWN", "valkey@9.0.7",
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("no-license without overrides: got %q, want %q", got, want)
	}
	// quic-go's assets/LICENSE.md (its logo policy) is a LicenseRef syft cannot identify.
	if got, want := fieldsOf(fs, CodeSBOMLicense, Error), []string{"github.com/quic-go/quic-go@v0.64.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("license errors without overrides: got %q, want %q", got, want)
	}
}
