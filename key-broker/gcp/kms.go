package gcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
)

// DefaultKMSEndpoint is the Cloud KMS REST API.
const DefaultKMSEndpoint = "https://cloudkms.googleapis.com"

var (
	cryptoKeyRe        = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)
	cryptoKeyVersionRe = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+$`)
)

// KMSKeyVersion returns the cryptoKeyVersion resource name for key, which is either a full cryptoKeyVersions name or a
// cryptoKeys name (then version is used). MAC keys have no primary version, so macSign always names one. The
// bootstrap creates version 1 and must never rotate or destroy it: diskKey and signerSeed depend on it.
func KMSKeyVersion(key, version string) (string, error) {
	switch {
	case cryptoKeyVersionRe.MatchString(key):
		return key, nil
	case cryptoKeyRe.MatchString(key):
		if _, err := strconv.ParseUint(version, 10, 32); err != nil || version == "0" {
			return "", fmt.Errorf("gcp: KMS key version %q is not a positive integer", version)
		}
		return key + "/cryptoKeyVersions/" + version, nil
	}
	return "", fmt.Errorf("gcp: %q is not a Cloud KMS cryptoKey or cryptoKeyVersion name", key)
}

// KMSMAC computes HMAC-SHA256 with a Cloud KMS MAC key version (purpose MAC, algorithm HMAC_SHA256), so the key
// never leaves KMS (D-011). The broker's service account has roles/cloudkms.signerVerifier on this one key.
type KMSMAC struct {
	KeyVersion string
	Endpoint   string // empty means DefaultKMSEndpoint
	Tokens     TokenSource
	Client     *http.Client
}

// NewKMSMAC validates the key version name.
func NewKMSMAC(keyVersion string, tokens TokenSource) (*KMSMAC, error) {
	if !cryptoKeyVersionRe.MatchString(keyVersion) {
		return nil, fmt.Errorf("gcp: %q is not a cryptoKeyVersion name", keyVersion)
	}
	if tokens == nil {
		return nil, errors.New("gcp: no token source")
	}
	return &KMSMAC{KeyVersion: keyVersion, Tokens: tokens}, nil
}

// MAC implements keybroker.MACSigner with cryptoKeyVersions.macSign. Request and response integrity are checked with
// CRC32C as Google recommends.
func (k *KMSMAC) MAC(ctx context.Context, data []byte) ([]byte, error) {
	ep := k.Endpoint
	if ep == "" {
		ep = DefaultKMSEndpoint
	}
	in := map[string]string{
		"data":       base64.StdEncoding.EncodeToString(data),
		"dataCrc32c": strconv.FormatUint(uint64(crc32c(data)), 10),
	}
	var out struct {
		Name               string `json:"name"`
		Mac                string `json:"mac"`
		MacCrc32c          string `json:"macCrc32c"`
		VerifiedDataCrc32c bool   `json:"verifiedDataCrc32c"`
	}
	if err := call(ctx, k.Client, k.Tokens, "cloudkms", http.MethodPost, ep+"/v1/"+k.KeyVersion+":macSign", in, &out); err != nil {
		return nil, err
	}
	if out.Name != k.KeyVersion {
		return nil, fmt.Errorf("cloudkms: macSign answered for %q, asked %q", out.Name, k.KeyVersion)
	}
	if !out.VerifiedDataCrc32c {
		return nil, errors.New("cloudkms: macSign did not verify the request checksum")
	}
	mac, err := base64.StdEncoding.DecodeString(out.Mac)
	if err != nil {
		return nil, errors.New("cloudkms: mac is not base64")
	}
	want, err := strconv.ParseUint(out.MacCrc32c, 10, 32)
	if err != nil || uint32(want) != crc32c(mac) {
		return nil, errors.New("cloudkms: mac checksum mismatch")
	}
	if len(mac) != 32 {
		return nil, fmt.Errorf("cloudkms: mac is %d bytes; the key must be HMAC_SHA256", len(mac))
	}
	return mac, nil
}
