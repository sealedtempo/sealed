// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// identity is image-identity.json: everything about a built image that later steps need, without the disk.
type identity struct {
	Schema          string `json:"schema"`
	Name            string `json:"name"`
	Variant         string `json:"variant"`
	IsDebug         bool   `json:"isDebug"`
	SealedOSVersion string `json:"sealedOsVersion"`
	Upstream        struct {
		Repo   string `json:"repo"`
		Tag    string `json:"tag"`
		Commit string `json:"commit"`
	} `json:"upstream"`
	Source struct {
		Commit string `json:"commit"`
		Tree   string `json:"tree"`
	} `json:"source"`
	OSImageHash string `json:"osImageHash"`
	// UKI is the Authenticode digest of EFI/BOOT/BOOTX64.EFI on the boot disk. SHA256 equals dstack's gcp_uki_auth
	// (the vTPM PCR2 event); SHA384 is what the TDX RTMR1 boot-application event should carry.
	UKI struct {
		AuthenticodeSHA256 string `json:"authenticodeSha256"`
		AuthenticodeSHA384 string `json:"authenticodeSha384"`
	} `json:"uki"`
	GCETarball struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"gceTarball"`
	DiskRawSHA256 string            `json:"diskRawSha256"`
	Files         map[string]string `json:"files"` // sha256 of each identity file under dstack-<version>/
	Metadata      json.RawMessage   `json:"metadata"`
	// VMConfig is the vm_config string for .sys-config.json, built exactly like dstack-cloud _generate_sys_config.
	VMConfig string `json:"vmConfig"`
}

const identitySchema = "sealed-os-identity/v1"

func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// pyJSONString encodes s as Python's json.dumps does for ASCII strings (the only kind used in vm_config).
func pyJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// vmConfig reproduces json.dumps(vm_config) from dstack-cloud: spec_version, os_image_hash, gcp_measurement in
// that order, Python's default ", " and ": " separators.
func vmConfig(osImageHash string, checksumFile, gcpMeasurement []byte) string {
	return fmt.Sprintf(`{"spec_version": 2, "os_image_hash": %s, "gcp_measurement": {"checksum_file": %s, "measurement": %s}}`,
		pyJSONString(osImageHash),
		pyJSONString(base64.StdEncoding.EncodeToString(checksumFile)),
		pyJSONString(base64.StdEncoding.EncodeToString(gcpMeasurement)))
}

// buildIdentity reads an assembled dstack-<version> directory and the outputs build.sh made from it.
func buildIdentity(dir, uki, tarball string) (*identity, error) {
	id := &identity{Schema: identitySchema, Files: map[string]string{}}
	sums, err := os.ReadFile(filepath.Join(dir, "sha256sum.txt"))
	if err != nil {
		return nil, err
	}
	digest, err := os.ReadFile(filepath.Join(dir, "digest.txt"))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(sums)
	id.OSImageHash = hex.EncodeToString(sum[:])
	if strings.TrimSpace(string(digest)) != id.OSImageHash {
		return nil, fmt.Errorf("digest.txt %q is not sha256(sha256sum.txt) %s", strings.TrimSpace(string(digest)), id.OSImageHash)
	}
	gcp, err := os.ReadFile(filepath.Join(dir, "measurement.gcp.cbor"))
	if err != nil {
		return nil, err
	}
	id.VMConfig = vmConfig(id.OSImageHash, sums, gcp)
	meta, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, meta); err != nil {
		return nil, fmt.Errorf("metadata.json: %w", err)
	}
	id.Metadata = compact.Bytes()
	for _, name := range identityFiles {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		h, _, err := sha256File(path)
		if err != nil {
			return nil, err
		}
		id.Files[name] = h
	}
	data, err := os.ReadFile(uki)
	if err != nil {
		return nil, err
	}
	a256, err := authenticode(data, sha256.New)
	if err != nil {
		return nil, fmt.Errorf("UKI: %w", err)
	}
	a384, err := authenticode(data, sha512.New384)
	if err != nil {
		return nil, fmt.Errorf("UKI: %w", err)
	}
	id.UKI.AuthenticodeSHA256 = hex.EncodeToString(a256)
	id.UKI.AuthenticodeSHA384 = hex.EncodeToString(a384)
	// assemble.sh wrote auth_hash.txt with dstack's own implementation; both must agree.
	if want, err := os.ReadFile(filepath.Join(dir, "auth_hash.txt")); err == nil && strings.TrimSpace(string(want)) != id.UKI.AuthenticodeSHA256 {
		return nil, fmt.Errorf("UKI Authenticode %s differs from assemble.sh auth_hash.txt %s", id.UKI.AuthenticodeSHA256, strings.TrimSpace(string(want)))
	}
	if h, _, err := sha256File(filepath.Join(dir, "disk.raw")); err == nil {
		id.DiskRawSHA256 = h
	}
	h, n, err := sha256File(tarball)
	if err != nil {
		return nil, err
	}
	id.GCETarball.File = filepath.Base(tarball)
	id.GCETarball.SHA256 = h
	id.GCETarball.Size = n
	return id, nil
}

// identityFiles are the files of the assembled image that go into the identity tarball (everything but disks).
var identityFiles = []string{
	"digest.txt", "sha256sum.txt", "metadata.json", "auth_hash.txt",
	"measurement.tdx.cbor", "measurement.snp.cbor", "measurement.gcp.cbor",
	"measurement.aws.cbor", "measurement.aws.replay.json",
}

func cmdIdentity(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	dir := fs.String("dir", "", "assembled dstack-<version> directory")
	uki := fs.String("uki", "", "BOOTX64.EFI extracted from the boot disk")
	tarball := fs.String("gce-tarball", "", "GCE import tarball")
	name := fs.String("name", "", "image name")
	variant := fs.String("variant", "", "prod or debug")
	version := fs.String("version", "", "Sealed OS version")
	upRepo := fs.String("upstream-repo", "", "")
	upTag := fs.String("upstream-tag", "", "")
	upCommit := fs.String("upstream-commit", "", "")
	srcCommit := fs.String("source-commit", "", "patched commit the image was built from")
	srcTree := fs.String("source-tree", "", "tree of the patched commit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for flagName, v := range map[string]string{"dir": *dir, "uki": *uki, "gce-tarball": *tarball, "name": *name,
		"version": *version, "source-commit": *srcCommit, "upstream-commit": *upCommit} {
		if v == "" {
			return fmt.Errorf("-%s is required", flagName)
		}
	}
	if *variant != "prod" && *variant != "debug" {
		return errors.New("-variant must be prod or debug")
	}
	id, err := buildIdentity(*dir, *uki, *tarball)
	if err != nil {
		return err
	}
	var meta struct {
		GitRevision string `json:"git_revision"`
		IsDev       bool   `json:"is_dev"`
	}
	if err := json.Unmarshal(id.Metadata, &meta); err != nil {
		return err
	}
	if meta.GitRevision != *srcCommit {
		return fmt.Errorf("metadata.json git_revision %q is not the prepared source commit %s", meta.GitRevision, *srcCommit)
	}
	if meta.IsDev {
		return errors.New("metadata.json is_dev is true: Sealed images are built from the prod flavor only")
	}
	id.Name, id.Variant, id.IsDebug, id.SealedOSVersion = *name, *variant, *variant == "debug", *version
	id.Upstream.Repo, id.Upstream.Tag, id.Upstream.Commit = *upRepo, *upTag, *upCommit
	id.Source.Commit, id.Source.Tree = *srcCommit, *srcTree
	return writeJSON(stdout, id)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func readIdentity(path string) (*identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var id identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if id.Schema != identitySchema {
		return nil, fmt.Errorf("%s: schema %q, want %q", path, id.Schema, identitySchema)
	}
	return &id, nil
}

func cmdNonce(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: osimage nonce")
	}
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, hex.EncodeToString(b[:]))
	return err
}

func parseReportData(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 64 {
		return nil, errors.New("report data must be 64 bytes of hex")
	}
	return b, nil
}

// measureScript runs as the app of a measurement boot (runner "bash"). It asks the guest agent for a TDX quote over
// the given report_data and prints the quote and the firmware event log (RTMR0-2 entries) to the serial console,
// which app-compose.service writes to (StandardOutput=journal+console). It needs no network, no containers and no
// secrets. Lines are chunked and tagged so they survive interleaving with kernel messages, and the END line
// carries sha256 checksums of both payloads.
const measureScript = `set -euo pipefail
rd=@REPORT_DATA@
resp=
for attempt in $(seq 1 60); do
  if resp=$(curl -fsS --unix-socket /var/run/dstack.sock -X POST -H 'Content-Type: application/json' --data "{\"report_data\":\"$rd\"}" http://dstack/GetQuote); then
    break
  fi
  echo "SEALED-MEASURE WAIT $attempt"
  resp=
  sleep 2
done
if [ -z "$resp" ]; then
  echo "SEALED-MEASURE FAIL the guest agent returned no quote"
  exit 1
fi
quote=$(printf '%s' "$resp" | jq -r .quote)
events=$(printf '%s' "$resp" | jq -c '.event_log | fromjson | map(select(.imr < 3))' | base64 -w0)
emit() {
  local tag=$1 data=$2 i=0
  while [ -n "$data" ]; do
    printf 'SEALED-MEASURE %s %05d %s\n' "$tag" "$i" "${data:0:192}"
    data=${data:192}
    i=$((i + 1))
  done
}
echo "SEALED-MEASURE BEGIN v1"
emit Q "$quote"
emit E "$events"
echo "SEALED-MEASURE END $(printf '%s' "$quote" | sha256sum | cut -d' ' -f1) $(printf '%s' "$events" | sha256sum | cut -d' ' -f1)"
`

// measureCompose returns the canonical (sorted keys, compact, no HTML escaping) app-compose.json bytes of a
// measurement boot. Every field is explicit (dstack.md gotcha G6). public_tcbinfo is false: the quote is all we need.
func measureCompose(reportData []byte) ([]byte, error) {
	compose := map[string]any{
		"allowed_envs":               []string{},
		"bash_script":                strings.ReplaceAll(measureScript, "@REPORT_DATA@", hex.EncodeToString(reportData)),
		"gateway_enabled":            false,
		"key_provider":               "none",
		"key_provider_id":            "",
		"kms_enabled":                false,
		"local_key_provider_enabled": false,
		"manifest_version":           2,
		"name":                       "sealed-os-measure",
		"no_instance_id":             false,
		"public_logs":                false,
		"public_sysinfo":             false,
		"public_tcbinfo":             false,
		"runner":                     "bash",
		"secure_time":                false,
		"storage_fs":                 "ext4",
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(compose); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func cmdCompose(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("compose", flag.ContinueOnError)
	rd := fs.String("report-data", "", "64-byte hex report_data the measurement boot quotes over")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reportData, err := parseReportData(*rd)
	if err != nil {
		return err
	}
	b, err := measureCompose(reportData)
	if err != nil {
		return err
	}
	_, err = stdout.Write(b)
	return err
}

// sysConfig is .sys-config.json for a measurement boot: no KMS, no gateway, and the image's vm_config.
func sysConfig(id *identity) ([]byte, error) {
	if id.VMConfig == "" {
		return nil, errors.New("identity has no vmConfig")
	}
	return json.Marshal(map[string]any{
		"kms_urls":     []string{},
		"gateway_urls": []string{},
		"pccs_url":     "",
		"vm_config":    id.VMConfig,
	})
}

func cmdSysConfig(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sys-config", flag.ContinueOnError)
	idPath := fs.String("identity", "", "image-identity.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := readIdentity(*idPath)
	if err != nil {
		return err
	}
	b, err := sysConfig(id)
	if err != nil {
		return err
	}
	_, err = stdout.Write(b)
	return err
}
