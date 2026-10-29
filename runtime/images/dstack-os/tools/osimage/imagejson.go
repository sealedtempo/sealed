// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/sealedtempo/sealed/verifier/attest"
)

// catalogImage is one entry of the "images" array contracts/script/RegisterCatalog.s.sol reads. The script uses
// name, version, mrtd, rtmr0-2, isDebug, sourceURI and imageId; the other fields document where the values came
// from and are ignored onchain.
type catalogImage struct {
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	MRTD             string   `json:"mrtd"`
	RTMR0            string   `json:"rtmr0"`
	RTMR1            string   `json:"rtmr1"`
	RTMR2            string   `json:"rtmr2"`
	IsDebug          bool     `json:"isDebug"`
	SourceURI        string   `json:"sourceURI"`
	ImageID          string   `json:"imageId"`
	MeasurementsHash string   `json:"measurementsHash"`
	MachineTypes     []string `json:"machineTypes"`
	Boots            int      `json:"boots"`
	OSImageHash      string   `json:"osImageHash"`
	GCETarballSHA256 string   `json:"gceTarballSha256"`
	Trust            string   `json:"trust"`
	MeasuredAt       string   `json:"measuredAt"`
}

type catalogFile struct {
	Images []catalogImage `json:"images"`
	Sealed struct {
		Schema          string `json:"schema"`
		Variant         string `json:"variant"`
		SealedOSVersion string `json:"sealedOsVersion"`
		SourceCommit    string `json:"sourceCommit"`
		Note            string `json:"note"`
	} `json:"sealed"`
}

// imageID is keccak256(abi.encode(name, version, measurementsHash)) (D-008, INTERFACES.md section 2).
func imageID(name, version string, measurementsHash [32]byte) ([32]byte, error) {
	stringT, err := abi.NewType("string", "", nil)
	if err != nil {
		return [32]byte{}, err
	}
	bytes32T, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return [32]byte{}, err
	}
	enc, err := abi.Arguments{{Type: stringT}, {Type: stringT}, {Type: bytes32T}}.Pack(name, version, measurementsHash)
	if err != nil {
		return [32]byte{}, err
	}
	var id [32]byte
	copy(id[:], crypto.Keccak256(enc))
	return id, nil
}

func decodeMR(s string) (attest.Measurement, error) {
	var m attest.Measurement
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != len(m) {
		return m, fmt.Errorf("measurement %q is not 48 bytes of hex", s)
	}
	copy(m[:], b)
	return m, nil
}

// buildCatalog groups measurement boots into PlatformRegistry images. Every boot of a machine type must give the
// same MRTD and RTMR0-2, otherwise the values are not stable enough to pin and it fails. Machine types with the same
// measurements share one entry, because PlatformRegistry keeps images unique by measurementsHash (CR-5); the version
// carries the machine types as semver build metadata, e.g. 0.6.1-s1+c3-standard-4.c3-standard-8.
func buildCatalog(id *identity, boots []measurement, sourceURI string) (*catalogFile, error) {
	if len(boots) == 0 {
		return nil, errors.New("no measurement boots")
	}
	byType := map[string][]measurement{}
	for _, b := range boots {
		if b.Schema != measurementSchema {
			return nil, fmt.Errorf("measurement schema %q, want %q", b.Schema, measurementSchema)
		}
		if b.OSImageHash != "" && b.OSImageHash != id.OSImageHash {
			return nil, fmt.Errorf("%s boot %d measured os_image_hash %s, not this image's %s", b.MachineType, b.Boot, b.OSImageHash, id.OSImageHash)
		}
		if !b.Quote.Verified {
			return nil, fmt.Errorf("%s boot %d: the quote was not verified against Intel collateral", b.MachineType, b.Boot)
		}
		byType[b.MachineType] = append(byType[b.MachineType], b)
	}
	type group struct {
		types []string
		boots []measurement
	}
	groups := map[string]*group{}
	for mt, list := range byType {
		first := list[0]
		for _, b := range list[1:] {
			if b.MRTD != first.MRTD || b.RTMR0 != first.RTMR0 || b.RTMR1 != first.RTMR1 || b.RTMR2 != first.RTMR2 {
				return nil, fmt.Errorf("%s: boots %d and %d measured different MRTD/RTMR0-2; the image cannot be pinned for it", mt, first.Boot, b.Boot)
			}
		}
		g := groups[first.MeasurementsHash]
		if g == nil {
			g = &group{}
			groups[first.MeasurementsHash] = g
		}
		g.types = append(g.types, mt)
		g.boots = append(g.boots, list...)
	}
	out := &catalogFile{Images: []catalogImage{}}
	out.Sealed.Schema = "sealed-os-image-catalog/v1"
	out.Sealed.Variant = id.Variant
	out.Sealed.SealedOSVersion = id.SealedOSVersion
	out.Sealed.SourceCommit = id.Source.Commit
	out.Sealed.Note = "Trust on first use: MRTD and RTMR0-2 were recorded from first boots of this image on Google Cloud TDX, " +
		"one entry per distinct set of measurements. Use as CATALOG_FILE for contracts/script/RegisterCatalog.s.sol."
	for _, g := range groups {
		sort.Strings(g.types)
		b := g.boots[0]
		var mrs [4]attest.Measurement
		for i, s := range []string{b.MRTD, b.RTMR0, b.RTMR1, b.RTMR2} {
			m, err := decodeMR(s)
			if err != nil {
				return nil, err
			}
			mrs[i] = m
		}
		mh := attest.MeasurementsHash(mrs[0], mrs[1], mrs[2], mrs[3])
		if hex0x(mh[:]) != b.MeasurementsHash {
			return nil, fmt.Errorf("measurementsHash %s does not match the recorded MRs", b.MeasurementsHash)
		}
		version := id.SealedOSVersion + "+" + strings.Join(g.types, ".")
		iid, err := imageID(id.Name, version, mh)
		if err != nil {
			return nil, err
		}
		latest := ""
		for _, x := range g.boots {
			if x.MeasuredAt > latest {
				latest = x.MeasuredAt
			}
		}
		out.Images = append(out.Images, catalogImage{
			Name: id.Name, Version: version,
			MRTD: b.MRTD, RTMR0: b.RTMR0, RTMR1: b.RTMR1, RTMR2: b.RTMR2,
			IsDebug: id.IsDebug, SourceURI: sourceURI,
			ImageID: hex0x(iid[:]), MeasurementsHash: hex0x(mh[:]),
			MachineTypes: g.types, Boots: len(g.boots),
			OSImageHash: id.OSImageHash, GCETarballSHA256: id.GCETarball.SHA256,
			Trust: "tofu", MeasuredAt: latest,
		})
	}
	sort.Slice(out.Images, func(i, j int) bool { return out.Images[i].Version < out.Images[j].Version })
	return out, nil
}

type bootFlags []string

func (b *bootFlags) String() string     { return strings.Join(*b, ",") }
func (b *bootFlags) Set(v string) error { *b = append(*b, v); return nil }

func cmdImageJSON(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("image-json", flag.ContinueOnError)
	idPath := fs.String("identity", "", "image-identity.json of the measured image")
	sourceURI := fs.String("source-uri", "", "public URL of the GCE tarball (default: derived from -release-base)")
	releaseBase := fs.String("release-base", "", "GitHub release download base, e.g. https://github.com/<owner>/<repo>/releases/download")
	var boots bootFlags
	fs.Var(&boots, "boot", "measurement JSON file of one boot (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := readIdentity(*idPath)
	if err != nil {
		return err
	}
	uri := *sourceURI
	if uri == "" {
		if *releaseBase == "" {
			return errors.New("-source-uri or -release-base is required")
		}
		uri = strings.TrimRight(*releaseBase, "/") + "/os-image-v" + id.SealedOSVersion + "/" + id.GCETarball.File
	}
	// The fragment binds the onchain sourceURI to the exact artifact bytes.
	if !strings.Contains(uri, "#") {
		uri += "#sha256=" + id.GCETarball.SHA256
	}
	var list []measurement
	for _, path := range boots {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m measurement
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		list = append(list, m)
	}
	cat, err := buildCatalog(id, list, uri)
	if err != nil {
		return err
	}
	return writeJSON(stdout, cat)
}
