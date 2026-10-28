package deploy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"

	"github.com/sealed-dev/sealed/cli/internal/fatimg"
	"github.com/sealed-dev/sealed/cli/internal/gcp"
)

// ImageAPI is what GCEShared needs from Compute Engine and Cloud Storage.
type ImageAPI interface {
	GetImage(ctx context.Context, name string) (*gcp.Image, error)
	InsertImage(ctx context.Context, img gcp.Image) error
}

// Uploader stores an object and returns its https URL.
type Uploader interface {
	Upload(ctx context.Context, bucket, object, contentType string, data []byte) (string, error)
}

// GCEShared builds the dstack shared disk as a GCE image: a FAT volume labeled DSTACKSHR with the shared files,
// padded to a whole number of GiB (GCE imports raw disks in GB units), packed as disk.raw in a gzip tarball,
// uploaded to the customer's boot bucket and imported as an image in the customer's project. The image holds only
// public data (the measured app-compose.json and the image's vm_config), so its integrity is checked by the
// measurement, not by access control.
type GCEShared struct {
	Project string
	Bucket  string
	Images  ImageAPI
	Storage Uploader
	// PadTo is the raw disk size; default 1 GiB.
	PadTo int64
}

// Ensure implements SharedDisk.
func (g *GCEShared) Ensure(ctx context.Context, imageName string, files map[string][]byte) (string, error) {
	ref := "projects/" + g.Project + "/global/images/" + imageName
	if img, err := g.Images.GetImage(ctx, imageName); err == nil {
		if img.Status != "" && img.Status != "READY" {
			return "", fmt.Errorf("image %s is %s", imageName, img.Status)
		}
		return ref, nil
	} else if !gcp.IsNotFound(err) {
		return "", err
	}
	if g.Bucket == "" {
		return "", fmt.Errorf("no boot bucket: set bootBucket in the stack file (sealed bootstrap creates <project>-sealed-boot)")
	}
	vol, err := fatimg.Build(files)
	if err != nil {
		return "", err
	}
	tgz, err := RawDiskTarball(vol, g.PadTo)
	if err != nil {
		return "", err
	}
	src, err := g.Storage.Upload(ctx, g.Bucket, imageName+".tar.gz", "application/gzip", tgz)
	if err != nil {
		return "", fmt.Errorf("upload shared disk: %w", err)
	}
	err = g.Images.InsertImage(ctx, gcp.Image{
		Name:            imageName,
		Description:     "dstack shared disk (app-compose.json, .sys-config.json, .instance_info) of a Sealed deployment",
		Labels:          map[string]string{"sealed": "shared-disk"},
		RawDisk:         &gcp.RawDisk{Source: src},
		GuestOsFeatures: []gcp.GuestOsFeature{{Type: "GVNIC"}},
	})
	if err != nil && !gcp.IsConflict(err) {
		return "", fmt.Errorf("import shared disk image: %w", err)
	}
	return ref, nil
}

// RawDiskTarball returns a gzip tarball whose only member is disk.raw: vol followed by zeros up to padTo bytes
// (default 1 GiB). The GNU tar format is the one GCE image import reads.
func RawDiskTarball(vol []byte, padTo int64) ([]byte, error) {
	if padTo == 0 {
		padTo = 1 << 30
	}
	if padTo < int64(len(vol)) {
		return nil, fmt.Errorf("raw disk padding %d is smaller than the volume", padTo)
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	hdr := &tar.Header{Name: "disk.raw", Mode: 0o644, Size: padTo, Format: tar.FormatGNU, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(vol); err != nil {
		return nil, err
	}
	zeros := make([]byte, 1<<20)
	for left := padTo - int64(len(vol)); left > 0; {
		n := int64(len(zeros))
		if left < n {
			n = left
		}
		if _, err := tw.Write(zeros[:n]); err != nil {
			return nil, err
		}
		left -= n
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readRawDisk is the inverse of RawDiskTarball, for tests.
func readRawDisk(tgz []byte) ([]byte, string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, "", err
	}
	tr := tar.NewReader(zr)
	h, err := tr.Next()
	if err != nil {
		return nil, "", err
	}
	b, err := io.ReadAll(tr)
	return b, h.Name, err
}
