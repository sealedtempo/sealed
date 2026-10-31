package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/sealedtempo/sealed/cli/internal/deploy"
	"github.com/sealedtempo/sealed/cli/internal/gcp"
)

// Boot and system disk images (D-075). Each deploying project holds its own copies: `sealed bootstrap` creates them
// with the customer's own credentials after the module is applied, so the deployer only ever uses sealed-* images
// of its own project.

// DefaultOSImageVersion is the Sealed dstack OS release bootstrap imports: SEALED_OS_VERSION in
// runtime/images/dstack-os/upstream.env (TestDefaultOSImageVersionPin keeps the two equal). Its release tag is
// os-image-v<version>.
const DefaultOSImageVersion = "0.6.1-s4"

// The OS image names in PlatformRegistry and in the release asset names (SEALED_IMAGE_NAME_PROD and
// SEALED_IMAGE_NAME_DEBUG), and the system disk image every deployment's dstack system disk is created from.
const (
	OSImageProd     = "sealed-dstack-os"
	OSImageDebug    = "sealed-dstack-os-debug"
	SystemDiskImage = "sealed-dstack-data-v1"
)

var (
	osVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-s[0-9]+)?$`)
	sha256Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	descSHARe   = regexp.MustCompile(`sha256=([0-9a-f]{64})\b`)
)

// ValidOSImageVersion checks --os-image-version.
func ValidOSImageVersion(v string) error {
	if !osVersionRe.MatchString(v) {
		return fmt.Errorf("--os-image-version %q is not an OS image version like %s", v, DefaultOSImageVersion)
	}
	return nil
}

// ImageName is the GCE image name of an OS release: name-version, lowercase, with dots, plus signs and underscores
// as dashes (the rule of runtime/images/dstack-os/import-and-measure.sh, so images it made are reused).
func ImageName(name, version string) string {
	return strings.ToLower(strings.NewReplacer(".", "-", "+", "-", "_", "-").Replace(name + "-" + version))
}

// ImageAPI is what OSImages needs from Compute Engine (gcp.Compute implements it).
type ImageAPI interface {
	GetImage(ctx context.Context, name string) (*gcp.Image, error)
	InsertImage(ctx context.Context, img gcp.Image) error
}

// FileUploader stores a local file in Cloud Storage and returns its https URL (gcp.Storage implements it).
type FileUploader interface {
	UploadFile(ctx context.Context, bucket, object, contentType, path string) (string, error)
}

// OSImages creates the boot images of one OS release (prod and debug) and the system disk image in a project.
type OSImages struct {
	Project string
	// Bucket stages the tarballs: the boot bucket, which only the customer's own credentials can write.
	Bucket string
	// AssetBase is the release asset base; the OS release is <AssetBase>/os-image-v<Version>/.
	AssetBase string
	Version   string
	Images    ImageAPI
	Storage   FileUploader
	// HTTP fetches the release assets. Nil: a client without an overall timeout that refuses non-https redirects.
	HTTP *http.Client
	// AllowHTTP accepts a plain http AssetBase (tests).
	AllowHTTP bool
	// Dir holds the downloads; each tarball is removed once its image exists.
	Dir string
	Log func(format string, a ...any)
	// PollInterval and MaxWait bound the wait for an image another run is still importing (defaults 10 s, 30 min).
	PollInterval time.Duration
	MaxWait      time.Duration
	Sleep        func(time.Duration)
}

// OSImage is one image bootstrap made sure of.
type OSImage struct {
	Role    string // "boot", "debugBoot" or "systemDisk"
	Name    string
	Ref     string // projects/<project>/global/images/<name>, the stack file's image.boot or image.systemDisk
	Created bool   // false when it was already there
}

// Planned lists the images Ensure creates, for --plan.
func (o *OSImages) Planned() []string {
	return []string{ImageName(OSImageProd, o.Version), ImageName(OSImageDebug, o.Version), SystemDiskImage}
}

// ReleaseURL is the directory of the OS release's assets.
func (o *OSImages) ReleaseURL() string {
	return strings.TrimRight(o.AssetBase, "/") + "/os-image-v" + o.Version
}

func (o *OSImages) logf(format string, a ...any) {
	if o.Log != nil {
		o.Log(format, a...)
	}
}

// Ensure makes sure the prod and debug boot images and the system disk image exist. It is idempotent: an image
// whose description names the release's tarball is kept, one whose description names other bytes stops it, and an
// interrupted run continues. An image the deployer forged with a copied description is not caught here (the
// rawDisk source is not returned when an image is read back); the key broker still refuses it on measurement.
func (o *OSImages) Ensure(ctx context.Context) ([]OSImage, error) {
	if o.Project == "" || o.Bucket == "" || o.Images == nil || o.Storage == nil {
		return nil, errors.New("OS images need the project, its boot bucket and Compute Engine and Cloud Storage clients")
	}
	if err := ValidOSImageVersion(o.Version); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(o.AssetBase, "https://") && !(o.AllowHTTP && strings.HasPrefix(o.AssetBase, "http://")) {
		return nil, fmt.Errorf("the OS image release base %q must be an https URL", o.AssetBase)
	}
	var out []OSImage
	for _, r := range []struct{ role, name, variant string }{{"boot", OSImageProd, "prod"}, {"debugBoot", OSImageDebug, "debug"}} {
		img, err := o.ensureRelease(ctx, r.name, r.variant)
		if err != nil {
			return out, err
		}
		img.Role = r.role
		out = append(out, img)
	}
	img, err := o.ensureSystemDisk(ctx)
	if err != nil {
		return out, err
	}
	return append(out, img), nil
}

func (o *OSImages) ref(name string) string { return "projects/" + o.Project + "/global/images/" + name }

// release is what the hashes file of one OS image says.
type release struct {
	variant     string
	osImageHash string
	sums        map[string]string // asset file name -> sha256
}

// parseHashes reads <name>-<version>-hashes.txt (runtime/images/dstack-os/build.sh): an "image <name> <version>
// (<variant>)" line, "os_image_hash <hex>", and sha256sum lines for the published assets.
func parseHashes(text, name, version string) (*release, error) {
	r := &release{sums: map[string]string{}}
	seen := false
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "image" && len(f) == 4:
			if f[1] != name || f[2] != version {
				return nil, fmt.Errorf("the hashes file is for %s %s, not %s %s", f[1], f[2], name, version)
			}
			r.variant, seen = strings.Trim(f[3], "()"), true
		case f[0] == "os_image_hash" && len(f) == 2:
			r.osImageHash = f[1]
		case len(f) == 2 && sha256Re.MatchString(f[0]):
			r.sums[strings.TrimPrefix(f[1], "*")] = f[0]
		}
	}
	if !seen {
		return nil, fmt.Errorf("the hashes file names no image line for %s %s", name, version)
	}
	if !sha256Re.MatchString(r.osImageHash) {
		return nil, fmt.Errorf("the hashes file of %s %s has no os_image_hash", name, version)
	}
	return r, nil
}

func (o *OSImages) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing a redirect to %s://%s", req.URL.Scheme, req.URL.Host)
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}}
}

func (o *OSImages) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch %s: HTTP %d (is the OS image release %s published?)", u, resp.StatusCode, o.Version)
	}
	return resp, nil
}

const maxHashesFile = 1 << 20

func (o *OSImages) fetchSmall(ctx context.Context, u string) (string, error) {
	resp, err := o.get(ctx, u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxHashesFile+1))
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", u, err)
	}
	if len(b) > maxHashesFile {
		return "", fmt.Errorf("fetch %s: larger than %d bytes", u, maxHashesFile)
	}
	return string(b), nil
}

// maxTarball bounds a download; the release tarballs are about 330 MB.
const maxTarball = 8 << 30

// download stores u in Dir while hashing it, and keeps the file only when its sha256 is want.
func (o *OSImages) download(ctx context.Context, u, asset, want string) (string, error) {
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return "", err
	}
	resp, err := o.get(ctx, u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.CreateTemp(o.Dir, asset+".*.partial")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxTarball+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxTarball {
		err = fmt.Errorf("larger than %d bytes", int64(maxTarball))
	}
	if err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("download %s: %w", u, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(f.Name())
		return "", fmt.Errorf("%s has sha256 %s, but the release's hashes file says %s: nothing was imported", asset, got, want)
	}
	return f.Name(), nil
}

// existing returns the image when it exists and is READY (waiting while another run imports it), nil when it does
// not exist.
func (o *OSImages) existing(ctx context.Context, name string) (*gcp.Image, error) {
	interval, maxWait := o.PollInterval, o.MaxWait
	if interval == 0 {
		interval = 10 * time.Second
	}
	if maxWait == 0 {
		maxWait = 30 * time.Minute
	}
	sleep := o.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for waited := time.Duration(0); ; waited += interval {
		img, err := o.Images.GetImage(ctx, name)
		if gcp.IsNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read image %s: %w", name, err)
		}
		switch img.Status {
		case "", "READY":
			return img, nil
		case "FAILED":
			return nil, fmt.Errorf("image %s failed to import: delete it (gcloud compute images delete %s --project %s) and run sealed bootstrap again", name, name, o.Project)
		}
		if waited >= maxWait {
			return nil, fmt.Errorf("image %s is still %s after %s", name, img.Status, maxWait)
		}
		if waited == 0 {
			o.logf("Image %s is %s; waiting for it.\n", name, img.Status)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sleep(interval)
	}
}

func madeFrom(img *gcp.Image, sum string) bool {
	for _, m := range descSHARe.FindAllStringSubmatch(img.Description, -1) {
		if m[1] == sum {
			return true
		}
	}
	return false
}

// insert uploads path and imports it as img, then reads the image back. A concurrent run that created it first is
// fine when its image is READY and, when want is set, was made from the same tarball.
func (o *OSImages) insert(ctx context.Context, img gcp.Image, path, want string) error {
	src, err := o.Storage.UploadFile(ctx, o.Bucket, "sealed-os/"+img.Name+".tar.gz", "application/gzip", path)
	if err != nil {
		return fmt.Errorf("upload %s to gs://%s: %w", img.Name, o.Bucket, err)
	}
	img.RawDisk = &gcp.RawDisk{Source: src}
	if err := o.Images.InsertImage(ctx, img); err != nil && !gcp.IsConflict(err) {
		return fmt.Errorf("import image %s: %w", img.Name, err)
	}
	got, err := o.existing(ctx, img.Name)
	if err != nil {
		return err
	}
	if got == nil {
		return fmt.Errorf("image %s is missing after its import", img.Name)
	}
	if want != "" && !madeFrom(got, want) {
		return fmt.Errorf("image %s was created by someone else meanwhile, not from sha256 %s (its description is %q)", img.Name, want, got.Description)
	}
	return nil
}

func (o *OSImages) ensureRelease(ctx context.Context, name, variant string) (OSImage, error) {
	base := name + "-" + o.Version
	hashesURL := o.ReleaseURL() + "/" + base + "-hashes.txt"
	text, err := o.fetchSmall(ctx, hashesURL)
	if err != nil {
		return OSImage{}, err
	}
	rel, err := parseHashes(text, name, o.Version)
	if err != nil {
		return OSImage{}, fmt.Errorf("%s: %w", hashesURL, err)
	}
	if rel.variant != variant {
		return OSImage{}, fmt.Errorf("%s: %s is the %s variant, want %s", hashesURL, name, rel.variant, variant)
	}
	asset := base + "-gce.tar.gz"
	want := rel.sums[asset]
	if want == "" {
		return OSImage{}, fmt.Errorf("%s lists no sha256 for %s", hashesURL, asset)
	}
	imageName := ImageName(name, o.Version)
	out := OSImage{Name: imageName, Ref: o.ref(imageName)}
	img, err := o.existing(ctx, imageName)
	if err != nil {
		return out, err
	}
	if img != nil {
		if !madeFrom(img, want) {
			return out, fmt.Errorf("image %s exists but was not made from %s (sha256 %s; its description is %q): delete it (gcloud compute images delete %s --project %s) and run sealed bootstrap again",
				imageName, asset, want, img.Description, imageName, o.Project)
		}
		o.logf("Boot image %s is in place (sha256 %s).\n", imageName, want)
		return out, nil
	}
	o.logf("Downloading %s and checking its sha256 against %s.\n", asset, base+"-hashes.txt")
	path, err := o.download(ctx, o.ReleaseURL()+"/"+asset, asset, want)
	if err != nil {
		return out, err
	}
	defer os.Remove(path)
	o.logf("Importing %s into %s (this takes a few minutes).\n", imageName, o.Project)
	versionLabel := strings.ToLower(strings.NewReplacer(".", "-", "+", "-").Replace(o.Version))
	err = o.insert(ctx, gcp.Image{
		Name:        imageName,
		Description: fmt.Sprintf("Sealed dstack OS %s %s (%s). os_image_hash=%s sha256=%s", name, o.Version, variant, rel.osImageHash, want),
		Labels:      map[string]string{"sealed-os": variant, "sealed-os-version": versionLabel},
		GuestOsFeatures: []gcp.GuestOsFeature{
			{Type: "UEFI_COMPATIBLE"}, {Type: "TDX_CAPABLE"}, {Type: "GVNIC"},
		},
	}, path, want)
	if err != nil {
		return out, err
	}
	out.Created = true
	return out, nil
}

func (o *OSImages) ensureSystemDisk(ctx context.Context) (OSImage, error) {
	out := OSImage{Role: "systemDisk", Name: SystemDiskImage, Ref: o.ref(SystemDiskImage)}
	tgz, err := SystemDiskTarball()
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(tgz)
	want := hex.EncodeToString(sum[:])
	img, err := o.existing(ctx, SystemDiskImage)
	if err != nil {
		return out, err
	}
	if img != nil {
		// Its content is not measured: dstack grows the partition and sets up LUKS on it at first boot, so an
		// image made by hand with sgdisk (other GUIDs) serves as well.
		if madeFrom(img, want) {
			o.logf("System disk image %s is in place.\n", SystemDiskImage)
		} else {
			o.logf("System disk image %s is in place (not made by sealed bootstrap; kept).\n", SystemDiskImage)
		}
		return out, nil
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return out, err
	}
	path := filepath.Join(o.Dir, SystemDiskImage+".tar.gz")
	if err := os.WriteFile(path, tgz, 0o600); err != nil {
		return out, err
	}
	defer os.Remove(path)
	o.logf("Importing the system disk image %s into %s.\n", SystemDiskImage, o.Project)
	err = o.insert(ctx, gcp.Image{
		Name:            SystemDiskImage,
		Description:     "dstack system disk of Sealed deployments: an empty 10 MiB GPT disk with one partition named dstack-data. sha256=" + want,
		Labels:          map[string]string{"sealed": "system-disk"},
		GuestOsFeatures: []gcp.GuestOsFeature{{Type: "GVNIC"}},
	}, path, "")
	if err != nil {
		return out, err
	}
	out.Created = true
	return out, nil
}

// The dstack system disk (D-075): 10 MiB with a GPT that holds one Linux filesystem partition named dstack-data,
// from sector 2048 to the last usable sector. That is the layout of `sgdisk -o -n 1:0:0 -c 1:dstack-data` on a
// 10 MiB file, the disk dstack's own CLI and import-and-measure.sh boot with. dstack finds the partition by its
// name, grows it to the disk and sets up LUKS on it at first boot. The GUIDs are fixed, so every project gets the
// same bytes.
const (
	sectorSize      = 512
	systemDiskBytes = 10 << 20
	gptEntries      = 128
	gptEntrySize    = 128
	partitionStart  = 2048
	// linuxFilesystemGUID is sgdisk's type code 8300.
	linuxFilesystemGUID = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
	systemDiskGUID      = "37D06A02-5D8A-441E-9088-8F75F9459C8D"
	systemPartitionGUID = "D1D8825B-A5E4-4CFE-9487-7CC21D61D675"
	systemPartitionName = "dstack-data"
)

// guidBytes encodes a GUID the way GPT stores it: the first three fields little-endian.
func guidBytes(s string) []byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		panic("bad GUID " + s)
	}
	b := append([]byte(nil), raw...)
	b[0], b[1], b[2], b[3] = raw[3], raw[2], raw[1], raw[0]
	b[4], b[5] = raw[5], raw[4]
	b[6], b[7] = raw[7], raw[6]
	return b
}

// chs is the MBR cylinder-head-sector address of lba for 255 heads and 63 sectors per track, or the "too big"
// marker beyond 1024 cylinders.
func chs(lba uint64) []byte {
	const heads, sectors = 255, 63
	if lba >= 1024*heads*sectors {
		return []byte{0xFF, 0xFF, 0xFF}
	}
	c, rem := lba/(heads*sectors), lba%(heads*sectors)
	h, sec := rem/sectors, rem%sectors+1
	return []byte{byte(h), byte(sec) | byte((c>>2)&0xC0), byte(c)}
}

// SystemDiskRaw returns the system disk's disk.raw.
func SystemDiskRaw() []byte {
	total := uint64(systemDiskBytes / sectorSize)
	entrySectors := uint64(gptEntries * gptEntrySize / sectorSize)
	firstUsable, lastUsable := 2+entrySectors, total-2-entrySectors
	disk := make([]byte, systemDiskBytes)

	// Protective MBR: one partition of type 0xEE over the whole disk, with CHS addresses as sgdisk writes them.
	mbr := disk[446:462]
	copy(mbr[1:4], chs(1))
	mbr[4] = 0xEE
	copy(mbr[5:8], chs(total-1))
	binary.LittleEndian.PutUint32(mbr[8:], 1)
	binary.LittleEndian.PutUint32(mbr[12:], uint32(total-1))
	disk[510], disk[511] = 0x55, 0xAA

	entries := make([]byte, gptEntries*gptEntrySize)
	copy(entries[0:], guidBytes(linuxFilesystemGUID))
	copy(entries[16:], guidBytes(systemPartitionGUID))
	binary.LittleEndian.PutUint64(entries[32:], partitionStart)
	binary.LittleEndian.PutUint64(entries[40:], lastUsable)
	for i, c := range utf16.Encode([]rune(systemPartitionName)) {
		binary.LittleEndian.PutUint16(entries[56+2*i:], c)
	}
	entriesCRC := crc32.ChecksumIEEE(entries)

	header := func(my, alternate, entriesLBA uint64) []byte {
		h := make([]byte, 92)
		copy(h, "EFI PART")
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], my)
		binary.LittleEndian.PutUint64(h[32:], alternate)
		binary.LittleEndian.PutUint64(h[40:], firstUsable)
		binary.LittleEndian.PutUint64(h[48:], lastUsable)
		copy(h[56:], guidBytes(systemDiskGUID))
		binary.LittleEndian.PutUint64(h[72:], entriesLBA)
		binary.LittleEndian.PutUint32(h[80:], gptEntries)
		binary.LittleEndian.PutUint32(h[84:], gptEntrySize)
		binary.LittleEndian.PutUint32(h[88:], entriesCRC)
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
		return h
	}
	backupEntries := total - 1 - entrySectors
	copy(disk[1*sectorSize:], header(1, total-1, 2))
	copy(disk[2*sectorSize:], entries)
	copy(disk[backupEntries*sectorSize:], entries)
	copy(disk[(total-1)*sectorSize:], header(total-1, 1, backupEntries))
	return disk
}

// SystemDiskTarball returns the system disk in the GCE import format: a gzip GNU tar whose only member is disk.raw.
func SystemDiskTarball() ([]byte, error) {
	raw := SystemDiskRaw()
	return deploy.RawDiskTarball(raw, int64(len(raw)))
}
