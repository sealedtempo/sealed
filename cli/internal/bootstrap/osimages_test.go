package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sealedtempo/sealed/cli/internal/gcp"
)

// --- the system disk ---

// TestSystemDiskIsAValidGPT checks the layout without external tools: protective MBR, both GPT headers and entry
// arrays with correct CRCs, and one Linux filesystem partition named dstack-data from 2048 to the last usable sector.
func TestSystemDiskIsAValidGPT(t *testing.T) {
	d := SystemDiskRaw()
	if len(d) != 10<<20 {
		t.Fatalf("size %d", len(d))
	}
	if d[510] != 0x55 || d[511] != 0xAA || d[446+4] != 0xEE || binary.LittleEndian.Uint32(d[446+8:]) != 1 || binary.LittleEndian.Uint32(d[446+12:]) != 20479 {
		t.Fatalf("protective MBR % x", d[446:462])
	}
	check := func(lba, wantMy, wantAlt, wantEntries uint64) {
		h := append([]byte(nil), d[lba*512:lba*512+92]...)
		if string(h[:8]) != "EFI PART" {
			t.Fatalf("no GPT header at LBA %d", lba)
		}
		crc := binary.LittleEndian.Uint32(h[16:])
		binary.LittleEndian.PutUint32(h[16:], 0)
		if crc32.ChecksumIEEE(h) != crc {
			t.Errorf("header CRC at LBA %d", lba)
		}
		u64 := func(o int) uint64 { return binary.LittleEndian.Uint64(h[o:]) }
		if u64(24) != wantMy || u64(32) != wantAlt || u64(40) != 34 || u64(48) != 20446 || u64(72) != wantEntries {
			t.Errorf("header at LBA %d: my %d alt %d usable %d-%d entries %d", lba, u64(24), u64(32), u64(40), u64(48), u64(72))
		}
		entries := d[wantEntries*512 : wantEntries*512+128*128]
		if crc32.ChecksumIEEE(entries) != binary.LittleEndian.Uint32(h[88:]) {
			t.Errorf("entries CRC of the header at LBA %d", lba)
		}
		e := entries[:128]
		if !bytes.Equal(e[:16], guidBytes(linuxFilesystemGUID)) || binary.LittleEndian.Uint64(e[32:]) != 2048 || binary.LittleEndian.Uint64(e[40:]) != 20446 {
			t.Errorf("partition 1 % x", e[:48])
		}
		if name := string(bytes.ReplaceAll(bytes.TrimRight(e[56:128], "\x00"), []byte{0}, nil)); name != "dstack-data" {
			t.Errorf("partition name %q", name)
		}
		if !bytes.Equal(entries[128:], make([]byte, 127*128)) {
			t.Error("more than one partition")
		}
	}
	check(1, 1, 20479, 2)
	check(20479, 20479, 1, 20447)
	if !bytes.Equal(SystemDiskRaw(), d) {
		t.Fatal("the system disk is not deterministic")
	}
}

// TestSystemDiskEqualsSgdisk: byte for byte the disk `sgdisk -o -n 1:0:0 -t 1:8300 -c 1:dstack-data` makes on a
// 10 MiB file, given the same two GUIDs. Skipped without sgdisk (SEALED_REQUIRE_SGDISK=1 fails instead).
func TestSystemDiskEqualsSgdisk(t *testing.T) {
	if _, err := exec.LookPath("sgdisk"); err != nil {
		if os.Getenv("SEALED_REQUIRE_SGDISK") == "1" {
			t.Fatal("SEALED_REQUIRE_SGDISK=1 but sgdisk is not installed")
		}
		t.Skip("sgdisk not installed")
	}
	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, make([]byte, 10<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sgdisk", "-o", "-n", "1:0:0", "-t", "1:8300", "-c", "1:dstack-data", "-U", systemDiskGUID, "-u", "1:"+systemPartitionGUID, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sgdisk: %v\n%s", err, out)
	}
	want, _ := os.ReadFile(path)
	got := SystemDiskRaw()
	if !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("first difference at byte %d (sector %d): %#x, sgdisk %#x", i, i/512, got[i], want[i])
			}
		}
	}
}

func TestSystemDiskTarball(t *testing.T) {
	tgz, err := SystemDiskTarball()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	h, err := tr.Next()
	if err != nil || h.Name != "disk.raw" || h.Format != tar.FormatGNU {
		t.Fatalf("member %+v %v", h, err)
	}
	body, _ := io.ReadAll(tr)
	if !bytes.Equal(body, SystemDiskRaw()) {
		t.Fatal("tarball content")
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatal("more than one member")
	}
}

// --- names and pins ---

func TestImageNames(t *testing.T) {
	if ImageName(OSImageProd, "0.6.1-s1") != "sealed-dstack-os-0-6-1-s1" || ImageName(OSImageDebug, "0.6.1-s1") != "sealed-dstack-os-debug-0-6-1-s1" {
		t.Fatal(ImageName(OSImageProd, "0.6.1-s1"), ImageName(OSImageDebug, "0.6.1-s1"))
	}
	for _, v := range []string{"0.6.1", "0.6.1-s1", "1.10.0-s12"} {
		if ValidOSImageVersion(v) != nil {
			t.Errorf("%s refused", v)
		}
	}
	for _, v := range []string{"", "latest", "0.6", "0.6.1-s1/../x", "v0.6.1"} {
		if ValidOSImageVersion(v) == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

// TestDefaultOSImageVersionPin: bootstrap imports the OS release the image build pins, under the names it publishes,
// and names and describes boot images exactly as import-and-measure.sh does, so either tool reuses the other's.
func TestDefaultOSImageVersionPin(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "runtime", "images", "dstack-os")
	env, err := os.ReadFile(filepath.Join(dir, "upstream.env"))
	if err != nil {
		t.Fatal(err)
	}
	val := func(k string) string {
		m := regexp.MustCompile(`(?m)^` + k + `=(\S+)$`).FindSubmatch(env)
		if m == nil {
			t.Fatalf("upstream.env has no %s", k)
		}
		return string(m[1])
	}
	if val("SEALED_OS_VERSION") != DefaultOSImageVersion || val("SEALED_IMAGE_NAME_PROD") != OSImageProd || val("SEALED_IMAGE_NAME_DEBUG") != OSImageDebug {
		t.Fatalf("upstream.env pins %s %s %s; bootstrap uses %s %s %s", val("SEALED_OS_VERSION"), val("SEALED_IMAGE_NAME_PROD"), val("SEALED_IMAGE_NAME_DEBUG"), DefaultOSImageVersion, OSImageProd, OSImageDebug)
	}
	script, err := os.ReadFile(filepath.Join(dir, "import-and-measure.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`image_name=${image_name:-$(echo "$name-$version" | tr 'A-Z.+_' 'a-z---')}`,
		`[[ $existing == *"sha256=$want_sha"* ]]`,
		`--guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC`,
		`--description="Sealed dstack OS $name $version ($variant). os_image_hash=$os_image_hash sha256=$want_sha"`,
		`object="$bucket/sealed-os/$image_name.tar.gz"`,
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("import-and-measure.sh no longer has %s; keep osimages.go in step", want)
		}
	}
}

// --- Ensure against fakes ---

type fakeImages struct {
	mu       sync.Mutex
	images   map[string]*gcp.Image
	inserted []gcp.Image
	pending  map[string]int // GetImage answers PENDING this many times before READY
	racers   map[string]*gcp.Image
}

func (f *fakeImages) GetImage(_ context.Context, name string) (*gcp.Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	img, ok := f.images[name]
	if !ok {
		return nil, &gcp.APIError{HTTPStatus: 404}
	}
	c := *img
	if f.pending[name] > 0 {
		f.pending[name]--
		c.Status = "PENDING"
	}
	return &c, nil
}

func (f *fakeImages) InsertImage(_ context.Context, img gcp.Image) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if racer, ok := f.racers[img.Name]; ok {
		// Another run (or the deployer) created the image between our read and our insert.
		f.images[img.Name] = racer
		delete(f.racers, img.Name)
	}
	if _, ok := f.images[img.Name]; ok {
		return &gcp.APIError{HTTPStatus: 409}
	}
	img.Status = "READY"
	f.inserted = append(f.inserted, img)
	f.images[img.Name] = &img
	return nil
}

type fakeUploads struct {
	objects map[string][]byte // bucket/object -> content
}

func (u *fakeUploads) UploadFile(_ context.Context, bucket, object, contentType, path string) (string, error) {
	if contentType != "application/gzip" {
		return "", fmt.Errorf("content type %s", contentType)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	u.objects[bucket+"/"+object] = b
	return "https://storage.googleapis.com/" + bucket + "/" + object, nil
}

type osRelease struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits map[string]int
	tars map[string][]byte // asset name -> served bytes
	// hashes overrides a hashes file by asset name.
	hashes map[string]string
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func newOSRelease(t *testing.T, version string) *osRelease {
	t.Helper()
	r := &osRelease{hits: map[string]int{}, tars: map[string][]byte{}, hashes: map[string]string{}}
	for _, n := range []string{OSImageProd, OSImageDebug} {
		r.tars[n+"-"+version+"-gce.tar.gz"] = []byte("gzip tarball of " + n + " " + version)
	}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		dir := "/releases/download/os-image-v" + version + "/"
		asset, ok := strings.CutPrefix(req.URL.Path, dir)
		if !ok {
			http.NotFound(w, req)
			return
		}
		r.hits[asset]++
		if b, ok := r.tars[asset]; ok {
			w.Write(b)
			return
		}
		if h, ok := r.hashes[asset]; ok {
			io.WriteString(w, h)
			return
		}
		for _, n := range []struct{ name, variant string }{{OSImageProd, "prod"}, {OSImageDebug, "debug"}} {
			base := n.name + "-" + version
			if asset != base+"-hashes.txt" {
				continue
			}
			fmt.Fprintf(w, "image            %s %s (%s)\nsource_commit    %s\nos_image_hash    %s\ngcp_uki_auth     %s\n",
				n.name, version, n.variant, strings.Repeat("c", 40), strings.Repeat("ab", 32), strings.Repeat("0", 64))
			fmt.Fprintf(w, "%s  %s-gce.tar.gz\n%s  %s-identity.tar.gz\n", sha(r.tars[base+"-gce.tar.gz"]), base, strings.Repeat("11", 32), base)
			return
		}
		http.NotFound(w, req)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func newOSImages(t *testing.T, rel *osRelease, imgs *fakeImages, up *fakeUploads) *OSImages {
	return &OSImages{
		Project: "acme-prod-4417", Bucket: "acme-prod-4417-sealed-boot", AssetBase: rel.srv.URL + "/releases/download", Version: "0.6.1-s1",
		Images: imgs, Storage: up, HTTP: rel.srv.Client(), AllowHTTP: true, Dir: filepath.Join(t.TempDir(), "os-images"),
		Sleep: func(time.Duration) {}, PollInterval: time.Second, MaxWait: 5 * time.Second,
	}
}

func newFakes() (*fakeImages, *fakeUploads) {
	return &fakeImages{images: map[string]*gcp.Image{}, pending: map[string]int{}, racers: map[string]*gcp.Image{}}, &fakeUploads{objects: map[string][]byte{}}
}

// TestOSImagesEnsure: bootstrap imports the prod and debug boot images from the release, each tarball checked
// against the release's hashes file, plus the system disk image, and a second run changes nothing.
func TestOSImagesEnsure(t *testing.T) {
	rel := newOSRelease(t, "0.6.1-s1")
	imgs, up := newFakes()
	o := newOSImages(t, rel, imgs, up)
	got, err := o.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []OSImage{
		{Role: "boot", Name: "sealed-dstack-os-0-6-1-s1", Ref: "projects/acme-prod-4417/global/images/sealed-dstack-os-0-6-1-s1", Created: true},
		{Role: "debugBoot", Name: "sealed-dstack-os-debug-0-6-1-s1", Ref: "projects/acme-prod-4417/global/images/sealed-dstack-os-debug-0-6-1-s1", Created: true},
		{Role: "systemDisk", Name: "sealed-dstack-data-v1", Ref: "projects/acme-prod-4417/global/images/sealed-dstack-data-v1", Created: true},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("images %+v", got)
	}
	if len(imgs.inserted) != 3 {
		t.Fatalf("inserted %d images", len(imgs.inserted))
	}
	for i, n := range []struct{ name, variant string }{{OSImageProd, "prod"}, {OSImageDebug, "debug"}} {
		img := imgs.inserted[i]
		tarball := rel.tars[n.name+"-0.6.1-s1-gce.tar.gz"]
		obj := "acme-prod-4417-sealed-boot/sealed-os/" + img.Name + ".tar.gz"
		if !bytes.Equal(up.objects[obj], tarball) || img.RawDisk == nil || img.RawDisk.Source != "https://storage.googleapis.com/"+obj {
			t.Errorf("%s: staged %q from %+v", img.Name, up.objects[obj], img.RawDisk)
		}
		wantDesc := fmt.Sprintf("Sealed dstack OS %s 0.6.1-s1 (%s). os_image_hash=%s sha256=%s", n.name, n.variant, strings.Repeat("ab", 32), sha(tarball))
		if img.Description != wantDesc || img.Labels["sealed-os"] != n.variant || img.Labels["sealed-os-version"] != "0-6-1-s1" ||
			fmt.Sprint(img.GuestOsFeatures) != "[{UEFI_COMPATIBLE} {TDX_CAPABLE} {GVNIC}]" {
			t.Errorf("%s: %+v", img.Name, img)
		}
	}
	sys := imgs.inserted[2]
	sysTar, _ := SystemDiskTarball()
	if !bytes.Equal(up.objects["acme-prod-4417-sealed-boot/sealed-os/sealed-dstack-data-v1.tar.gz"], sysTar) ||
		!strings.HasSuffix(sys.Description, "sha256="+sha(sysTar)) || fmt.Sprint(sys.GuestOsFeatures) != "[{GVNIC}]" {
		t.Errorf("system disk %+v", sys)
	}
	if left, _ := os.ReadDir(o.Dir); len(left) != 0 {
		t.Errorf("downloads left behind: %v", left)
	}

	// Idempotent: nothing is downloaded or imported again.
	before := rel.hits[OSImageProd+"-0.6.1-s1-gce.tar.gz"]
	again, err := o.Ensure(context.Background())
	if err != nil || len(imgs.inserted) != 3 || rel.hits[OSImageProd+"-0.6.1-s1-gce.tar.gz"] != before {
		t.Fatalf("second run: %v, %d inserts, %d downloads", err, len(imgs.inserted), rel.hits[OSImageProd+"-0.6.1-s1-gce.tar.gz"])
	}
	for _, img := range again {
		if img.Created {
			t.Errorf("%s created again", img.Name)
		}
	}
}

// TestOSImagesRefuseBadBytes: a tarball whose sha256 differs from the hashes file is never staged or imported, and
// an existing image made from other bytes stops the bootstrap instead of being used.
func TestOSImagesRefuseBadBytes(t *testing.T) {
	t.Run("tampered tarball", func(t *testing.T) {
		rel := newOSRelease(t, "0.6.1-s1")
		imgs, up := newFakes()
		o := newOSImages(t, rel, imgs, up)
		// The hashes file is computed from the honest bytes; serve others.
		honest := rel.tars[OSImageProd+"-0.6.1-s1-gce.tar.gz"]
		rel.hashes[OSImageProd+"-0.6.1-s1-hashes.txt"] = fmt.Sprintf("image %s 0.6.1-s1 (prod)\nos_image_hash %s\n%s  %s-0.6.1-s1-gce.tar.gz\n", OSImageProd, strings.Repeat("ab", 32), sha(honest), OSImageProd)
		rel.tars[OSImageProd+"-0.6.1-s1-gce.tar.gz"] = []byte("evil bytes")
		_, err := o.Ensure(context.Background())
		if err == nil || !strings.Contains(err.Error(), "has sha256 "+sha([]byte("evil bytes"))) || !strings.Contains(err.Error(), "says "+sha(honest)) {
			t.Fatalf("tampered tarball: %v", err)
		}
		if len(imgs.inserted) != 0 || len(up.objects) != 0 {
			t.Fatalf("imported %d, staged %d", len(imgs.inserted), len(up.objects))
		}
		if left, _ := os.ReadDir(o.Dir); len(left) != 0 {
			t.Errorf("bad download kept: %v", left)
		}
	})
	t.Run("existing image from other bytes", func(t *testing.T) {
		rel := newOSRelease(t, "0.6.1-s1")
		imgs, up := newFakes()
		imgs.images["sealed-dstack-os-0-6-1-s1"] = &gcp.Image{Name: "sealed-dstack-os-0-6-1-s1", Status: "READY", Description: "Sealed dstack OS sealed-dstack-os 0.6.1-s1 (prod). os_image_hash=x sha256=" + strings.Repeat("ee", 32)}
		_, err := newOSImages(t, rel, imgs, up).Ensure(context.Background())
		if err == nil || !strings.Contains(err.Error(), "exists but was not made from") || !strings.Contains(err.Error(), "gcloud compute images delete sealed-dstack-os-0-6-1-s1 --project acme-prod-4417") {
			t.Fatalf("foreign image: %v", err)
		}
		if len(imgs.inserted) != 0 {
			t.Fatal("imported next to a foreign image")
		}
	})
	t.Run("description that only starts with the sha256", func(t *testing.T) {
		rel := newOSRelease(t, "0.6.1-s1")
		imgs, up := newFakes()
		sum := sha(rel.tars[OSImageProd+"-0.6.1-s1-gce.tar.gz"])
		imgs.images["sealed-dstack-os-0-6-1-s1"] = &gcp.Image{Name: "sealed-dstack-os-0-6-1-s1", Status: "READY", Description: "sha256=" + sum + "00"}
		if _, err := newOSImages(t, rel, imgs, up).Ensure(context.Background()); err == nil {
			t.Fatal("a longer hex string was taken for the release sha256")
		}
	})
	t.Run("image created meanwhile", func(t *testing.T) {
		rel := newOSRelease(t, "0.6.1-s1")
		imgs, up := newFakes()
		sum := sha(rel.tars[OSImageProd+"-0.6.1-s1-gce.tar.gz"])
		imgs.racers["sealed-dstack-os-0-6-1-s1"] = &gcp.Image{Name: "sealed-dstack-os-0-6-1-s1", Status: "READY", Description: "sha256=" + strings.Repeat("ee", 32)}
		if _, err := newOSImages(t, rel, imgs, up).Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "created by someone else meanwhile") {
			t.Fatalf("foreign racer: %v", err)
		}
		imgs, up = newFakes()
		imgs.racers["sealed-dstack-os-0-6-1-s1"] = &gcp.Image{Name: "sealed-dstack-os-0-6-1-s1", Status: "READY", Description: "sha256=" + sum}
		if _, err := newOSImages(t, rel, imgs, up).Ensure(context.Background()); err != nil {
			t.Fatalf("a concurrent run with the same tarball: %v", err)
		}
	})
	t.Run("wrong variant or version in the hashes file", func(t *testing.T) {
		for asset, body := range map[string]string{
			OSImageProd + "-0.6.1-s1-hashes.txt":  fmt.Sprintf("image %s 0.6.1-s1 (debug)\nos_image_hash %s\n", OSImageProd, strings.Repeat("ab", 32)),
			OSImageDebug + "-0.6.1-s1-hashes.txt": fmt.Sprintf("image %s 0.6.0-s9 (debug)\nos_image_hash %s\n", OSImageDebug, strings.Repeat("ab", 32)),
		} {
			rel := newOSRelease(t, "0.6.1-s1")
			rel.hashes[asset] = body
			imgs, up := newFakes()
			if _, err := newOSImages(t, rel, imgs, up).Ensure(context.Background()); err == nil {
				t.Errorf("%s accepted", body)
			}
		}
	})
	t.Run("unpublished release", func(t *testing.T) {
		rel := newOSRelease(t, "0.6.1-s1")
		imgs, up := newFakes()
		o := newOSImages(t, rel, imgs, up)
		o.Version = "0.6.2-s1"
		if _, err := o.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "published") {
			t.Fatalf("missing release: %v", err)
		}
	})
	t.Run("plain http release base", func(t *testing.T) {
		rel := newOSRelease(t, "0.6.1-s1")
		imgs, up := newFakes()
		o := newOSImages(t, rel, imgs, up)
		o.AllowHTTP = false
		if _, err := o.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("http base: %v", err)
		}
	})
}

// TestOSImagesWaitsAndKeeps: an image another run is still importing is waited for, a failed one stops with the
// delete command, and a system disk image made by hand is kept.
func TestOSImagesWaitsAndKeeps(t *testing.T) {
	rel := newOSRelease(t, "0.6.1-s1")
	imgs, up := newFakes()
	sum := sha(rel.tars[OSImageProd+"-0.6.1-s1-gce.tar.gz"])
	imgs.images["sealed-dstack-os-0-6-1-s1"] = &gcp.Image{Name: "sealed-dstack-os-0-6-1-s1", Status: "READY", Description: "sha256=" + sum}
	imgs.pending["sealed-dstack-os-0-6-1-s1"] = 2
	imgs.images["sealed-dstack-data-v1"] = &gcp.Image{Name: "sealed-dstack-data-v1", Status: "READY", Description: "made by hand with sgdisk"}
	got, err := newOSImages(t, rel, imgs, up).Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Created || !got[1].Created || got[2].Created || len(imgs.inserted) != 1 || imgs.inserted[0].Name != "sealed-dstack-os-debug-0-6-1-s1" {
		t.Fatalf("images %+v, inserted %d", got, len(imgs.inserted))
	}

	imgs2, up2 := newFakes()
	imgs2.images["sealed-dstack-os-0-6-1-s1"] = &gcp.Image{Name: "sealed-dstack-os-0-6-1-s1", Status: "FAILED"}
	if _, err := newOSImages(t, rel, imgs2, up2).Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to import") {
		t.Fatalf("failed image: %v", err)
	}

	imgs3, up3 := newFakes()
	imgs3.images["sealed-dstack-os-0-6-1-s1"] = &gcp.Image{Name: "sealed-dstack-os-0-6-1-s1", Status: "READY", Description: "sha256=" + sum}
	imgs3.pending["sealed-dstack-os-0-6-1-s1"] = 100
	if _, err := newOSImages(t, rel, imgs3, up3).Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "still PENDING") {
		t.Fatalf("endless PENDING: %v", err)
	}
}
