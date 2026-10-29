package deploy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/cli/internal/settings"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// TestStackFileMachineTypes: a stack names no machine type (default_machine_type) or one with a registered image
// (D-083, G05). Each image entry is measured on one machine shape and RTMR0 follows the shape, so any other type
// would be denied its keys at first boot, after the wallet approved the stack and the VM exists.
func TestStackFileMachineTypes(t *testing.T) {
	for _, mt := range []string{"", "c3-standard-8"} {
		extra := ""
		if mt != "" {
			extra = "machineType: " + mt + "\n"
		}
		s, err := ParseStackFile([]byte(stackYAML(t, extra)))
		if err != nil || s.MachineType != mt {
			t.Fatalf("machineType %q: %v", mt, err)
		}
	}
	// c3-standard-4 is the relay's shape (D-078), not measured yet; c4 and the larger c3 shapes have no image.
	for _, mt := range []string{"c3-standard-4", "c4-standard-8", "c3-standard-22", "c3-standard-44", "c4-standard-4", "n2-standard-8", "C3-STANDARD-8"} {
		_, err := ParseStackFile([]byte(stackYAML(t, "machineType: "+mt+"\n")))
		if err == nil || !strings.Contains(err.Error(), "D-083") || !strings.Contains(err.Error(), "use c3-standard-8") {
			t.Errorf("machineType %s: %v", mt, err)
		}
	}
}

// TestBuildInstanceConfidentialTypeFromTEE: cloud.tee picks the confidentialInstanceType (G30). An unknown TEE never
// builds a VM.
func TestBuildInstanceConfidentialTypeFromTEE(t *testing.T) {
	p := InstanceParams{Project: "acme-prod-4417", Region: "us-central1", Zone: "us-central1-a", Names: (&StackFile{Name: "demo"}).Names(),
		MachineType: "c3-standard-8", DataDiskSelfLink: "d", DeploymentID: "0x" + strings.Repeat("ab", 32)}
	s, err := settings.Load(settings.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tee := range []string{"", settings.TEEIntelTDX, s.Defaults.Cloud.TEE} {
		p.TEE = tee
		in := BuildInstance(p)
		if in.ConfidentialInstanceConfig.ConfidentialInstanceType != "TDX" || len(CheckInstance(in)) != 0 {
			t.Fatalf("tee %q: %+v %v", tee, in.ConfidentialInstanceConfig, CheckInstance(in))
		}
	}
	for _, tee := range []string{"amd-sev-snp", "amd-sev", "tdx", "Intel-TDX"} {
		p.TEE = tee
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("tee %q built a VM", tee)
				}
			}()
			BuildInstance(p)
		}()
	}
}

// TestCheckInstanceRefusesUnregisteredMachineType: the read-back check refuses a VM of a shape no image is
// registered for, in the form Compute Engine returns the machine type (a URL) and in the form deploy sends it.
func TestCheckInstanceRefusesUnregisteredMachineType(t *testing.T) {
	p := InstanceParams{Project: "acme-prod-4417", Region: "us-central1", Zone: "us-central1-a", Names: (&StackFile{Name: "demo"}).Names(),
		MachineType: "c3-standard-8", DataDiskSelfLink: "d", DeploymentID: "0x" + strings.Repeat("ab", 32)}
	in := BuildInstance(p)
	if problems := CheckInstance(in); len(problems) != 0 {
		t.Fatal(problems)
	}
	in.MachineType = "https://www.googleapis.com/compute/v1/projects/acme-prod-4417/zones/us-central1-a/machineTypes/c3-standard-8"
	if problems := CheckInstance(in); len(problems) != 0 {
		t.Fatal(problems)
	}
	for _, mt := range []string{"zones/us-central1-a/machineTypes/c3-standard-4", "https://www.googleapis.com/compute/v1/projects/acme-prod-4417/zones/us-central1-a/machineTypes/c4-standard-8", ""} {
		in.MachineType = mt
		if problems := CheckInstance(in); len(problems) != 1 || !strings.Contains(problems[0], "has no registered image") {
			t.Errorf("machine type %q: %v", mt, problems)
		}
		if problems := CheckDebugInstance(in, "x@y"); !slices.ContainsFunc(problems, func(s string) bool { return strings.Contains(s, "has no registered image") }) {
			t.Errorf("debug, machine type %q: %v", mt, problems)
		}
	}
}

// TestCheckMachineType: the machine type must be a registered type of cloud.machine_family, and one the stack's image
// entry was measured on, as its version's build metadata names (D-070, D-083).
func TestCheckMachineType(t *testing.T) {
	s, err := settings.Load(settings.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cloud := s.Defaults.Cloud
	img := func(v string) *chain.Image {
		return &chain.Image{Name: "sealed-dstack-os", Version: v, Status: chain.ImageActive}
	}
	for _, ok := range []struct {
		mt  string
		img *chain.Image
	}{
		{"c3-standard-8", img("0.6.1-s1+c3-standard-8")},
		{"c3-standard-8", img("0.6.1-s1+c3-standard-4.c3-standard-8")},
		{"c3-standard-8", img("1.0.0")}, // simulator images of local test chains name no machine type
		{"c3-standard-8", nil},
	} {
		if err := CheckMachineType(ok.mt, ok.img, cloud); err != nil {
			t.Errorf("%s on %+v: %v", ok.mt, ok.img, err)
		}
	}
	for _, bad := range []struct {
		mt   string
		img  *chain.Image
		want string
	}{
		{"c3-standard-8", img("0.6.1-s1+c3-standard-4"), "was measured on c3-standard-4, not on machine type c3-standard-8"},
		{"c3-standard-8", img("0.6.1-s1+c3-standard-22.c3-standard-44"), "was measured on c3-standard-22, c3-standard-44"},
		{"c3-standard-4", img("0.6.1-s1+c3-standard-4"), "not a c3 machine type with a registered image"},
		{"c4-standard-8", img("0.6.1-s1+c4-standard-8"), "not a c3 machine type with a registered image"},
		{"", img("0.6.1-s1+c3-standard-8"), "not a c3 machine type"},
	} {
		if err := CheckMachineType(bad.mt, bad.img, cloud); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%s on %+v: %v, want %q", bad.mt, bad.img, err, bad.want)
		}
	}
	other := cloud
	other.MachineFamily = "c4"
	if err := CheckMachineType("c3-standard-8", img("0.6.1-s1+c3-standard-8"), other); err == nil {
		t.Error("c3-standard-8 accepted for machine_family c4")
	}
}

// TestImageMachineTypesMatchTheOSImageTool: ImageMachineTypes reads the version the measurement tool writes
// (<sealed OS version>+<type>.<type>, runtime/images/dstack-os/tools/osimage/imagejson.go).
func TestImageMachineTypesMatchTheOSImageTool(t *testing.T) {
	for v, want := range map[string][]string{
		"0.6.1-s1+c3-standard-4.c3-standard-8": {"c3-standard-4", "c3-standard-8"},
		"0.6.1-s1+c3-standard-8":               {"c3-standard-8"},
		"0.6.1-s1":                             nil,
		"0.6.1-s1+":                            nil,
		"1.0.0":                                nil,
	} {
		if got := ImageMachineTypes(v); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", v, got, want)
		}
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "runtime", "images", "dstack-os", "tools", "osimage", "imagejson.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `version := id.SealedOSVersion + "+" + strings.Join(g.types, ".")`) {
		t.Fatal("the osimage tool no longer writes <version>+<type>.<type>: update ImageMachineTypes")
	}
}
