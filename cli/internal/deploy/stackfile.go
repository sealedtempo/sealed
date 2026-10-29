// Package deploy implements `sealed deploy --config stack.yaml` (spec 8.4): the customer deploys with their own
// credentials and no console. It resolves the releases onchain, fetches their bundles by bundleHash, composes
// the stack with runtime/composer, refuses to continue until the customer's wallet approved exactly that stack
// (D-014), and creates the confidential VM through the Compute Engine API with no service account, no scopes, OS
// Login and the serial port off, project SSH keys blocked, a persistent data disk and a static IP (spec 5.9).
//
// The data disk and the enclave signer follow the salt (D-058): the key broker derives the disk key and the
// signer seed from (customer, salt), so an upgrade (new releases or a changed config, same salt) keeps both, and a
// new salt means a fresh disk. The salt defaults to a value derived from project and name, so upgrades keep it.
package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/sealedtempo/sealed/cli/internal/token"
)

// StackSchema is the stack file schema id.
const StackSchema = "sealed-deploy/v1"

// StackFile is stack.yaml.
type StackFile struct {
	Schema string `yaml:"schema"`
	// Name names every resource: sealed-<name> (VM), sealed-<name>-data, sealed-<name>-ip.
	Name string `yaml:"name"`
	// Connection is the sct_ token from sealed bootstrap. The fields below override or replace it.
	Connection   string              `yaml:"connection"`
	Project      string              `yaml:"project"`
	Region       string              `yaml:"region"`
	KeyBroker    string              `yaml:"keyBroker"`
	Customer     string              `yaml:"customer"`
	Zone         string              `yaml:"zone"`
	MachineType  string              `yaml:"machineType"`
	DataDiskGB   int                 `yaml:"dataDiskGb"`
	Salt         string              `yaml:"salt"`
	Image        Image               `yaml:"image"`
	Apps         []App               `yaml:"apps"`
	Hostnames    *Host               `yaml:"hostnames"`
	Endpoints    Ends                `yaml:"endpoints"`
	Settlement   *Settl              `yaml:"settlement"`
	RelayOwner   string              `yaml:"relayOwner"`
	BootBucket   string              `yaml:"bootBucket"`
	EgressAdd    map[string][]string `yaml:"egressAdditions"`
	AllowedRange []string            `yaml:"allowedVpcRanges"`
}

// Image names the approved OS image and the GCE images it boots from.
type Image struct {
	// ID is the PlatformRegistry imageId (approved and not debug, unless Debug is set).
	ID string `yaml:"id"`
	// Boot is the GCE image of the measured OS (projects/<p>/global/images/<name>).
	Boot string `yaml:"boot"`
	// SystemDisk is the GCE image of dstack's system data disk (one GPT partition named dstack-data).
	SystemDisk string `yaml:"systemDisk"`
	// VMConfig is the image's vm_config string for .sys-config.json (published with the image).
	VMConfig string `yaml:"vmConfig"`
	// Debug deploys a debug image (PlatformRegistry isDebug, spec 5.8) for development: it never receives
	// production secrets, and the VM gets the bootstrap's log writer identity (logging.write only) so its
	// container logs reach Cloud Logging. Production images refuse it; debug images require it.
	Debug bool `yaml:"debug"`
}

// App selects one catalog app. Release is "latest" (default), a release version, or a 0x releaseId.
type App struct {
	ID      string `yaml:"id"`
	Release string `yaml:"release"`
}

// Host is the hostname scheme (INTERFACES section 5): sslip (default) or custom with domains.
type Host struct {
	Scheme  string            `yaml:"scheme"`
	Domains map[string]string `yaml:"domains"`
}

// Ends are the endpoints the stack calls. keyBroker comes from the connection.
type Ends struct {
	PlatformAPI string `yaml:"platformApi"`
	TempoRPC    string `yaml:"tempoRpc"`
	Relay       string `yaml:"relay"`
	RelayAttest string `yaml:"relayAttest"`
}

// Settl is the settlement block; defaults come from config/defaults.yaml.
type Settl struct {
	Mode               string `yaml:"mode"`
	IntervalMinutes    int64  `yaml:"intervalMinutes"`
	GracePeriodMinutes int64  `yaml:"gracePeriodMinutes"`
	SpendLimitPerDay   string `yaml:"spendLimitPerDay"`
}

var (
	nameRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	zoneRe    = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+-[a-z]$`)
	mtRe      = regexp.MustCompile(`^c3-standard-(4|8|22|44|88|176)$|^c4-standard-(2|4|8|16|32|48|96|144|192)$`)
	gceImgRe  = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
	bucketRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)
	appIDRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	hex32Re   = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	addressRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
)

// LoadStackFile reads and validates stack.yaml. Unknown keys are errors.
func LoadStackFile(path string) (*StackFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseStackFile(raw)
}

// ParseStackFile parses stack.yaml bytes.
func ParseStackFile(raw []byte) (*StackFile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var s StackFile
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("stack file: %w", err)
	}
	if err := s.normalize(); err != nil {
		return nil, fmt.Errorf("stack file: %w", err)
	}
	return &s, nil
}

func (s *StackFile) normalize() error {
	if s.Schema != StackSchema {
		return fmt.Errorf("schema must be %q", StackSchema)
	}
	if !nameRe.MatchString(s.Name) {
		return fmt.Errorf("name %q: 2 to 32 lowercase letters, digits and hyphens, starting with a letter", s.Name)
	}
	if s.Connection != "" {
		c, err := token.Decode(s.Connection)
		if err != nil {
			return err
		}
		fill := func(dst *string, v, field string) error {
			if *dst == "" {
				*dst = v
				return nil
			}
			if !strings.EqualFold(*dst, v) {
				return fmt.Errorf("%s %q differs from the connection token's %q", field, *dst, v)
			}
			return nil
		}
		for _, f := range []struct {
			dst      *string
			v, field string
		}{{&s.Project, c.Project, "project"}, {&s.Region, c.Region, "region"}, {&s.KeyBroker, c.KeyBrokerURL, "keyBroker"}, {&s.Customer, c.Customer, "customer"}} {
			if err := fill(f.dst, f.v, f.field); err != nil {
				return err
			}
		}
	}
	switch {
	case s.Project == "" || s.Region == "" || s.KeyBroker == "" || s.Customer == "":
		return fmt.Errorf("project, region, keyBroker and customer are required (or a connection token)")
	case !addressRe.MatchString(s.Customer):
		return fmt.Errorf("customer %q is not an address", s.Customer)
	}
	s.Customer = strings.ToLower(s.Customer)
	if s.Zone == "" {
		s.Zone = s.Region + "-a"
	}
	if !zoneRe.MatchString(s.Zone) || !strings.HasPrefix(s.Zone, s.Region+"-") {
		return fmt.Errorf("zone %q is not a zone of %s", s.Zone, s.Region)
	}
	if s.MachineType != "" && !mtRe.MatchString(s.MachineType) {
		return fmt.Errorf("machineType %q is not a TDX machine type (c3-standard-* or c4-standard-*)", s.MachineType)
	}
	if s.DataDiskGB != 0 && (s.DataDiskGB < 10 || s.DataDiskGB > 65536) {
		return fmt.Errorf("dataDiskGb must be between 10 and 65536")
	}
	if s.Salt != "" && !hex32Re.MatchString(s.Salt) {
		return fmt.Errorf("salt must be 0x plus 64 lowercase hex characters")
	}
	if !hex32Re.MatchString(s.Image.ID) {
		return fmt.Errorf("image.id must be the PlatformRegistry imageId (0x plus 64 lowercase hex)")
	}
	if !gceImgRe.MatchString(s.Image.Boot) || !gceImgRe.MatchString(s.Image.SystemDisk) {
		return fmt.Errorf("image.boot and image.systemDisk must be projects/<project>/global/images/<name>")
	}
	if s.BootBucket != "" && !bucketRe.MatchString(s.BootBucket) {
		return fmt.Errorf("bootBucket %q is not a bucket name", s.BootBucket)
	}
	if len(s.Apps) == 0 {
		return fmt.Errorf("apps: at least one app")
	}
	seen := map[string]bool{}
	for i := range s.Apps {
		a := &s.Apps[i]
		if !appIDRe.MatchString(a.ID) {
			return fmt.Errorf("apps[%d]: id %q", i, a.ID)
		}
		if seen[a.ID] {
			return fmt.Errorf("app %s listed twice", a.ID)
		}
		seen[a.ID] = true
		if a.Release == "" {
			a.Release = "latest"
		}
	}
	sort.Slice(s.Apps, func(i, j int) bool { return s.Apps[i].ID < s.Apps[j].ID })
	if s.Hostnames == nil {
		s.Hostnames = &Host{Scheme: "sslip"}
	}
	if s.RelayOwner != "" && !addressRe.MatchString(s.RelayOwner) {
		return fmt.Errorf("relayOwner %q is not an address", s.RelayOwner)
	}
	return nil
}

// ResourceNames are the Compute Engine names of a deployment. All start with sealed- (the deployer's condition).
type ResourceNames struct {
	Instance, DataDisk, Address, BootDisk, SystemDisk, SharedDisk, SharedImage string
}

// Names returns the resource names for the stack.
func (s *StackFile) Names() ResourceNames {
	base := "sealed-" + s.Name
	return ResourceNames{
		Instance: base, DataDisk: base + "-data", Address: base + "-ip", BootDisk: base + "-boot",
		SystemDisk: base + "-system", SharedDisk: base + "-shared", SharedImage: base + "-shared",
	}
}

// SaltHex is the configured salt, or one derived from project and name only. It never depends on the apps, the
// releases, the image or the config, so an upgrade keeps it, and with it the data disk key and the enclave signer
// (D-058); a redeploy of an unchanged stack file also keeps its deploymentId. Changing the salt (or the name)
// means a fresh data disk: the old one cannot be opened with the new key.
func (s *StackFile) SaltHex() string {
	if s.Salt != "" {
		return s.Salt
	}
	h := sha256.Sum256([]byte("sealed/deploy-salt/v1\x00" + s.Project + "\x00" + s.Name))
	return "0x" + hex.EncodeToString(h[:])
}
