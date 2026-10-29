package deploy

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/sealedtempo/sealed/cli/internal/gcp"
	"github.com/sealedtempo/sealed/cli/internal/settings"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// VMTag opens 80 and 443 in the bootstrap firewall.
const VMTag = "sealed-vm"

// SubnetName is the bootstrap subnet.
const SubnetName = "sealed-subnet"

// DataDeviceName is the device name sealed-agent opens with LUKS (/dev/disk/by-id/google-sealed-data).
const DataDeviceName = "sealed-data"

// DebugLogAccountID is the log writer service account the bootstrap creates with enable_debug_logging
// (infra/terraform/customer-bootstrap/debug_logging.tf). Only debug VMs get it (spec 5.8).
const DebugLogAccountID = "sealed-debug-logs"

// DebugLogScopes are the only OAuth scopes a debug VM gets: sealed-logship writes container logs, nothing else.
var DebugLogScopes = []string{"https://www.googleapis.com/auth/logging.write"}

// DebugLogServiceAccount is the debug log writer of a project.
func DebugLogServiceAccount(project string) string {
	return DebugLogAccountID + "@" + project + ".iam.gserviceaccount.com"
}

// VariantLabel marks a VM and its data disk as running the production or the debug image.
const VariantLabel = "sealed-variant"

// Metadata the VM must carry (spec 5.9). Values are the strings Compute Engine expects.
var requiredMetadata = map[string]string{
	"block-project-ssh-keys":     "TRUE",
	"enable-oslogin":             "FALSE",
	"serial-port-enable":         "FALSE",
	"serial-port-logging-enable": "FALSE",
	"enable-guest-attributes":    "FALSE",
}

// InstanceParams describe one deployment VM.
type InstanceParams struct {
	Project, Region, Zone string
	Names                 ResourceNames
	MachineType           string // one of settings.RegisteredMachineTypes (D-083)
	BootImage             string // measured OS image
	SystemDiskImage       string // dstack-data GPT image
	SharedDiskImage       string // per-deployment dstack shared disk
	DataDiskSelfLink      string // existing sealed-<name>-data
	NatIP                 string // static IP
	DeploymentID          string // 0x hex, public
	Labels                map[string]string
	// DebugLogSA is set only for a debug image (spec 5.8): the VM then gets this log writer identity with
	// DebugLogScopes. Production VMs never have a service account.
	DebugLogSA string
	// TEE is cloud.tee of the defaults, which picks the confidentialInstanceType. Empty is intel-tdx, the only TEE
	// settings.Load accepts.
	TEE string
}

func diskType(zone string) string { return "zones/" + zone + "/diskTypes/pd-balanced" }

// ImageMachineTypes are the machine types a PlatformRegistry OS image entry was measured on: the build metadata of
// its version (<sealed OS version>+<type>.<type>, written by runtime/images/dstack-os/tools/osimage). A version
// without build metadata, like the simulator images of local test chains, names none.
func ImageMachineTypes(version string) []string {
	_, meta, ok := strings.Cut(version, "+")
	if !ok || meta == "" {
		return nil
	}
	return strings.Split(meta, ".")
}

// CheckMachineType refuses a machine type whose VM the key broker would deny at first boot (D-083): one that is not
// a registered machine type of cloud.machine_family, or one the stack's image entry was not measured on. The broker
// compares the quote with the image's measurements, and RTMR0 follows the machine shape (D-070).
func CheckMachineType(machineType string, img *chain.Image, cloud settings.Cloud) error {
	if !slices.Contains(cloud.MachineTypes(), machineType) {
		return fmt.Errorf("machine type %q is not a %s machine type with a registered image (%s, D-083)",
			machineType, cloud.MachineFamily, strings.Join(cloud.MachineTypes(), ", "))
	}
	if img == nil {
		return nil
	}
	if measured := ImageMachineTypes(img.Version); len(measured) > 0 && !slices.Contains(measured, machineType) {
		return fmt.Errorf("image %s %s was measured on %s, not on machine type %s, so the key broker would refuse the VM at first boot (D-083): set machineType to one of those, or image.id to the entry measured on %s",
			img.Name, img.Version, strings.Join(measured, ", "), machineType, machineType)
	}
	return nil
}

// confidentialInstanceType maps cloud.tee to Compute Engine's confidentialInstanceType ("" is intel-tdx).
func confidentialInstanceType(tee string) (string, error) {
	if tee == "" {
		tee = settings.TEEIntelTDX
	}
	return settings.ConfidentialInstanceType(tee)
}

// BuildInstance returns the instance resource. A production VM never gets a service account (the list is
// explicitly empty, so no scopes either); a debug VM gets only the log writer identity with the logging.write
// scope. Both turn OS Login, the serial port and its logging off, block project SSH keys, and require TDX with
// host maintenance TERMINATE. Secure boot stays off because dstack's UKI is not signed for the default db; the
// vTPM stays on because dstack mixes its key into the instance id. An unknown TEE panics, because settings.Load
// refuses every other cloud.tee: a VM is never built without confidential compute.
func BuildInstance(p InstanceParams) *gcp.Instance {
	confidentialType, err := confidentialInstanceType(p.TEE)
	if err != nil {
		panic(err)
	}
	t := true
	variant, description, accounts := "production", "Sealed confidential deployment ", []gcp.ServiceAccount{}
	if p.DebugLogSA != "" {
		variant, description = "debug", "Sealed DEBUG deployment (no production secrets, container logs to Cloud Logging) "
		accounts = []gcp.ServiceAccount{{Email: p.DebugLogSA, Scopes: append([]string(nil), DebugLogScopes...)}}
	}
	labels := map[string]string{"sealed": "deployment", "sealed-name": strings.TrimPrefix(p.Names.Instance, "sealed-"), VariantLabel: variant}
	if len(p.DeploymentID) >= 18 {
		labels["sealed-deployment"] = strings.TrimPrefix(p.DeploymentID, "0x")[:16]
	}
	for k, v := range p.Labels {
		labels[k] = v
	}
	var items []gcp.MetadataItem
	for _, k := range []string{"block-project-ssh-keys", "enable-guest-attributes", "enable-oslogin", "serial-port-enable", "serial-port-logging-enable"} {
		items = append(items, gcp.MetadataItem{Key: k, Value: requiredMetadata[k]})
	}
	if p.DeploymentID != "" {
		items = append(items, gcp.MetadataItem{Key: "sealed-deployment-id", Value: p.DeploymentID})
	}
	return &gcp.Instance{
		Name:        p.Names.Instance,
		Description: description + p.DeploymentID,
		MachineType: "zones/" + p.Zone + "/machineTypes/" + p.MachineType,
		Labels:      labels,
		Tags:        &gcp.Tags{Items: []string{VMTag}},
		Metadata:    &gcp.Metadata{Items: items},
		Disks: []gcp.AttachedDisk{
			{Boot: true, AutoDelete: true, DeviceName: "boot", Mode: "READ_WRITE", Interface: "NVME", InitializeParams: &gcp.InitializeParams{
				DiskName: p.Names.BootDisk, SourceImage: p.BootImage, DiskType: diskType(p.Zone), DiskSizeGb: "10",
			}},
			{AutoDelete: true, DeviceName: "dstack-system", Mode: "READ_WRITE", Interface: "NVME", InitializeParams: &gcp.InitializeParams{
				DiskName: p.Names.SystemDisk, SourceImage: p.SystemDiskImage, DiskType: diskType(p.Zone), DiskSizeGb: "20",
			}},
			{AutoDelete: true, DeviceName: "dstack-shared", Mode: "READ_WRITE", Interface: "NVME", InitializeParams: &gcp.InitializeParams{
				DiskName: p.Names.SharedDisk, SourceImage: p.SharedDiskImage, DiskType: diskType(p.Zone), DiskSizeGb: "10",
			}},
			// The app data disk survives the VM: it is never auto-deleted.
			{AutoDelete: false, DeviceName: DataDeviceName, Mode: "READ_WRITE", Interface: "NVME", Source: p.DataDiskSelfLink},
		},
		NetworkInterfaces: []gcp.NetworkInterface{{
			Subnetwork: "projects/" + p.Project + "/regions/" + p.Region + "/subnetworks/" + SubnetName,
			NicType:    "GVNIC",
			StackType:  "IPV4_ONLY",
			AccessConfigs: []gcp.AccessConfig{{
				Type: "ONE_TO_ONE_NAT", Name: "External NAT", NatIP: p.NatIP, NetworkTier: "PREMIUM",
			}},
		}},
		ServiceAccounts:            accounts,
		Scheduling:                 &gcp.Scheduling{OnHostMaintenance: "TERMINATE", AutomaticRestart: &t},
		ConfidentialInstanceConfig: &gcp.ConfidentialInstanceConfig{ConfidentialInstanceType: confidentialType},
		ShieldedInstanceConfig:     &gcp.ShieldedInstanceConfig{EnableSecureBoot: false, EnableVtpm: true, EnableIntegrityMonitoring: true},
	}
}

// CheckInstance lists every way in which a production VM read back from the API violates spec 5.9. An empty list
// means it complies.
func CheckInstance(in *gcp.Instance) []string { return checkInstance(in, "") }

// CheckDebugInstance is CheckInstance for a debug VM (spec 5.8): its one exception is exactly the log writer
// identity debugLogSA with only the logging.write scope, and the debug label.
func CheckDebugInstance(in *gcp.Instance, debugLogSA string) []string {
	if debugLogSA == "" {
		return []string{"no debug log writer identity named"}
	}
	return checkInstance(in, debugLogSA)
}

// DeploymentIDOf is the sealed-deployment-id metadata of a VM sealed deploy created ("" otherwise).
func DeploymentIDOf(in *gcp.Instance) string {
	if in.Metadata != nil {
		for _, it := range in.Metadata.Items {
			if it.Key == "sealed-deployment-id" {
				return it.Value
			}
		}
	}
	return ""
}

func checkInstance(in *gcp.Instance, debugLogSA string) []string {
	var problems []string
	switch {
	case debugLogSA == "" && len(in.ServiceAccounts) != 0:
		problems = append(problems, fmt.Sprintf("has service account %s", in.ServiceAccounts[0].Email))
	case debugLogSA == "" && in.Labels[VariantLabel] == "debug":
		problems = append(problems, "is labeled as a debug VM")
	case debugLogSA != "":
		if len(in.ServiceAccounts) != 1 || in.ServiceAccounts[0].Email != debugLogSA || !slices.Equal(in.ServiceAccounts[0].Scopes, DebugLogScopes) {
			var got []string
			for _, a := range in.ServiceAccounts {
				got = append(got, a.Email+" "+strings.Join(a.Scopes, ","))
			}
			problems = append(problems, fmt.Sprintf("a debug VM must have exactly %s with scope %s, has [%s]", debugLogSA, strings.Join(DebugLogScopes, ","), strings.Join(got, "; ")))
		}
		if in.Labels[VariantLabel] != "debug" {
			problems = append(problems, "the debug VM is not labeled "+VariantLabel+"=debug")
		}
	}
	if want, _ := confidentialInstanceType(""); in.ConfidentialInstanceConfig == nil || in.ConfidentialInstanceConfig.ConfidentialInstanceType != want {
		problems = append(problems, "confidential compute "+want+" is not on")
	}
	if mt := path.Base(in.MachineType); !slices.Contains(settings.RegisteredMachineTypes, mt) {
		problems = append(problems, fmt.Sprintf("machine type %q has no registered image (D-083: %s)", mt, strings.Join(settings.RegisteredMachineTypes, ", ")))
	}
	if in.Scheduling == nil || in.Scheduling.OnHostMaintenance != "TERMINATE" {
		problems = append(problems, "onHostMaintenance is not TERMINATE")
	}
	md := map[string]string{}
	if in.Metadata != nil {
		for _, it := range in.Metadata.Items {
			md[it.Key] = strings.ToUpper(it.Value)
		}
	}
	for k, want := range requiredMetadata {
		if md[k] != want {
			problems = append(problems, fmt.Sprintf("metadata %s is %q, want %s", k, md[k], want))
		}
	}
	for _, forbidden := range []string{"ssh-keys", "sshKeys", "startup-script", "user-data"} {
		if _, ok := md[forbidden]; ok {
			problems = append(problems, "metadata "+forbidden+" is set")
		}
	}
	tagged := false
	if in.Tags != nil {
		for _, t := range in.Tags.Items {
			tagged = tagged || t == VMTag
		}
	}
	if !tagged {
		problems = append(problems, "missing network tag "+VMTag)
	}
	var data *gcp.AttachedDisk
	for i := range in.Disks {
		if in.Disks[i].DeviceName == DataDeviceName {
			data = &in.Disks[i]
		}
	}
	if data == nil {
		problems = append(problems, "no "+DataDeviceName+" disk")
	} else if data.AutoDelete {
		problems = append(problems, "the data disk would be deleted with the VM")
	}
	if len(in.NetworkInterfaces) != 1 || !strings.HasSuffix(in.NetworkInterfaces[0].Subnetwork, "/subnetworks/"+SubnetName) {
		problems = append(problems, "not exactly one interface in "+SubnetName)
	}
	return problems
}
