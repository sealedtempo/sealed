package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Compute manages instances, disks and static IPs of one project.
type Compute struct {
	C       *Client
	Project string
	Root    string // default ComputeRoot
	// PollInterval between operation polls; default 3 s.
	PollInterval time.Duration
	Sleep        func(time.Duration)
}

func (c *Compute) root() string {
	if c.Root != "" {
		return c.Root
	}
	return ComputeRoot
}

func (c *Compute) base() string { return c.root() + "/projects/" + url.PathEscape(c.Project) }

// Operation is a Compute Engine long-running operation.
type Operation struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Zone       string `json:"zone,omitempty"`
	Region     string `json:"region,omitempty"`
	TargetLink string `json:"targetLink,omitempty"`
	Error      *struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	} `json:"error,omitempty"`
}

func (o *Operation) err() error {
	if o.Error == nil || len(o.Error.Errors) == 0 {
		return nil
	}
	var parts []string
	for _, e := range o.Error.Errors {
		parts = append(parts, e.Code+": "+e.Message)
	}
	return fmt.Errorf("operation %s failed: %s", o.Name, strings.Join(parts, "; "))
}

// wait polls an operation until DONE. scope is "zones/<zone>" or "regions/<region>".
func (c *Compute) wait(ctx context.Context, scope string, op *Operation) error {
	interval := c.PollInterval
	if interval == 0 {
		interval = 3 * time.Second
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for op.Status != "DONE" {
		if err := ctx.Err(); err != nil {
			return err
		}
		sleep(interval)
		u := fmt.Sprintf("%s/%s/operations/%s", c.base(), scope, url.PathEscape(op.Name))
		next := &Operation{}
		if err := c.C.Do(ctx, "GET", u, nil, next); err != nil {
			return err
		}
		op = next
	}
	return op.err()
}

// Address is a regional static external IP.
type Address struct {
	Name        string            `json:"name"`
	Address     string            `json:"address,omitempty"`
	AddressType string            `json:"addressType,omitempty"`
	NetworkTier string            `json:"networkTier,omitempty"`
	Status      string            `json:"status,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Description string            `json:"description,omitempty"`
}

// GetAddress returns a regional address.
func (c *Compute) GetAddress(ctx context.Context, region, name string) (*Address, error) {
	a := &Address{}
	u := fmt.Sprintf("%s/regions/%s/addresses/%s", c.base(), url.PathEscape(region), url.PathEscape(name))
	if err := c.C.Do(ctx, "GET", u, nil, a); err != nil {
		return nil, err
	}
	return a, nil
}

// EnsureAddress reserves a premium-tier external IP named name, or returns the existing one.
func (c *Compute) EnsureAddress(ctx context.Context, region, name, description string) (*Address, error) {
	if a, err := c.GetAddress(ctx, region, name); err == nil {
		return a, nil
	} else if !IsNotFound(err) {
		return nil, err
	}
	op := &Operation{}
	u := fmt.Sprintf("%s/regions/%s/addresses", c.base(), url.PathEscape(region))
	if err := c.C.Do(ctx, "POST", u, Address{Name: name, AddressType: "EXTERNAL", NetworkTier: "PREMIUM", Description: description}, op); err != nil && !IsConflict(err) {
		return nil, err
	} else if err == nil {
		if err := c.wait(ctx, "regions/"+region, op); err != nil {
			return nil, err
		}
	}
	return c.GetAddress(ctx, region, name)
}

// Disk is a zonal persistent disk.
type Disk struct {
	Name        string            `json:"name"`
	SizeGb      string            `json:"sizeGb,omitempty"`
	Type        string            `json:"type,omitempty"`
	SourceImage string            `json:"sourceImage,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Description string            `json:"description,omitempty"`
	Status      string            `json:"status,omitempty"`
	SelfLink    string            `json:"selfLink,omitempty"`
	Users       []string          `json:"users,omitempty"`
}

// GetDisk returns a zonal disk.
func (c *Compute) GetDisk(ctx context.Context, zone, name string) (*Disk, error) {
	d := &Disk{}
	u := fmt.Sprintf("%s/zones/%s/disks/%s", c.base(), url.PathEscape(zone), url.PathEscape(name))
	if err := c.C.Do(ctx, "GET", u, nil, d); err != nil {
		return nil, err
	}
	return d, nil
}

// EnsureDisk creates the disk unless it exists. An existing disk is kept as it is (it holds the deployment's
// encrypted data across redeploys).
func (c *Compute) EnsureDisk(ctx context.Context, zone string, d Disk) (*Disk, bool, error) {
	if got, err := c.GetDisk(ctx, zone, d.Name); err == nil {
		return got, false, nil
	} else if !IsNotFound(err) {
		return nil, false, err
	}
	op := &Operation{}
	u := fmt.Sprintf("%s/zones/%s/disks", c.base(), url.PathEscape(zone))
	if err := c.C.Do(ctx, "POST", u, d, op); err != nil {
		return nil, false, err
	}
	if err := c.wait(ctx, "zones/"+zone, op); err != nil {
		return nil, false, err
	}
	got, err := c.GetDisk(ctx, zone, d.Name)
	return got, true, err
}

// Instance is the subset of the Compute Engine instance resource the CLI sets and reads.
type Instance struct {
	Name                       string                      `json:"name"`
	Description                string                      `json:"description,omitempty"`
	MachineType                string                      `json:"machineType,omitempty"`
	Status                     string                      `json:"status,omitempty"`
	Labels                     map[string]string           `json:"labels,omitempty"`
	Tags                       *Tags                       `json:"tags,omitempty"`
	Metadata                   *Metadata                   `json:"metadata,omitempty"`
	Disks                      []AttachedDisk              `json:"disks,omitempty"`
	NetworkInterfaces          []NetworkInterface          `json:"networkInterfaces,omitempty"`
	ServiceAccounts            []ServiceAccount            `json:"serviceAccounts"`
	Scheduling                 *Scheduling                 `json:"scheduling,omitempty"`
	ConfidentialInstanceConfig *ConfidentialInstanceConfig `json:"confidentialInstanceConfig,omitempty"`
	ShieldedInstanceConfig     *ShieldedInstanceConfig     `json:"shieldedInstanceConfig,omitempty"`
	SelfLink                   string                      `json:"selfLink,omitempty"`
}

type Tags struct {
	Items []string `json:"items,omitempty"`
}

type Metadata struct {
	Items []MetadataItem `json:"items,omitempty"`
}

type MetadataItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type AttachedDisk struct {
	Boot             bool              `json:"boot,omitempty"`
	AutoDelete       bool              `json:"autoDelete"`
	DeviceName       string            `json:"deviceName,omitempty"`
	Mode             string            `json:"mode,omitempty"`
	Interface        string            `json:"interface,omitempty"`
	Source           string            `json:"source,omitempty"`
	InitializeParams *InitializeParams `json:"initializeParams,omitempty"`
}

type InitializeParams struct {
	DiskName    string            `json:"diskName,omitempty"`
	SourceImage string            `json:"sourceImage,omitempty"`
	DiskType    string            `json:"diskType,omitempty"`
	DiskSizeGb  string            `json:"diskSizeGb,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type NetworkInterface struct {
	Subnetwork    string         `json:"subnetwork,omitempty"`
	NicType       string         `json:"nicType,omitempty"`
	StackType     string         `json:"stackType,omitempty"`
	AccessConfigs []AccessConfig `json:"accessConfigs,omitempty"`
}

type AccessConfig struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	NatIP       string `json:"natIP,omitempty"`
	NetworkTier string `json:"networkTier,omitempty"`
}

// ServiceAccount is listed only so a read-back can prove the list is empty.
type ServiceAccount struct {
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
}

type Scheduling struct {
	OnHostMaintenance string `json:"onHostMaintenance,omitempty"`
	AutomaticRestart  *bool  `json:"automaticRestart,omitempty"`
}

type ConfidentialInstanceConfig struct {
	ConfidentialInstanceType string `json:"confidentialInstanceType,omitempty"`
}

type ShieldedInstanceConfig struct {
	EnableSecureBoot          bool `json:"enableSecureBoot"`
	EnableVtpm                bool `json:"enableVtpm"`
	EnableIntegrityMonitoring bool `json:"enableIntegrityMonitoring"`
}

// GetInstance returns an instance.
func (c *Compute) GetInstance(ctx context.Context, zone, name string) (*Instance, error) {
	in := &Instance{}
	u := fmt.Sprintf("%s/zones/%s/instances/%s", c.base(), url.PathEscape(zone), url.PathEscape(name))
	if err := c.C.Do(ctx, "GET", u, nil, in); err != nil {
		return nil, err
	}
	return in, nil
}

// ErrInstanceExists is returned by InsertInstance when an instance of that name exists.
var ErrInstanceExists = errors.New("instance already exists")

// InsertInstance creates the instance and waits for the operation. requestID makes a retried insert idempotent.
func (c *Compute) InsertInstance(ctx context.Context, zone string, in *Instance, requestID string) error {
	op := &Operation{}
	u := fmt.Sprintf("%s/zones/%s/instances", c.base(), url.PathEscape(zone))
	if requestID != "" {
		u += "?requestId=" + url.QueryEscape(requestID)
	}
	if err := c.C.Do(ctx, "POST", u, in, op); err != nil {
		if IsConflict(err) {
			return ErrInstanceExists
		}
		return err
	}
	return c.wait(ctx, "zones/"+zone, op)
}

// instanceAction posts start, stop, or deletes the instance.
func (c *Compute) instanceAction(ctx context.Context, zone, name, action string) error {
	op := &Operation{}
	u := fmt.Sprintf("%s/zones/%s/instances/%s", c.base(), url.PathEscape(zone), url.PathEscape(name))
	method := "POST"
	if action == "delete" {
		method = "DELETE"
	} else {
		u += "/" + action
	}
	if err := c.C.Do(ctx, method, u, nil, op); err != nil {
		return err
	}
	return c.wait(ctx, "zones/"+zone, op)
}

// StartInstance starts a stopped instance.
func (c *Compute) StartInstance(ctx context.Context, zone, name string) error {
	return c.instanceAction(ctx, zone, name, "start")
}

// StopInstance stops an instance (its disks are kept).
func (c *Compute) StopInstance(ctx context.Context, zone, name string) error {
	return c.instanceAction(ctx, zone, name, "stop")
}

// DeleteInstance deletes an instance (auto-delete disks go with it).
func (c *Compute) DeleteInstance(ctx context.Context, zone, name string) error {
	return c.instanceAction(ctx, zone, name, "delete")
}

// Image is a Compute Engine image.
type Image struct {
	Name            string            `json:"name"`
	Description     string            `json:"description,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	RawDisk         *RawDisk          `json:"rawDisk,omitempty"`
	GuestOsFeatures []GuestOsFeature  `json:"guestOsFeatures,omitempty"`
	Status          string            `json:"status,omitempty"`
	SelfLink        string            `json:"selfLink,omitempty"`
}

type RawDisk struct {
	Source string `json:"source"`
}

type GuestOsFeature struct {
	Type string `json:"type"`
}

// GetImage returns an image of this project.
func (c *Compute) GetImage(ctx context.Context, name string) (*Image, error) {
	img := &Image{}
	u := fmt.Sprintf("%s/global/images/%s", c.base(), url.PathEscape(name))
	if err := c.C.Do(ctx, "GET", u, nil, img); err != nil {
		return nil, err
	}
	return img, nil
}

// InsertImage creates an image from a raw disk tarball in Cloud Storage and waits for it.
func (c *Compute) InsertImage(ctx context.Context, img Image) error {
	op := &Operation{}
	u := fmt.Sprintf("%s/global/images", c.base())
	if err := c.C.Do(ctx, "POST", u, img, op); err != nil {
		return err
	}
	return c.wait(ctx, "global", op)
}

// Storage uploads objects.
type Storage struct {
	C          *Client
	UploadRoot string // default StorageUploadRoot
	ObjectRoot string // default StorageObjectRoot
}

// Upload stores data as bucket/object (simple media upload) and returns the object's https URL, the form
// images.insert accepts as rawDisk.source.
func (s *Storage) Upload(ctx context.Context, bucket, object, contentType string, data []byte) (string, error) {
	root := s.UploadRoot
	if root == "" {
		root = StorageUploadRoot
	}
	u := fmt.Sprintf("%s/b/%s/o?uploadType=media&name=%s", root, url.PathEscape(bucket), url.QueryEscape(object))
	if err := s.C.DoRaw(ctx, "POST", u, contentType, data, nil); err != nil {
		return "", err
	}
	objRoot := s.ObjectRoot
	if objRoot == "" {
		objRoot = StorageObjectRoot
	}
	return objRoot + "/" + bucket + "/" + object, nil
}
