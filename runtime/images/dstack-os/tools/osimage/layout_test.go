// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// disk is one attached disk, in attachment order, identified by its GCE device name and size in GB.
type disk struct {
	device string
	sizeGB int
}

// TestMeasureScriptDiskLayoutMatchesBuildInstance checks C10/G08: import-and-measure.sh must boot the exact
// 4-disk layout that cli/internal/deploy BuildInstance gives a production VM, in the same order and with the
// same device names and sizes. RTMR0's EV_EFI_VARIABLE_BOOT entries depend on the disk count, so a different
// layout (the old 3-disk boot+data+shared) measures an RTMR0 no production VM ever has. The test reads the
// script, instance.go and config/defaults.yaml and fails on any divergence, so neither side can drift alone.
func TestMeasureScriptDiskLayoutMatchesBuildInstance(t *testing.T) {
	prod := productionLayout(t)
	script := scriptLayout(t)

	if len(prod) != 4 {
		t.Fatalf("expected a 4-disk production layout, parsed %d from instance.go: %+v", len(prod), prod)
	}
	// The known production layout, so a silent change on either side is caught, not just a drift that keeps
	// both sides equal.
	want := []disk{
		{"boot", 10},
		{"dstack-system", 20},
		{"dstack-shared", 10},
		{"sealed-data", 50},
	}
	if !equalLayout(prod, want) {
		t.Fatalf("BuildInstance layout changed: parsed %+v, want %+v (update the measurement script and this test together)", prod, want)
	}
	if !equalLayout(script, want) {
		t.Fatalf("import-and-measure.sh layout %+v does not match the production layout %+v", script, want)
	}
}

func equalLayout(a, b []disk) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// productionLayout parses BuildInstance in cli/internal/deploy/instance.go into the ordered disk list. The first
// three disks carry an explicit DeviceName and DiskSizeGb; the sealed-data disk is an existing disk whose device
// name is the DataDeviceName constant and whose size is config/defaults.yaml's data_disk_gb (50).
func productionLayout(t *testing.T) []disk {
	t.Helper()
	root := repoRoot(t)
	src := readFile(t, filepath.Join(root, "cli", "internal", "deploy", "instance.go"))

	// The DataDeviceName constant is the sealed-data device name.
	dataDevice := matchOne(t, src, `const\s+DataDeviceName\s*=\s*"([^"]+)"`, "DataDeviceName")

	body := between(t, src, "func BuildInstance(", "// CheckInstance")

	// Device names in attachment order. DataDeviceName (an identifier) is the fourth.
	deviceRe := regexp.MustCompile(`DeviceName:\s*(?:"([^"]+)"|DataDeviceName)`)
	var devices []string
	for _, m := range deviceRe.FindAllStringSubmatch(body, -1) {
		if m[1] != "" {
			devices = append(devices, m[1])
		} else {
			devices = append(devices, dataDevice)
		}
	}
	// Explicit sizes in order (boot, dstack-system, dstack-shared); sealed-data has none in BuildInstance.
	sizeRe := regexp.MustCompile(`DiskSizeGb:\s*"(\d+)"`)
	var sizes []int
	for _, m := range sizeRe.FindAllStringSubmatch(body, -1) {
		sizes = append(sizes, atoi(t, m[1]))
	}
	if len(devices) != 4 || len(sizes) != 3 {
		t.Fatalf("instance.go BuildInstance parse: %d device names, %d explicit sizes (want 4 and 3): devices=%v sizes=%v", len(devices), len(sizes), devices, sizes)
	}
	// The sealed-data disk is sized by config/defaults.yaml data_disk_gb.
	defaults := readFile(t, filepath.Join(root, "config", "defaults.yaml"))
	dataGB := atoi(t, matchOne(t, defaults, `(?m)^data_disk_gb:\s*(\d+)\s*$`, "data_disk_gb"))
	sizes = append(sizes, dataGB)

	out := make([]disk, 4)
	for i := range out {
		out[i] = disk{device: devices[i], sizeGB: sizes[i]}
	}
	return out
}

// scriptLayout parses the `gcloud compute instances create` call in import-and-measure.sh into the ordered disk
// list: the boot disk from --boot-disk-device-name / --boot-disk-size, then each --create-disk in order.
func scriptLayout(t *testing.T) []disk {
	t.Helper()
	script := readFile(t, filepath.Join("..", "..", "import-and-measure.sh"))

	out := []disk{{
		device: matchOne(t, script, `--boot-disk-device-name=([A-Za-z0-9-]+)`, "--boot-disk-device-name"),
		sizeGB: parseSizeGB(t, matchOne(t, script, `--boot-disk-size=(\d+GB)`, "--boot-disk-size")),
	}}

	createRe := regexp.MustCompile(`--create-disk="([^"]*)"`)
	for _, m := range createRe.FindAllStringSubmatch(script, -1) {
		fields := map[string]string{}
		for _, kv := range strings.Split(m[1], ",") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				fields[k] = v
			}
		}
		dev, ok := fields["device-name"]
		if !ok {
			t.Fatalf("--create-disk has no device-name: %q", m[1])
		}
		size, ok := fields["size"]
		if !ok {
			t.Fatalf("--create-disk has no size: %q", m[1])
		}
		out = append(out, disk{device: dev, sizeGB: parseSizeGB(t, size)})
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "..", "..")
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func matchOne(t *testing.T, s, pattern, what string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("no %s match (/%s/)", what, pattern)
	}
	return m[1]
}

func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("start marker %q not found", start)
	}
	rest := s[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("end marker %q not found after %q", end, start)
	}
	return rest[:j]
}

func parseSizeGB(t *testing.T, v string) int {
	t.Helper()
	v = strings.TrimSuffix(v, "GB")
	return atoi(t, v)
}

func atoi(t *testing.T, v string) int {
	t.Helper()
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("not an integer: %q", v)
	}
	return n
}
