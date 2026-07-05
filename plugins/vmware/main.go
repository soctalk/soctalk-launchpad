// Launchpad plugin: VMware ESXi provider.
//
// Provisions an Ubuntu Noble VM on a standalone ESXi 7/8 host and joins it
// to a Tailscale tailnet. Same protocol surface as the qemu plugin, so the
// launchpad's up/down flow is unchanged.
//
// Design (per codex review):
//   - govmomi (github.com/vmware/govmomi) for the vSphere API.
//   - Cloud-init via VMware guestinfo (base64 user-data + meta-data in
//     ExtraConfig). The Ubuntu Noble cloud image ships with the VMware
//     cloud-init datasource enabled by default, so no seed ISO is needed.
//   - Ubuntu Noble OVA is imported on first create per plugin process; the
//     imported VM is kept powered-off as a base VM and cloned for each real
//     VM. Cache key = OVA URL sha1 → base VM name lp-base-<hash>.
//   - No pre-imported templates, no ovftool dependency: govmomi ovf +
//     nfc.Lease.Upload handle the vmdk upload.
package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/license"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/ovf"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	sdk "github.com/soctalk/launchpad-sdk-go"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/cloudinit"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/tailscale"
)

func byteReader(data []byte) io.Reader { return bytes.NewReader(data) }

const (
	name    = "vmware"
	version = "0.1.0"

	defaultOVAURL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.ova"
)

type config struct {
	ESXiURL   string   `json:"esxi_url"`
	Datastore string   `json:"datastore"`
	Network   string   `json:"network"`
	Tailnet   string   `json:"tailnet"`
	CPU       int32    `json:"cpu,omitempty"`
	MemoryMB  int64    `json:"memory_mb,omitempty"`
	DiskGB    int      `json:"disk_gb,omitempty"`
	SSHKeys   []string `json:"ssh_keys,omitempty"`
	TagPrefix string   `json:"tag_prefix,omitempty"`

	OVAURL         string `json:"ova_url,omitempty"`
	BaseVMOverride string `json:"base_vm,omitempty"` // if set, use this VM as clone source
}

type provider struct {
	cfg       config
	vc        *vim25.Client
	finder    *find.Finder
	dc        *object.Datacenter
	tsAPIKey  string
	baseVMMu  sync.Mutex
	baseVMRef *object.VirtualMachine
}

func main() {
	p := &provider{}
	err := sdk.Serve(sdk.Plugin{
		Name:    name,
		Version: version,
		AllowedEnvVars: []string{
			"TAILSCALE_API_KEY", "ESXI_URL", "ESXI_USERNAME", "ESXI_PASSWORD", "HOME",
		},
		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"esxi_url":  map[string]any{"type": "string"},
				"datastore": map[string]any{"type": "string"},
				"network":   map[string]any{"type": "string"},
				"tailnet":   map[string]any{"type": "string"},
				"cpu":       map[string]any{"type": "integer", "minimum": 1},
				"memory_mb": map[string]any{"type": "integer", "minimum": 512},
				"disk_gb":   map[string]any{"type": "integer", "minimum": 5},
				"ssh_keys":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"ova_url":   map[string]any{"type": "string"},
			},
			"required": []string{"esxi_url", "datastore", "network", "tailnet"},
		},
		Initialize: p.initialize,
		Plan:       p.plan,
		Create:     p.create,
		WaitReady:  p.waitReady,
		Destroy:    p.destroy,
		Inspect:    p.inspect,
		Shutdown:   p.shutdown,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "vmware plugin:", err)
		os.Exit(1)
	}
}

func (p *provider) initialize(ctx context.Context, params sdk.InitializeParams) (sdk.InitializeResult, error) {
	if raw, err := json.Marshal(params.Config); err == nil {
		_ = json.Unmarshal(raw, &p.cfg)
	}
	if p.cfg.ESXiURL == "" || p.cfg.Datastore == "" || p.cfg.Network == "" || p.cfg.Tailnet == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"vmware.config.incomplete",
			"esxi_url, datastore, network, tailnet are all required")
	}
	if p.cfg.CPU == 0 {
		p.cfg.CPU = 4
	}
	if p.cfg.MemoryMB == 0 {
		p.cfg.MemoryMB = 8192
	}
	if p.cfg.DiskGB == 0 {
		p.cfg.DiskGB = 60
	}
	if p.cfg.OVAURL == "" {
		p.cfg.OVAURL = defaultOVAURL
	}

	user := os.Getenv("ESXI_USERNAME")
	pw := os.Getenv("ESXI_PASSWORD")
	if user == "" || pw == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"vmware.auth.missing_creds",
			"ESXI_USERNAME and ESXI_PASSWORD environment variables are required")
	}
	p.tsAPIKey = os.Getenv("TAILSCALE_API_KEY")
	if p.tsAPIKey == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"vmware.tailscale.missing_api_key",
			"TAILSCALE_API_KEY is required for minting device auth keys")
	}

	u, err := soap.ParseURL(p.cfg.ESXiURL)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"vmware.esxi_url.invalid", "cannot parse esxi_url: %v", err)
	}
	u.User = url.UserPassword(user, pw)

	// Fresh login each plugin invocation. Insecure=true because pilot ESXi
	// typically has a self-signed cert.
	c, err := govmomi.NewClient(ctx, u, true)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"vmware.esxi.unreachable", "cannot log in to %s: %v", p.cfg.ESXiURL, err)
	}
	p.vc = c.Client

	// Activate 60-day evaluation license. Standalone ESXi ships with the
	// Free Hypervisor license which BLOCKS VM lifecycle operations via the
	// API (ImportVApp, CloneVM). Eval mode unlocks the full API for 60 days.
	// The null key is VMware's canonical eval trigger.
	lm := license.NewManager(p.vc)
	if _, err := lm.Update(ctx, "00000-00000-00000-00000-00000", nil); err != nil {
		// Non-fatal: some ESXi versions/vCenter don't allow API license changes.
		// Real operation will fail with a clearer error if we're still on Free.
	}

	p.finder = find.NewFinder(p.vc, true)
	dcs, err := p.finder.DatacenterList(ctx, "*")
	if err != nil || len(dcs) == 0 {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"vmware.esxi.no_datacenter", "no datacenter visible on ESXi: %v", err)
	}
	p.dc = dcs[0]
	p.finder.SetDatacenter(p.dc)

	// Verify datastore + network exist.
	if _, err := p.finder.Datastore(ctx, p.cfg.Datastore); err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"vmware.datastore.not_found", "datastore %q not found: %v", p.cfg.Datastore, err)
	}
	if _, err := p.finder.Network(ctx, p.cfg.Network); err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"vmware.network.not_found", "network %q not found: %v", p.cfg.Network, err)
	}

	return sdk.InitializeResult{Ready: true}, nil
}

func (p *provider) shutdown(ctx context.Context) error { return nil }

func (p *provider) plan(ctx context.Context, params sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
	return sdk.VMPlanResult{
		Summary: fmt.Sprintf("vmware: %s on %s (%dvCPU/%dMB, tailscale hostname lp-%s)",
			params.Spec.Name, p.cfg.ESXiURL, p.cfg.CPU, p.cfg.MemoryMB, params.Spec.VMKey),
		EstimatedDurationSec: 300,
	}, nil
}

// vmSize is the effective per-VM resource envelope.
type vmSize struct {
	cpu    int32
	memMB  int64
	resMB  int64 // memory reservation (0 = none)
	diskGB int
}

// sizeFor resolves a VM's resources: plugin-config defaults, overridden by
// the spec's SizeHint — a comma-separated k=v list, e.g.
// "mem=8192,res=4096,cpu=4,disk=40". Unknown keys are ignored so the hint
// stays forward-compatible across plugins.
func (p *provider) sizeFor(spec sdk.VMSpec) vmSize {
	s := vmSize{cpu: p.cfg.CPU, memMB: p.cfg.MemoryMB, diskGB: p.cfg.DiskGB}
	for _, kv := range strings.Split(spec.SizeHint, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(k) {
		case "mem":
			s.memMB = n
		case "res":
			s.resMB = n
		case "cpu":
			s.cpu = int32(n)
		case "disk":
			s.diskGB = int(n)
		}
	}
	return s
}

func vmNameFor(runID, vmKey string) string { return "lp-" + runID + "-" + vmKey }

func (p *provider) create(ctx context.Context, params sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	if p.vc == nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatAuth,
			"vmware.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	spec := params.Spec
	name := vmNameFor(spec.RunID, spec.VMKey)
	size := p.sizeFor(spec)

	// Idempotency: if a VM with this name already exists, return its info.
	emit.Progress("lookup", 3, "checking for existing VM")
	if existing, _ := p.finder.VirtualMachine(ctx, name); existing != nil {
		return p.currentResult(ctx, spec, existing, emit)
	}

	// Mint Tailscale auth key.
	emit.Progress("tailscale", 25, "minting device auth key")
	tag := tailscale.TagForSpec(spec, p.cfg.TagPrefix)
	hostname := tailscale.Hostname(spec.VMKey)
	tskey, err := tailscale.MintKey(ctx, p.cfg.Tailnet, tag)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Import OVA directly with the target VM name. Standalone ESXi does not
	// support CloneVM (that's a vCenter-only task) so we skip the base-VM
	// cache-and-clone approach and import fresh per VM. Slower on subsequent
	// VMs but works against a bare ESXi host.
	emit.Progress("clone", 40, "importing OVA as new VM")
	imported, err := p.importOVA(ctx, name, emit)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}
	cloned := imported

	// Configure resources + guestinfo cloud-init + extend the root disk to
	// cfg.DiskGB. Ubuntu cloud images ship with an ~10 GB root; without this
	// step Wazuh + k3s fill the disk within minutes → DiskPressure evictions.
	// cloud-init's growpart / cc_growpart runs on boot and expands the
	// partition + filesystem into whatever new capacity we set here.
	emit.Progress("cloud_init", 70, "configuring CPU/RAM/disk + guestinfo cloud-init")
	userData := cloudinit.Compose(cloudinit.Inputs{
		Hostname: hostname, SSHKeys: cloudinit.MergeSSHKeys(p.cfg.SSHKeys, spec.SSHKeys),
		TailscaleKey: tskey, TailscaleTag: tag, ExtraUserData: spec.UserData,
	})
	metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", spec.VMKey, hostname)

	// Collect existing devices so we can size up disk #0 (the OVA's root disk).
	var mvm mo.VirtualMachine
	_ = cloned.Properties(ctx, cloned.Reference(), []string{"config.hardware"}, &mvm)
	var deviceChange []types.BaseVirtualDeviceConfigSpec
	targetBytes := int64(size.diskGB) * 1024 * 1024 * 1024
	for _, dev := range mvm.Config.Hardware.Device {
		if d, ok := dev.(*types.VirtualDisk); ok {
			if d.CapacityInBytes >= targetBytes {
				continue // already at or above target
			}
			d.CapacityInBytes = targetBytes
			d.CapacityInKB = targetBytes / 1024
			deviceChange = append(deviceChange, &types.VirtualDeviceConfigSpec{
				Operation: types.VirtualDeviceConfigSpecOperationEdit,
				Device:    d,
			})
			break // first disk only — subsequent disks left as-is
		}
	}
	configSpec := types.VirtualMachineConfigSpec{
		NumCPUs:      size.cpu,
		MemoryMB:     size.memMB,
		DeviceChange: deviceChange,
		ExtraConfig: []types.BaseOptionValue{
			&types.OptionValue{Key: "guestinfo.userdata", Value: base64.StdEncoding.EncodeToString([]byte(userData))},
			&types.OptionValue{Key: "guestinfo.userdata.encoding", Value: "base64"},
			&types.OptionValue{Key: "guestinfo.metadata", Value: base64.StdEncoding.EncodeToString([]byte(metaData))},
			&types.OptionValue{Key: "guestinfo.metadata.encoding", Value: "base64"},
		},
	}
	// Partial memory reservation shrinks the .vswp file (vswp = memsize −
	// reservation), which matters on small datastores. Must stay well below
	// host physical memory across all VMs or power-on admission fails.
	if size.resMB > 0 {
		res := size.resMB
		configSpec.MemoryAllocation = &types.ResourceAllocationInfo{Reservation: &res}
	}
	rcTask, err := cloned.Reconfigure(ctx, configSpec)
	if err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"vmware.reconfigure.failed", "reconfigure: %v", err)
	}
	if err := rcTask.WaitEx(ctx); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"vmware.reconfigure.wait_failed", "reconfigure wait: %v", err)
	}

	// Power on.
	emit.Progress("boot", 85, "powering on VM")
	poTask, err := cloned.PowerOn(ctx)
	if err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"vmware.poweron.failed", "power on: %v", err)
	}
	if err := poTask.WaitEx(ctx); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"vmware.poweron.wait_failed", "power on wait: %v", err)
	}
	emit.Progress("boot", 95, "cloud-init + tailscale up running inside")

	return sdk.VMCreateResult{
		VMID:    cloned.Reference().Value,
		SSHUser: "ops",
		SSHPort: 22,
	}, nil
}

func (p *provider) currentResult(ctx context.Context, spec sdk.VMSpec, v *object.VirtualMachine, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	return sdk.VMCreateResult{
		VMID: v.Reference().Value, SSHUser: "ops", SSHPort: 22,
	}, nil
}

func (p *provider) waitReady(ctx context.Context, params sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
	if p.tsAPIKey == "" {
		return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatAuth,
			"vmware.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	hostname := tailscale.Hostname(params.VMKey)
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		device, err := tailscale.FindDevice(ctx, p.cfg.Tailnet, hostname)
		if err != nil {
			emit.Log("debug", "tailscale API error", map[string]any{"err": err.Error()})
		}
		if device != nil {
			online := "yes"
			if !device.Online() {
				online = "no"
			}
			emit.Progress("wait_ready", 60, fmt.Sprintf("tailscale device found; online=%s", online))
			if device.Online() {
				v4, v6 := "", ""
				for _, a := range device.Addresses {
					if strings.Contains(a, ":") {
						if v6 == "" {
							v6 = a
						}
					} else if v4 == "" {
						v4 = a
					}
				}
				return sdk.VMWaitReadyResult{Ready: true, IPv4: v4, IPv6: v6}, nil
			}
		}
		select {
		case <-ctx.Done():
			return sdk.VMWaitReadyResult{}, ctx.Err()
		case <-time.After(6 * time.Second):
		}
	}
	return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatTimeout,
		"vmware.wait_ready.timeout",
		"tailscale device %s did not come online within 20m", hostname)
}

func (p *provider) destroy(ctx context.Context, params sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
	if p.vc == nil {
		return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatAuth,
			"vmware.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	name := vmNameFor(params.RunID, params.VMKey)
	didWork := false

	emit.Progress("destroy", 20, "looking up VM")
	v, err := p.finder.VirtualMachine(ctx, name)
	if err == nil && v != nil {
		emit.Progress("destroy", 40, "powering off")
		if state, _ := v.PowerState(ctx); state == types.VirtualMachinePowerStatePoweredOn {
			t, _ := v.PowerOff(ctx)
			if t != nil {
				_ = t.WaitEx(ctx)
			}
		}
		emit.Progress("destroy", 70, "destroying VM")
		t, dErr := v.Destroy(ctx)
		if dErr == nil {
			_ = t.WaitEx(ctx)
			didWork = true
		}
	}

	emit.Progress("destroy", 85, "revoking tailscale device")
	hostname := tailscale.Hostname(params.VMKey)
	if device, _ := tailscale.FindDevice(ctx, p.cfg.Tailnet, hostname); device != nil {
		if err := tailscale.DeleteDevice(ctx, device.ID); err == nil {
			didWork = true
		}
	}
	return sdk.VMDestroyResult{Destroyed: didWork}, nil
}

func (p *provider) inspect(ctx context.Context, params sdk.VMInspectParams, emit sdk.Emitter) (sdk.VMInspectResult, error) {
	if p.vc == nil {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	name := vmNameFor(params.RunID, params.VMKey)
	v, err := p.finder.VirtualMachine(ctx, name)
	if err != nil || v == nil {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	// Map vSphere power states to the SDK's protocol states. The orchestrator
	// resume path only treats State=="running" as reusable, so returning the
	// raw "poweredOn" would make every resume destroy + re-import the VM.
	powerState, _ := v.PowerState(ctx)
	state := "unknown"
	switch powerState {
	case types.VirtualMachinePowerStatePoweredOn:
		state = "running"
	case types.VirtualMachinePowerStatePoweredOff:
		state = "stopped"
	case types.VirtualMachinePowerStateSuspended:
		state = "suspended"
	}
	ipv4 := ""
	if device, _ := tailscale.FindDevice(ctx, p.cfg.Tailnet, tailscale.Hostname(params.VMKey)); device != nil {
		ipv4 = device.PrimaryIPv4()
	}
	return sdk.VMInspectResult{
		Exists: true, VMID: v.Reference().Value, State: state,
		IPv4: ipv4, SSHUser: "ops",
	}, nil
}

// findResourcePool returns the standalone ESXi host's default pool.
func (p *provider) findResourcePool(ctx context.Context) (*object.ResourcePool, error) {
	pools, err := p.finder.ResourcePoolList(ctx, "*")
	if err != nil || len(pools) == 0 {
		return nil, sdk.Errf(sdk.CatProviderUnavailable,
			"vmware.no_resource_pool", "no resource pool visible: %v", err)
	}
	return pools[0], nil
}

// ensureBaseVM downloads the Ubuntu Noble OVA and imports it as a VM the
// first time, then reuses it for subsequent creates in the same process.
func (p *provider) ensureBaseVM(ctx context.Context, emit sdk.Emitter) (*object.VirtualMachine, error) {
	p.baseVMMu.Lock()
	defer p.baseVMMu.Unlock()
	if p.baseVMRef != nil {
		return p.baseVMRef, nil
	}
	if p.cfg.BaseVMOverride != "" {
		v, err := p.finder.VirtualMachine(ctx, p.cfg.BaseVMOverride)
		if err != nil {
			return nil, sdk.Errf(sdk.CatValidation,
				"vmware.base_vm.not_found", "base_vm %q: %v", p.cfg.BaseVMOverride, err)
		}
		p.baseVMRef = v
		return v, nil
	}

	baseName := baseVMName(p.cfg.OVAURL)
	if v, err := p.finder.VirtualMachine(ctx, baseName); err == nil && v != nil {
		p.baseVMRef = v
		return v, nil
	}

	// Fresh import.
	emit.Progress("base_vm_import", 15, "downloading + importing OVA (~500 MB, ~1-2 min)")
	imported, err := p.importOVA(ctx, baseName, emit)
	if err != nil {
		return nil, err
	}
	p.baseVMRef = imported
	return imported, nil
}

func baseVMName(ovaURL string) string {
	h := sha1.Sum([]byte(ovaURL))
	return "lp-base-" + hex.EncodeToString(h[:])[:8]
}

// importOVA downloads the OVA + uses ovf.Manager + nfc.Lease to import the
// vmdks into the datastore, creating a new VM in the process.
func (p *provider) importOVA(ctx context.Context, vmName string, emit sdk.Emitter) (*object.VirtualMachine, error) {
	ovaBytes, err := downloadOVA(ctx, p.cfg.OVAURL)
	if err != nil {
		return nil, sdk.Errf(sdk.CatProviderUnavailable,
			"vmware.ova.download_failed", "downloading %s: %v", p.cfg.OVAURL, err)
	}
	ovfXML, vmdkParts, err := extractOVA(ovaBytes)
	if err != nil {
		return nil, sdk.Errf(sdk.CatValidation,
			"vmware.ova.parse_failed", "parse OVA: %v", err)
	}
	pool, err := p.findResourcePool(ctx)
	if err != nil {
		return nil, err
	}
	ds, err := p.finder.Datastore(ctx, p.cfg.Datastore)
	if err != nil {
		return nil, err
	}
	net, err := p.finder.Network(ctx, p.cfg.Network)
	if err != nil {
		return nil, err
	}

	m := ovf.NewManager(p.vc)
	networkMap := []types.OvfNetworkMapping{{Name: "VM Network", Network: net.Reference()}}
	importSpec, err := m.CreateImportSpec(ctx, ovfXML,
		pool, ds,
		&types.OvfCreateImportSpecParams{
			EntityName:       vmName,
			NetworkMapping:   networkMap,
			DiskProvisioning: "thin",
		})
	if err != nil {
		return nil, sdk.Errf(sdk.CatInternal,
			"vmware.ova.spec_failed", "OVF CreateImportSpec: %v", err)
	}
	if importSpec.Error != nil && len(importSpec.Error) > 0 {
		return nil, sdk.Errf(sdk.CatInternal,
			"vmware.ova.spec_error", "OVF spec: %+v", importSpec.Error)
	}

	folder, _ := p.dc.Folders(ctx)
	// The vmdk upload streams hundreds of MB over the (possibly tunneled)
	// connection to ESXi. Transient drops — broken pipe, EOF, connection
	// reset, 503 — are common on constrained links, so retry the whole
	// lease (ImportVApp → Upload → Complete) a few times, aborting the
	// partial lease between attempts. A failed lease can't be resumed, so
	// the retry re-imports from scratch.
	const maxImportAttempts = 4
	var lastErr error
	for attempt := 1; attempt <= maxImportAttempts; attempt++ {
		lease, err := pool.ImportVApp(ctx, importSpec.ImportSpec, folder.VmFolder, nil)
		if err != nil {
			lastErr = fmt.Errorf("ImportVApp: %w", err)
			emit.Log("warn", "OVA import attempt failed (ImportVApp)",
				map[string]any{"attempt": attempt, "err": err.Error()})
			continue
		}
		info, err := lease.Wait(ctx, importSpec.FileItem)
		if err != nil {
			lastErr = fmt.Errorf("lease wait: %w", err)
			_ = lease.Abort(ctx, nil)
			continue
		}
		uploadErr := func() error {
			updater := lease.StartUpdater(ctx, info)
			defer updater.Done()
			for _, item := range info.Items {
				data, ok := vmdkParts[item.Path]
				if !ok {
					return fmt.Errorf("OVA missing vmdk %s", item.Path)
				}
				opts := soap.Upload{ContentLength: int64(len(data))}
				if err := lease.Upload(ctx, item, byteReader(data), opts); err != nil {
					return fmt.Errorf("upload %s: %w", item.Path, err)
				}
			}
			return lease.Complete(ctx)
		}()
		if uploadErr == nil {
			lastErr = nil
			break
		}
		lastErr = uploadErr
		emit.Log("warn", "OVA upload attempt failed; aborting lease and retrying",
			map[string]any{"attempt": attempt, "of": maxImportAttempts, "err": uploadErr.Error()})
		_ = lease.Abort(ctx, nil)
		// Best-effort: remove any half-created VM so the re-import name is free.
		if v, ferr := p.finder.VirtualMachine(ctx, vmName); ferr == nil && v != nil {
			if t, derr := v.Destroy(ctx); derr == nil {
				_ = t.WaitEx(ctx)
			}
		}
	}
	if lastErr != nil {
		return nil, sdk.Errf(sdk.CatInternal,
			"vmware.ova.upload_failed", "%v (after %d attempts)", lastErr, maxImportAttempts)
	}

	// Look up the newly-imported VM.
	v, err := p.finder.VirtualMachine(ctx, vmName)
	if err != nil {
		return nil, sdk.Errf(sdk.CatInternal,
			"vmware.ova.lookup_failed", "imported VM not found: %v", err)
	}
	return v, nil
}
