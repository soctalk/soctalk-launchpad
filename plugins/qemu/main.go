// launchpad-plugin-qemu provisions VMs on a remote Ubuntu host over SSH
// by driving qemu-system-x86_64 with a cloud-init seed ISO. The VMs join a
// Tailscale tailnet at first boot, and the plugin returns the assigned
// Tailscale IPv4 as the primary contact address.
//
// Config (params.config):
//
//	ssh_host:     ops@100.102.223.8    (Tailscale IP or hostname)
//	ssh_port:     22                    (optional)
//	base_image:   /home/ops/noble.img   (backing store, cloud-init-ready)
//	work_dir:     /home/ops/lp-vms      (per-run subdirs created here)
//	tailnet:      tail6397c.ts.net      (tailnet name for hostname suffix)
//	cpu:          4                     (default vCPUs)
//	memory_mb:    8192                  (default memory)
//	disk_gb:      60                    (grown from base image, default)
//	tag_prefix:   ""                    (optional prefix on advertised tags)
//	ssh_keys:     ["ssh-ed25519 ..."]  (authorized keys added to ops user)
//
// Env:
//
//	TAILSCALE_API_KEY  (from https://login.tailscale.com/admin/settings/keys)
//
// Every VM ends up on the tailnet as `lp-<vm_key>.<tailnet>` with either
// `tag:mssp` (Role=mssp) or `tag:tenant-<slug>` (Role=tenant, from spec.tags).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/cloudinit"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/images"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/sshhost"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/tailscale"
	"golang.org/x/crypto/ssh"
)

const (
	name    = "qemu"
	version = "0.1.0"
)

type config struct {
	SSHHost string `json:"ssh_host"`
	SSHPort int    `json:"ssh_port,omitempty"`

	// Cloud base image. Either supply a pre-staged local path (BaseImage) OR
	// let the plugin download from a public URL (BaseImageURL) and cache it
	// on the target host. If neither is set, defaults to Ubuntu Noble.
	BaseImage       string `json:"base_image,omitempty"`
	BaseImageURL    string `json:"base_image_url,omitempty"`
	BaseImageSHA256 string `json:"base_image_sha256,omitempty"`
	ImageCacheDir   string `json:"image_cache_dir,omitempty"`

	WorkDir   string   `json:"work_dir"`
	Tailnet   string   `json:"tailnet"`
	CPU       int      `json:"cpu,omitempty"`
	MemoryMB  int      `json:"memory_mb,omitempty"`
	DiskGB    int      `json:"disk_gb,omitempty"`
	TagPrefix string   `json:"tag_prefix,omitempty"`
	SSHKeys   []string `json:"ssh_keys,omitempty"`
}

// defaultBaseImageURL is Canonical's current Ubuntu Noble amd64 cloud image.
// It is rebuilt periodically; pin base_image_sha256 in config to freeze.
const defaultBaseImageURL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"

// provider holds the plugin's mutable state for the lifetime of the process.
// tsAPIKey is the Tailscale API key, set once in initialize. imageCache
// memoizes the resolved base-image path on the target host.
type provider struct {
	cfg        config
	sshClient  *ssh.Client
	tsAPIKey   string
	imageCache images.Cache
}

func main() {
	p := &provider{}
	err := sdk.Serve(sdk.Plugin{
		Name:    name,
		Version: version,

		AllowedEnvVars: []string{"TAILSCALE_API_KEY", "SSH_AUTH_SOCK", "HOME"},

		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"ssh_host":          map[string]any{"type": "string"},
				"ssh_port":          map[string]any{"type": "integer", "minimum": 1, "maximum": 65535},
				"base_image":        map[string]any{"type": "string"},
				"base_image_url":    map[string]any{"type": "string"},
				"base_image_sha256": map[string]any{"type": "string"},
				"image_cache_dir":   map[string]any{"type": "string"},
				"work_dir":          map[string]any{"type": "string"},
				"tailnet":           map[string]any{"type": "string"},
				"cpu":               map[string]any{"type": "integer", "minimum": 1},
				"memory_mb":         map[string]any{"type": "integer", "minimum": 512},
				"disk_gb":           map[string]any{"type": "integer", "minimum": 5},
				"tag_prefix":        map[string]any{"type": "string"},
				"ssh_keys":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"ssh_host", "work_dir", "tailnet"},
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
		fmt.Fprintln(os.Stderr, "qemu plugin:", err)
		os.Exit(1)
	}
}

func (p *provider) initialize(ctx context.Context, params sdk.InitializeParams) (sdk.InitializeResult, error) {
	// Unmarshal typed config.
	if raw, err := json.Marshal(params.Config); err == nil {
		_ = json.Unmarshal(raw, &p.cfg)
	}
	if p.cfg.SSHHost == "" || p.cfg.WorkDir == "" || p.cfg.Tailnet == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"qemu.config.incomplete",
			"ssh_host, work_dir, tailnet are all required")
	}
	// Base-image source: pre-staged path OR URL to download. Default to
	// Ubuntu Noble amd64 cloud image if neither is set.
	if p.cfg.BaseImage == "" && p.cfg.BaseImageURL == "" {
		p.cfg.BaseImageURL = defaultBaseImageURL
	}
	if p.cfg.SSHPort == 0 {
		p.cfg.SSHPort = 22
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
	p.tsAPIKey = os.Getenv("TAILSCALE_API_KEY")
	if p.tsAPIKey == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"qemu.tailscale.missing_api_key",
			"TAILSCALE_API_KEY is required for minting device auth keys")
	}
	// Open SSH to the host and hold it for the plugin's lifetime.
	c, err := sshhost.Dial(p.cfg.SSHHost, p.cfg.SSHPort)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"qemu.ssh.unreachable",
			"cannot SSH to %s: %v (agent-loaded key expected)", p.cfg.SSHHost, err)
	}
	p.sshClient = c
	// Quick probe: base tooling + curl (needed when we download the cloud
	// image from a URL rather than using a pre-staged local path).
	probe := "which qemu-system-x86_64 && which genisoimage && which qemu-img"
	if p.cfg.BaseImage == "" {
		probe += " && which curl"
	}
	if _, err := sshhost.Run(ctx, p.sshClient, probe); err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"qemu.host.missing_tools",
			"host is missing qemu-system-x86_64 / genisoimage / qemu-img / curl: %v", err)
	}
	// Ensure work_dir exists.
	if _, err := sshhost.Run(ctx, p.sshClient, "mkdir -p "+sshhost.ShellEscape(p.cfg.WorkDir)); err != nil {
		return sdk.InitializeResult{}, err
	}
	return sdk.InitializeResult{Ready: true}, nil
}

func (p *provider) shutdown(ctx context.Context) error {
	if p.sshClient != nil {
		_ = p.sshClient.Close()
		p.sshClient = nil
	}
	return nil
}

func (p *provider) plan(ctx context.Context, params sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
	return sdk.VMPlanResult{
		Summary: fmt.Sprintf("qemu: %s on %s (%dvCPU/%dMB, tailscale hostname lp-%s)",
			params.Spec.Name, p.cfg.SSHHost, p.cfg.CPU, p.cfg.MemoryMB, params.Spec.VMKey),
		EstimatedDurationSec: 180,
	}, nil
}

func (p *provider) vmWorkDir(runID, vmKey string) string {
	return p.cfg.WorkDir + "/" + runID + "/" + vmKey
}

func (p *provider) create(ctx context.Context, params sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	if p.sshClient == nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatAuth,
			"qemu.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	spec := params.Spec

	work := p.vmWorkDir(spec.RunID, spec.VMKey)
	pidPath := work + "/qemu.pid"

	// Idempotency: reuse only when the process is alive AND its tailnet
	// device is online. A VM whose device was revoked is unreachable forever
	// (user-mode NAT means the tailnet is the only path in), so kill it and
	// re-provision instead of returning a dead endpoint.
	emit.Progress("lookup", 3, "checking for existing VM")
	if alive, _ := sshhost.PidAlive(ctx, p.sshClient, pidPath); alive {
		d, _ := tailscale.FindDevice(ctx, p.cfg.Tailnet, tailscale.Hostname(spec.VMKey))
		if d != nil && d.Online() {
			emit.Log("info", "reusing running QEMU VM (tailnet device online)",
				map[string]any{"pid_path": pidPath, "ipv4": d.PrimaryIPv4()})
			return p.currentResult(ctx, spec, emit)
		}
		emit.Log("warn", "existing QEMU VM has no live tailnet device — killing and re-provisioning",
			map[string]any{"pid_path": pidPath})
		_, _ = sshhost.Run(ctx, p.sshClient, "kill $(cat "+sshhost.ShellEscape(pidPath)+") 2>/dev/null || true")
		_, _ = sshhost.Run(ctx, p.sshClient,
			fmt.Sprintf("[ -d %s ] && mv %s /tmp/lp-stale-%s-$(date +%%s) || true",
				sshhost.ShellEscape(work), sshhost.ShellEscape(work), spec.VMKey))
		if d != nil {
			_ = tailscale.DeleteDevice(ctx, d.ID)
		}
	}

	// Prepare work dir.
	emit.Progress("prepare", 10, "creating work dir on host")
	if _, err := sshhost.Run(ctx, p.sshClient, "mkdir -p "+sshhost.ShellEscape(work)); err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Ensure the base cloud image is present on the target host. Downloads
	// once and caches; subsequent VMs on the same host reuse.
	baseImagePath, err := p.imageCache.Ensure(ctx, p.sshClient, images.Options{
		ErrPrefix:       "qemu",
		BaseImage:       p.cfg.BaseImage,
		BaseImageURL:    p.cfg.BaseImageURL,
		BaseImageSHA256: p.cfg.BaseImageSHA256,
		ImageCacheDir:   p.cfg.ImageCacheDir,
		WorkDir:         p.cfg.WorkDir,
	}, emit)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Mint a Tailscale ephemeral auth key.
	emit.Progress("tailscale", 20, "minting device auth key")
	tag := tailscale.TagForSpec(spec, p.cfg.TagPrefix)
	tskey, err := tailscale.MintKey(ctx, p.cfg.Tailnet, tag)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Compose cloud-init user-data. Authorize both provider-config keys and
	// launchpad-level keys (spec.SSHKeys) so a run that sets ssh_keys only at
	// the top level still boots the ops user with the operator's key.
	hostname := tailscale.Hostname(spec.VMKey)
	userData := cloudinit.Compose(cloudinit.Inputs{
		Hostname:      hostname,
		SSHKeys:       cloudinit.MergeSSHKeys(p.cfg.SSHKeys, spec.SSHKeys),
		TailscaleKey:  tskey,
		TailscaleTag:  tag,
		ExtraUserData: spec.UserData,
	})
	metaData := fmt.Sprintf("instance-id: lp-%s\nlocal-hostname: %s\n", spec.VMKey, hostname)

	// Upload user-data and meta-data.
	emit.Progress("cloud_init", 35, "writing user-data + meta-data")
	if err := sshhost.WriteFile(p.sshClient, work+"/user-data", []byte(userData)); err != nil {
		return sdk.VMCreateResult{}, err
	}
	if err := sshhost.WriteFile(p.sshClient, work+"/meta-data", []byte(metaData)); err != nil {
		return sdk.VMCreateResult{}, err
	}
	// Build seed.iso on the host.
	if _, err := sshhost.Run(ctx, p.sshClient,
		"cd "+sshhost.ShellEscape(work)+" && genisoimage -output seed.iso -volid cidata -joliet -rock user-data meta-data"); err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Create qcow2 backed by base image.
	emit.Progress("disk", 55, "creating qcow2 with backing store")
	if _, err := sshhost.Run(ctx, p.sshClient,
		fmt.Sprintf("qemu-img create -f qcow2 -F qcow2 -b %s %s/disk.qcow2 %dG",
			sshhost.ShellEscape(baseImagePath), sshhost.ShellEscape(work), p.cfg.DiskGB)); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"qemu.qemu-img.create_failed", "%v", err)
	}

	// Launch QEMU.
	//
	// Networking: user-mode (SLIRP) NAT so the guest reaches the internet to
	// download Tailscale + do apt. No hostfwd needed — Tailscale becomes the
	// overlay for anything that needs to reach the VM.
	emit.Progress("boot", 75, "spawning qemu")
	launch := fmt.Sprintf(`nohup qemu-system-x86_64 \
  -enable-kvm -machine q35 -cpu host \
  -m %d -smp %d \
  -drive file=%s/disk.qcow2,format=qcow2,if=virtio \
  -drive file=%s/seed.iso,format=raw,if=virtio,readonly=on \
  -netdev user,id=net0 \
  -device virtio-net,netdev=net0 \
  -serial file:%s/serial.log \
  -display none \
  -pidfile %s \
  -daemonize > %s/nohup.out 2>&1`,
		p.cfg.MemoryMB, p.cfg.CPU,
		sshhost.ShellEscape(work), sshhost.ShellEscape(work), sshhost.ShellEscape(work),
		sshhost.ShellEscape(pidPath), sshhost.ShellEscape(work),
	)
	if _, err := sshhost.Run(ctx, p.sshClient, launch); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"qemu.qemu.launch_failed", "%v", err)
	}

	emit.Progress("boot", 95, "qemu spawned; tailscale + cloud-init running inside")
	return sdk.VMCreateResult{
		VMID:    spec.RunID + "/" + spec.VMKey,
		SSHUser: "ops",
		SSHPort: 22,
	}, nil
}

func (p *provider) waitReady(ctx context.Context, params sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
	if p.tsAPIKey == "" {
		return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatAuth,
			"qemu.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	// Poll Tailscale API for a device matching lp-<vm_key> and wait until it's Online.
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
		"qemu.wait_ready.timeout",
		"tailscale device %s did not come online within 20m", hostname)
}

func (p *provider) destroy(ctx context.Context, params sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
	if p.sshClient == nil {
		return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatAuth,
			"qemu.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	work := p.vmWorkDir(params.RunID, params.VMKey)
	pidPath := work + "/qemu.pid"

	// Track whether we did any real work. Destroyed=false means "nothing to
	// destroy" so callers can treat repeated destroys as idempotent no-ops.
	didWork := false

	emit.Progress("destroy", 20, "checking pidfile")
	if alive, _ := sshhost.PidAlive(ctx, p.sshClient, pidPath); alive {
		_, _ = sshhost.Run(ctx, p.sshClient, "kill $(cat "+sshhost.ShellEscape(pidPath)+") 2>/dev/null || true")
		didWork = true
	}

	// Also match by work-dir path in the command line — covers the case
	// where a prior destroy moved the pidfile aside but left the qemu
	// process running. pkill returns 0 on match, 1 on no-match; the wrapper
	// echo tells us which so we can update didWork accordingly. Runs both
	// signals in one round-trip (SIGTERM then wait 1s then SIGKILL).
	emit.Progress("destroy", 40, "checking for stragglers")
	out, _ := sshhost.Run(ctx, p.sshClient, fmt.Sprintf(
		"if pkill -f %s 2>/dev/null; then echo killed; sleep 1; pkill -9 -f %s 2>/dev/null || true; fi",
		sshhost.ShellEscape("qemu-system.*"+work), sshhost.ShellEscape("qemu-system.*"+work),
	))
	if strings.Contains(out, "killed") {
		didWork = true
	}

	emit.Progress("destroy", 60, "removing work dir")
	// Move aside rather than rm-rf (reversible for forensics).
	if out, _ := sshhost.Run(ctx, p.sshClient,
		fmt.Sprintf("[ -d %s ] && mv %s /tmp/lp-destroyed-%s-$(date +%%s) && echo moved || true",
			sshhost.ShellEscape(work), sshhost.ShellEscape(work), params.VMKey)); strings.Contains(out, "moved") {
		didWork = true
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
	if p.sshClient == nil {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	work := p.vmWorkDir(params.RunID, params.VMKey)
	pidPath := work + "/qemu.pid"
	alive, _ := sshhost.PidAlive(ctx, p.sshClient, pidPath)
	hostname := tailscale.Hostname(params.VMKey)
	ipv4 := ""
	state := "unknown"
	if device, _ := tailscale.FindDevice(ctx, p.cfg.Tailnet, hostname); device != nil {
		ipv4 = device.PrimaryIPv4()
		if device.Online() {
			state = "running"
		} else {
			state = "stopped"
		}
	} else if alive {
		state = "starting"
	}
	return sdk.VMInspectResult{
		Exists:  alive || ipv4 != "",
		VMID:    params.RunID + "/" + params.VMKey,
		State:   state,
		IPv4:    ipv4,
		SSHUser: "ops",
	}, nil
}

// currentResult builds a VMCreateResult for an existing running VM by
// checking tailscale for its IP. Called during idempotent reuse.
func (p *provider) currentResult(ctx context.Context, spec sdk.VMSpec, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	res := sdk.VMCreateResult{
		VMID:    spec.RunID + "/" + spec.VMKey,
		SSHUser: "ops",
		SSHPort: 22,
	}
	if d, _ := tailscale.FindDevice(ctx, p.cfg.Tailnet, tailscale.Hostname(spec.VMKey)); d != nil {
		res.IPv4 = d.PrimaryIPv4()
	}
	return res, nil
}
