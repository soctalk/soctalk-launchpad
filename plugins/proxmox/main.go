// launchpad-plugin-proxmox provisions VMs on a Proxmox VE cluster via the
// PVE REST API. Uses cloud-init snippets for user-data injection.
//
// STATUS: v0.1.0 is a scaffold that speaks the plugin protocol correctly
// (passes launchpad's compliance suite) and exercises the PVE API shape,
// but has not been end-to-end validated against a live Proxmox cluster.
// The API integration is intentionally minimal: create-from-template,
// wait for status=running, delete. Cloud-init user-data is written as a
// snippet on the storage the cluster designates for snippets.
//
// Config (from launchpad):
//
//	endpoint:  https://pve.example:8006
//	node:      pve1 (which cluster node to target)
//	storage:   local-lvm (VM disk storage)
//	snippets:  local  (storage that accepts type "snippets")
//	template:  9000  (VM ID of a cloud-init-ready template to clone)
//	bridge:    vmbr0 (default network bridge)
//
// Env:
//
//	PROXMOX_API_TOKEN_ID     e.g. root@pam!launchpad
//	PROXMOX_API_TOKEN_SECRET the token secret
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/cloudinit"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/sshhost"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/tailscale"
)

const (
	name    = "proxmox"
	version = "0.1.0"
)

type config struct {
	Endpoint  string `json:"endpoint,omitempty"`
	Node      string `json:"node,omitempty"`
	Storage   string `json:"storage,omitempty"`
	Snippets  string `json:"snippets,omitempty"`
	Template  int    `json:"template,omitempty"`
	Bridge    string `json:"bridge,omitempty"`
	Tailnet   string `json:"tailnet,omitempty"`
	TagPrefix string `json:"tag_prefix,omitempty"`

	// SSH access to the PVE node. Proxmox's storage upload API rejects
	// content type "snippets", so cloud-init user-data snippets must be
	// written directly to the node's filesystem over SSH (agent auth).
	SSHHost     string `json:"ssh_host,omitempty"`     // e.g. "root@100.102.223.8"
	SSHPort     int    `json:"ssh_port,omitempty"`     // default 22
	SnippetsDir string `json:"snippets_dir,omitempty"` // default /var/lib/vz/snippets
}

type client struct {
	cfg  config
	http *http.Client
	auth string // "PVEAPIToken=<id>=<secret>"
}

// provider holds the plugin's mutable state, populated by initialize.
type provider struct {
	// tsAPIKey is the Tailscale API key used to mint ephemeral device auth keys.
	// Set once in initialize from the TAILSCALE_API_KEY env (injected per-run from
	// the Network resource).
	tsAPIKey  string
	pveClient *client
}

func main() {
	p := &provider{}
	err := sdk.Serve(sdk.Plugin{
		Name:    name,
		Version: version,

		AllowedEnvVars: []string{"PROXMOX_API_TOKEN_ID", "PROXMOX_API_TOKEN_SECRET", "TAILSCALE_API_KEY", "SSH_AUTH_SOCK", "HOME"},

		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"endpoint":     map[string]any{"type": "string"},
				"node":         map[string]any{"type": "string"},
				"storage":      map[string]any{"type": "string"},
				"snippets":     map[string]any{"type": "string"},
				"template":     map[string]any{"type": "integer"},
				"bridge":       map[string]any{"type": "string"},
				"tailnet":      map[string]any{"type": "string"},
				"tag_prefix":   map[string]any{"type": "string"},
				"ssh_host":     map[string]any{"type": "string"},
				"ssh_port":     map[string]any{"type": "integer", "minimum": 1, "maximum": 65535},
				"snippets_dir": map[string]any{"type": "string"},
			},
			"required":             []string{"endpoint", "node", "storage", "template"},
			"additionalProperties": false,
		},

		Initialize: p.initialize,
		Plan:       p.plan,
		Create:     p.create,
		WaitReady:  p.waitReady,
		Destroy:    p.destroy,
		Inspect:    p.inspect,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxmox plugin:", err)
		os.Exit(1)
	}
}

func (p *provider) initialize(ctx context.Context, params sdk.InitializeParams) (sdk.InitializeResult, error) {
	id, secret := os.Getenv("PROXMOX_API_TOKEN_ID"), os.Getenv("PROXMOX_API_TOKEN_SECRET")
	if id == "" || secret == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"proxmox.credentials.missing",
			"PROXMOX_API_TOKEN_ID and PROXMOX_API_TOKEN_SECRET must both be set")
	}
	c := &client{
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// Proxmox commonly runs with a self-signed cert; skip
				// verification. Operators wanting strict TLS can pin the CA
				// separately by extending this transport in a future rev.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		auth: fmt.Sprintf("PVEAPIToken=%s=%s", id, secret),
	}
	// Config.
	if raw, err := json.Marshal(params.Config); err == nil {
		_ = json.Unmarshal(raw, &c.cfg)
	}
	if c.cfg.SSHPort == 0 {
		c.cfg.SSHPort = 22
	}
	if c.cfg.SnippetsDir == "" {
		c.cfg.SnippetsDir = "/var/lib/vz/snippets"
	}
	// Tailscale API key: injected per-run from the Network resource. Required to
	// mint the ephemeral device auth key baked into the VM's cloud-init.
	p.tsAPIKey = os.Getenv("TAILSCALE_API_KEY")
	if c.cfg.Endpoint == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"proxmox.config.missing_endpoint", "config.endpoint is required")
	}
	// Ping.
	if _, err := c.get(ctx, "/api2/json/version"); err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"proxmox.api.probe_failed",
			"Proxmox API probe failed: %v", err)
	}
	p.pveClient = c
	return sdk.InitializeResult{Ready: true}, nil
}

func (p *provider) requireClient() error {
	if p.pveClient == nil {
		return sdk.Errf(sdk.CatAuth, "proxmox.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	return nil
}

func (p *provider) plan(ctx context.Context, params sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
	return sdk.VMPlanResult{
		Summary:              fmt.Sprintf("proxmox: clone template on node %s", p.pluginNodeOrPlaceholder()),
		EstimatedDurationSec: 120,
	}, nil
}

func (p *provider) pluginNodeOrPlaceholder() string {
	if p.pveClient != nil {
		return p.pveClient.cfg.Node
	}
	return "<node>"
}

// vmidForKey deterministically maps a vm_key to a VMID in [10000, 60000). This
// avoids VMID collisions across launchpad runs on the same cluster.
func vmidForKey(runID, vmKey string) int {
	var sum int
	for _, r := range runID + "/" + vmKey {
		sum = sum*31 + int(r)
	}
	if sum < 0 {
		sum = -sum
	}
	return 10000 + (sum % 50000)
}

func (p *provider) create(ctx context.Context, params sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	if err := p.requireClient(); err != nil {
		return sdk.VMCreateResult{}, err
	}
	spec := params.Spec
	vmid := vmidForKey(spec.RunID, spec.VMKey)
	c := p.pveClient

	// If vmid exists already, reuse (idempotent).
	emit.Progress("lookup", 5, fmt.Sprintf("checking for existing vmid=%d", vmid))
	existing, err := c.get(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/current", c.cfg.Node, vmid))
	if err == nil && existing != nil {
		emit.Log("info", "reusing existing VM", map[string]any{"vmid": vmid})
		return c.buildCreateResult(ctx, vmid, spec)
	}

	// Clone from template.
	emit.Progress("clone", 30, fmt.Sprintf("cloning template %d → vmid=%d", c.cfg.Template, vmid))
	form := url.Values{}
	form.Set("newid", fmt.Sprint(vmid))
	form.Set("name", sanitizeName(spec.Name, spec.VMKey))
	form.Set("full", "1")
	cloneRaw, err := c.post(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/clone", c.cfg.Node, c.cfg.Template), form)
	if err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"proxmox.clone_failed", "%v", err)
	}
	// The clone endpoint returns a task UPID and runs asynchronously; the new
	// VM stays locked until the task finishes. Wait for it before writing
	// cicustom or starting the VM, otherwise those calls race the copy and
	// fail with lock/not-found errors.
	var cloneResp struct {
		Data string `json:"data"`
	}
	_ = json.Unmarshal(cloneRaw, &cloneResp)
	if upid := cloneResp.Data; upid != "" {
		emit.Progress("clone", 40, "waiting for clone task to finish")
		if err := c.waitTask(ctx, upid); err != nil {
			return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
				"proxmox.clone_failed", "clone task: %v", err)
		}
	}

	// Mint a Tailscale ephemeral auth key and compose cloud-init that installs
	// Tailscale and joins the tailnet on first boot. The orchestrator then
	// resolves this VM by its tailnet hostname (lp-<vmKey>).
	emit.Progress("tailscale", 50, "minting device auth key")
	tag := tailscale.TagForSpec(spec, p.pveClient.cfg.TagPrefix)
	tskey, err := tailscale.MintKey(ctx, c.cfg.Tailnet, tag)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}
	ud := cloudinit.Compose(cloudinit.Inputs{
		Hostname:      tailscale.Hostname(spec.VMKey),
		SSHKeys:       cloudinit.MergeSSHKeys(nil, spec.SSHKeys),
		TailscaleKey:  tskey,
		TailscaleTag:  tag,
		ExtraUserData: spec.UserData,
	})

	// Write user-data snippet (raw #cloud-config; Proxmox cicustom snippets are
	// not base64-encoded). Always written so the VM joins the tailnet.
	emit.Progress("cloud_init", 60, "writing cloud-init snippet")
	if err := c.writeUserDataSnippet(ctx, vmid, ud); err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Start the VM.
	emit.Progress("start", 85, "starting VM")
	if _, err := c.post(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/start", c.cfg.Node, vmid), url.Values{}); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"proxmox.start_failed", "%v", err)
	}
	emit.Progress("create", 100, "VM cloned and started")
	return c.buildCreateResult(ctx, vmid, spec)
}

func (p *provider) waitReady(ctx context.Context, params sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
	if err := p.requireClient(); err != nil {
		return sdk.VMWaitReadyResult{}, err
	}
	// Deeper cloud-init readiness is deferred to the launchpad's SSH probe.
	// Here we just check qemu status transitions to "running".
	c := p.pveClient
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		body, err := c.get(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%s/status/current", c.cfg.Node, params.VMID))
		if err != nil {
			return sdk.VMWaitReadyResult{}, err
		}
		if strings.Contains(string(body), `"status":"running"`) {
			return sdk.VMWaitReadyResult{Ready: true}, nil
		}
		select {
		case <-ctx.Done():
			return sdk.VMWaitReadyResult{}, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatTimeout,
		"proxmox.wait_ready.timeout", "VM did not reach running within 20m")
}

func (p *provider) destroy(ctx context.Context, params sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
	if err := p.requireClient(); err != nil {
		return sdk.VMDestroyResult{}, err
	}
	c := p.pveClient
	vmid := 0
	if params.VMID != "" {
		fmt.Sscanf(params.VMID, "%d", &vmid)
	} else {
		vmid = vmidForKey(params.RunID, params.VMKey)
	}
	// Check existence.
	if _, err := c.get(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/current", c.cfg.Node, vmid)); err != nil {
		return sdk.VMDestroyResult{Destroyed: false}, nil
	}
	emit.Progress("stop", 20, "stopping VM")
	_, _ = c.post(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/stop", c.cfg.Node, vmid), url.Values{})
	emit.Progress("destroy", 70, "deleting VM")
	if _, err := c.delete(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d?purge=1", c.cfg.Node, vmid)); err != nil {
		return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"proxmox.delete_failed", "%v", err)
	}
	return sdk.VMDestroyResult{Destroyed: true}, nil
}

func (p *provider) inspect(ctx context.Context, params sdk.VMInspectParams, emit sdk.Emitter) (sdk.VMInspectResult, error) {
	if err := p.requireClient(); err != nil {
		return sdk.VMInspectResult{}, err
	}
	c := p.pveClient
	vmid := 0
	if params.VMID != "" {
		fmt.Sscanf(params.VMID, "%d", &vmid)
	} else {
		vmid = vmidForKey(params.RunID, params.VMKey)
	}
	body, err := c.get(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/current", c.cfg.Node, vmid))
	if err != nil {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	state := "unknown"
	if strings.Contains(string(body), `"status":"running"`) {
		state = "running"
	} else if strings.Contains(string(body), `"status":"stopped"`) {
		state = "stopped"
	}
	return sdk.VMInspectResult{
		Exists: true, VMID: fmt.Sprint(vmid), State: state, SSHUser: "ops",
	}, nil
}

// ------------------------------------------------------------------
// PVE API helpers
// ------------------------------------------------------------------

func (c *client) get(ctx context.Context, path string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.cfg.Endpoint+path, nil)
	return c.do(req)
}
func (c *client) post(ctx context.Context, path string, form url.Values) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", c.cfg.Endpoint+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}
func (c *client) delete(ctx context.Context, path string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "DELETE", c.cfg.Endpoint+path, nil)
	return c.do(req)
}

// waitTask polls a PVE task (identified by its UPID) until it stops, returning
// an error if it exits with anything other than "OK". Endpoints such as clone
// run asynchronously and leave the VM locked until the task completes, so
// callers must wait before configuring or starting the VM.
func (c *client) waitTask(ctx context.Context, upid string) error {
	// The UPID encodes the node that runs the task (UPID:<node>:...); prefer it
	// over cfg.Node so we poll the correct node in a clustered setup.
	node := c.cfg.Node
	if parts := strings.Split(upid, ":"); len(parts) > 1 && parts[1] != "" {
		node = parts[1]
	}
	path := fmt.Sprintf("/api2/json/nodes/%s/tasks/%s/status", node, url.PathEscape(upid))
	deadline := time.Now().Add(10 * time.Minute)
	for {
		raw, err := c.get(ctx, path)
		if err != nil {
			return err
		}
		var st struct {
			Data struct {
				Status     string `json:"status"`
				ExitStatus string `json:"exitstatus"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			return fmt.Errorf("decode task status: %w", err)
		}
		if st.Data.Status == "stopped" {
			if st.Data.ExitStatus != "OK" {
				return fmt.Errorf("task %s exited %q", upid, st.Data.ExitStatus)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("task %s did not finish within timeout", upid)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
func (c *client) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Authorization", c.auth)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("PVE %s %s → %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(b))
	}
	return b, nil
}

func (c *client) writeUserDataSnippet(ctx context.Context, vmid int, userData string) error {
	// Proxmox's storage upload API rejects content type "snippets" (it only
	// accepts iso/vztmpl/import), so the snippet file cannot be POSTed to the
	// API. Snippets can only live on the PVE node's filesystem — write the
	// file over SSH, then point the VM's cicustom at it via the API (which
	// does work for the config update).
	if c.cfg.Snippets == "" {
		return sdk.Errf(sdk.CatValidation,
			"proxmox.config.missing_snippets",
			"config.snippets storage is required for user-data injection")
	}
	if c.cfg.SSHHost == "" {
		return sdk.Errf(sdk.CatValidation,
			"proxmox.config.missing_ssh_host",
			"Proxmox snippet injection requires SSH access to the node: set config.ssh_host (e.g. root@100.102.223.8)")
	}

	// Write the snippet to the node's snippets dir over SSH.
	cli, err := sshhost.Dial(c.cfg.SSHHost, c.cfg.SSHPort)
	if err != nil {
		return sdk.Errf(sdk.CatProviderUnavailable,
			"proxmox.ssh.unreachable",
			"cannot SSH to %s: %v (agent-loaded key expected)", c.cfg.SSHHost, err)
	}
	defer cli.Close()

	snippetsDir := c.cfg.SnippetsDir
	if snippetsDir == "" {
		snippetsDir = "/var/lib/vz/snippets"
	}
	filename := fmt.Sprintf("lp-%d-user.yaml", vmid)
	remotePath := strings.TrimRight(snippetsDir, "/") + "/" + filename

	if _, err := sshhost.Run(ctx, cli, "mkdir -p "+sshhost.ShellEscape(snippetsDir)); err != nil {
		return sdk.Errf(sdk.CatProviderUnavailable,
			"proxmox.snippet_write_failed", "cannot create snippets dir %s: %v", snippetsDir, err)
	}
	if err := sshhost.WriteFile(cli, remotePath, []byte(userData)); err != nil {
		return sdk.Errf(sdk.CatProviderUnavailable,
			"proxmox.snippet_write_failed", "cannot write snippet %s: %v", remotePath, err)
	}

	// Point the VM at it. This API call works (only the /upload of snippets
	// content is rejected by PVE).
	sform := url.Values{}
	sform.Set("cicustom", fmt.Sprintf("user=%s:snippets/%s", c.cfg.Snippets, filename))
	_, err = c.post(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", c.cfg.Node, vmid), sform)
	return err
}

func (c *client) buildCreateResult(ctx context.Context, vmid int, spec sdk.VMSpec) (sdk.VMCreateResult, error) {
	// v1 does not query the guest agent for IPs; the launchpad post-provision
	// step is expected to do its own IP discovery via cloud-init metadata or
	// SSH-bootstrap. IPv4 stays empty here.
	return sdk.VMCreateResult{
		VMID:    fmt.Sprint(vmid),
		SSHUser: "ops",
		SSHPort: 22,
	}, nil
}

func sanitizeName(name, fallback string) string {
	if name == "" {
		name = fallback
	}
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		out = "lp-vm"
	}
	return out
}
