// Package tailscale provides shared helpers for launchpad provider plugins
// that join provisioned VMs to a Tailscale tailnet: minting ephemeral device
// auth keys, looking up / deleting devices via the Tailscale API, and deriving
// stable hostnames and advertised tags from a VMSpec.
//
// The Tailscale API key is read from the TAILSCALE_API_KEY environment variable
// at call time. Plugins are expected to validate its presence during
// initialize (and to list it in AllowedEnvVars).
package tailscale

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"
)

// apiKey returns the Tailscale API key from the environment. Empty when unset;
// the API call will then fail with an auth error, which callers surface.
func apiKey() string { return os.Getenv("TAILSCALE_API_KEY") }

// MintKey requests a new ephemeral auth key from the tailnet API. The key is
// single-use, ephemeral, and pre-authorized (tag-scoped so it can be
// auto-approved when the tag is trusted in the ACL).
func MintKey(ctx context.Context, tailnet, tag string) (string, error) {
	if tailnet == "" {
		return "", fmt.Errorf("tailnet is empty")
	}
	payload := map[string]any{
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					"reusable":      false,
					"ephemeral":     true,
					"preauthorized": true,
					"tags":          []string{tag},
				},
			},
		},
		"expirySeconds": 3600,
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/keys", tailnet)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(apiKey(), "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"tailscale.api_error", "%v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", sdk.Errf(sdk.CatAuth,
			"tailscale.api_status",
			"tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", sdk.Errf(sdk.CatInternal,
			"tailscale.key_missing", "no key in tailscale response: %s", string(raw))
	}
	return out.Key, nil
}

// Device mirrors the Tailscale API device object fields plugins consume.
type Device struct {
	ID                string   `json:"id"`
	Hostname          string   `json:"hostname"`
	Name              string   `json:"name"`
	Addresses         []string `json:"addresses"`
	LastSeen          string   `json:"lastSeen"`
	Authorized        bool     `json:"authorized"`
	NodeKey           string   `json:"nodeKey"`
	Machine           string   `json:"machine"`
	Tags              []string `json:"tags"`
	Expires           string   `json:"expires"`
	KeyExpiryDisabled bool     `json:"keyExpiryDisabled"`
}

// PrimaryIPv4 returns the device's first IPv4 tailnet address, or "".
func (d *Device) PrimaryIPv4() string {
	for _, a := range d.Addresses {
		if strings.Count(a, ".") == 3 {
			return a
		}
	}
	return ""
}

// Online reports whether the device has been seen within the last 3 minutes.
func (d *Device) Online() bool {
	if d.LastSeen == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, d.LastSeen)
	if err != nil {
		return false
	}
	return time.Since(t) < 3*time.Minute
}

// FindDevice returns the tailnet device whose hostname matches (or whose name
// is hostname.<tailnet>), or (nil, nil) when no device matches.
func FindDevice(ctx context.Context, tailnet, hostname string) (*Device, error) {
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", tailnet)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.SetBasicAuth(apiKey(), "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Devices []Device `json:"devices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	for i := range out.Devices {
		d := &out.Devices[i]
		if d.Hostname == hostname {
			return d, nil
		}
		// Match Name prefix (name is hostname.tailnet).
		if strings.HasPrefix(d.Name, hostname+".") {
			return d, nil
		}
	}
	return nil, nil
}

// DeleteDevice removes a device from the tailnet by its device ID.
func DeleteDevice(ctx context.Context, id string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE",
		"https://api.tailscale.com/api/v2/device/"+id, nil)
	req.SetBasicAuth(apiKey(), "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete device %s: %d %s", id, resp.StatusCode, string(raw))
	}
	return nil
}

// SanitizeHostname lower-cases s and replaces any character outside [a-z0-9-]
// with '-', trims leading/trailing dashes, caps length at 40, and falls back to
// a random "lp-<hex>" when the result is empty.
func SanitizeHostname(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
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
		buf := make([]byte, 4)
		_, _ = rand.Read(buf)
		out = "lp-" + hex.EncodeToString(buf)
	}
	return out
}

// Hostname returns the tailnet hostname for a VM: "lp-" + SanitizeHostname(vmKey).
func Hostname(vmKey string) string {
	return "lp-" + SanitizeHostname(vmKey)
}

// TagForSpec returns the tag a VM advertises on the tailnet. Role=mssp →
// tag:<prefix>mssp, Role=tenant with a slug → tag:<prefix>tenant-<slug>,
// otherwise tag:<prefix>lp-<vm_key>. prefix is the operator-configured tag
// prefix (often "").
func TagForSpec(spec sdk.VMSpec, prefix string) string {
	role := spec.Tags["role"]
	slug := spec.Tags["tenant_slug"]
	if role == "mssp" {
		return "tag:" + prefix + "mssp"
	}
	if role == "tenant" && slug != "" {
		return "tag:" + prefix + "tenant-" + slug
	}
	return "tag:" + prefix + "lp-" + spec.VMKey
}
