// Package cloudinit composes the #cloud-config user-data that launchpad
// provider plugins feed to Ubuntu cloud images. The generated config
// provisions the ops user, installs Tailscale, joins the tailnet with a minted
// auth key, and (optionally) installs the operator's extra bootstrap script as
// a oneshot systemd unit so it runs on first boot.
package cloudinit

import (
	"bytes"
	"fmt"
	"strings"
)

// Inputs are the values that vary between VMs when composing user-data.
type Inputs struct {
	Hostname      string
	SSHKeys       []string
	TailscaleKey  string
	TailscaleTag  string
	ExtraUserData string
}

// Compose builds a #cloud-config document from in. When ExtraUserData is set it
// is written to /etc/launchpad/user-extra.sh and wired to run once on boot via
// the lp-user-extra.service systemd unit.
func Compose(in Inputs) string {
	var b bytes.Buffer
	b.WriteString("#cloud-config\n")
	fmt.Fprintf(&b, "hostname: %s\n", in.Hostname)
	b.WriteString("manage_etc_hosts: true\n")
	b.WriteString("users:\n")
	b.WriteString("  - default\n")
	b.WriteString("  - name: ops\n")
	b.WriteString("    sudo: ALL=(ALL) NOPASSWD:ALL\n")
	b.WriteString("    shell: /bin/bash\n")
	if len(in.SSHKeys) > 0 {
		b.WriteString("    ssh_authorized_keys:\n")
		for _, k := range in.SSHKeys {
			fmt.Fprintf(&b, "      - %s\n", k)
		}
	}
	b.WriteString("package_update: true\n")
	b.WriteString("packages: [curl, ca-certificates, jq]\n")
	// write_files runs before runcmd, so stage the optional extra script first.
	if in.ExtraUserData != "" {
		b.WriteString("write_files:\n")
		b.WriteString("  - path: /etc/launchpad/user-extra.sh\n")
		b.WriteString("    permissions: '0755'\n")
		b.WriteString("    content: |\n")
		for _, line := range strings.Split(in.ExtraUserData, "\n") {
			fmt.Fprintf(&b, "      %s\n", line)
		}
	}
	// A SINGLE runcmd block (a second `runcmd:` key would silently override this
	// one in YAML). Installing Tailscale and joining the tailnet are each wrapped
	// in a retry loop, because some hypervisors' NAT (notably VirtualBox) settles
	// slower than the first attempt would allow.
	b.WriteString("runcmd:\n")
	b.WriteString("  - for i in $(seq 1 40); do command -v tailscale >/dev/null 2>&1 && break; curl -fsSL https://tailscale.com/install.sh | sh; sleep 5; done\n")
	fmt.Fprintf(&b,
		"  - for i in $(seq 1 40); do tailscale up --auth-key=%q --advertise-tags=%s --hostname=%s && break; sleep 5; done\n",
		in.TailscaleKey, in.TailscaleTag, in.Hostname)
	if in.ExtraUserData != "" {
		b.WriteString("  - /etc/launchpad/user-extra.sh\n")
	}
	return b.String()
}

// MergeSSHKeys returns the union of a and b, de-duplicated and whitespace-
// trimmed, preserving order (a's keys first).
func MergeSSHKeys(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, k := range append(append([]string{}, a...), b...) {
		if k = strings.TrimSpace(k); k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}
