// Package targetresolver maps run-config targets to plugin manifests. It is the
// single owner of target discovery, shared by the CLI (`up`/`down`) and the
// HTTP run manager so the two can't drift.
package targetresolver

import (
	"fmt"
	"strings"

	"github.com/soctalk/launchpad/internal/orchestrator"
	"github.com/soctalk/launchpad/internal/pluginhost"
)

// Resolve discovers manifests for every target the config references — the
// top-level Config.Target plus any per-VM Target override — keyed by target.
func Resolve(cfg orchestrator.Config) (map[string]*pluginhost.Manifest, error) {
	seen := map[string]struct{}{}
	if cfg.Target != "" {
		seen[cfg.Target] = struct{}{}
	}
	if t := cfg.MSSP.Target; t != "" {
		seen[t] = struct{}{}
	}
	for _, tn := range cfg.Tenants {
		if t := tn.Target; t != "" {
			seen[t] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no target specified (set config.target or a per-VM target)")
	}
	out := map[string]*pluginhost.Manifest{}
	for name := range seen {
		m, err := Manifest(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = m
	}
	return out, nil
}

// Manifest resolves a single target to its plugin manifest. A target may be a
// composed "platform@host" key, a bare platform name, or a path to a plugin
// directory; the plugin is selected by the platform half.
func Manifest(nameOrPath string) (*pluginhost.Manifest, error) {
	if strings.ContainsRune(nameOrPath, '/') || strings.ContainsRune(nameOrPath, '.') {
		return pluginhost.LoadManifest(nameOrPath)
	}
	name := orchestrator.PlatformOfTarget(nameOrPath)
	manifests, _ := pluginhost.DiscoverPlugins()
	for _, m := range manifests {
		if m.Name == name {
			return m, nil
		}
	}
	return nil, fmt.Errorf("plugin %q not found (check `launchpad plugin list`)", name)
}
