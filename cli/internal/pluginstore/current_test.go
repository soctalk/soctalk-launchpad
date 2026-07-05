package pluginstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// IsCurrent must reflect signature validity, expiry, completeness, and manifest
// integrity — not just the presence of a matching binary.
func TestIsCurrentAndManifestRepair(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("PLUGIN-BINARY")
	src := buildSource(t, priv, bin, time.Now().Add(time.Hour))
	s := newStore(t)
	opts := Options{Source: src, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	if _, err := s.Sync(context.Background(), opts); err != nil {
		t.Fatalf("sync: %v", err)
	}

	if !s.IsCurrent(pub, time.Now(), runtime.GOOS, runtime.GOARCH, "0.2.0") {
		t.Fatal("store should be current immediately after a clean sync")
	}

	// A missing manifest (matching binary but no plugin.yaml) is not current,
	// and the next sync repairs it instead of reporting up-to-date.
	if err := os.Remove(filepath.Join(s.Dir(), "qemu", "plugin.yaml")); err != nil {
		t.Fatal(err)
	}
	if s.IsCurrent(pub, time.Now(), runtime.GOOS, runtime.GOARCH, "0.2.0") {
		t.Fatal("missing manifest must not count as current")
	}
	rep, err := s.Sync(context.Background(), opts)
	if err != nil {
		t.Fatalf("repair sync: %v", err)
	}
	if !contains(rep.Installed, "qemu") {
		t.Fatalf("expected qemu reinstalled to repair manifest, got %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), "qemu", "plugin.yaml")); err != nil {
		t.Fatalf("manifest not restored: %v", err)
	}

	// An expired cached index is never current (even with matching files), so
	// auto-sync refreshes a repairable store rather than stalling.
	if s.IsCurrent(pub, time.Now().Add(2*time.Hour), runtime.GOOS, runtime.GOARCH, "0.2.0") {
		t.Fatal("expired cached index must not count as current")
	}

	// A wrong key on the cached index is not current.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if s.IsCurrent(otherPub, time.Now(), runtime.GOOS, runtime.GOARCH, "0.2.0") {
		t.Fatal("cache signed by another key must not count as current")
	}

	// An upgraded CLI (different wanted version) must not trust the old cache.
	if s.IsCurrent(pub, time.Now(), runtime.GOOS, runtime.GOARCH, "0.3.0") {
		t.Fatal("cache from a different release must not count as current")
	}

	// A plugin.yaml whose executable no longer points at the hashed binary is
	// not current, even though the binary itself still matches.
	yml := filepath.Join(s.Dir(), "qemu", "plugin.yaml")
	b, _ := os.ReadFile(yml)
	if err := os.WriteFile(yml, []byte(strings.Replace(string(b), "./plugin", "./evil", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if s.IsCurrent(pub, time.Now(), runtime.GOOS, runtime.GOARCH, "0.2.0") {
		t.Fatal("manifest with a redirected executable must not count as current")
	}
}
