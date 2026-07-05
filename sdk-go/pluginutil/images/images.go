// Package images fetches and caches a base cloud image on the target host over
// SSH. Launchpad plugins should not require the operator to pre-stage a base
// image: given a URL the image is fetched *on the target host* (where it is
// used) and cached under work_dir/_images by default, keyed by a short hash of
// the URL to avoid filename collisions across mirrors.
//
// Verification is opt-in: when SHA256 is set the image is verified with
// sha256sum on the target and mismatches are refused. When unset, a present
// non-empty file counts as a cache hit — pinning is the operator's call.
package images

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	sdk "github.com/soctalk/launchpad-sdk-go"
	"github.com/soctalk/launchpad-sdk-go/pluginutil/sshhost"
	"golang.org/x/crypto/ssh"
)

// Options describes where the base image comes from and where it is cached.
// ErrPrefix is prepended to emitted error codes (e.g. "qemu" →
// "qemu.image.download_failed") so per-plugin diagnostics are preserved.
type Options struct {
	ErrPrefix       string
	BaseImage       string // pre-staged local path on the host; wins when set
	BaseImageURL    string // URL to fetch when BaseImage is empty
	BaseImageSHA256 string // optional pin; verified when set
	ImageCacheDir   string // cache dir; defaults to WorkDir/_images
	WorkDir         string
}

// Cache memoizes the resolved on-host image path for a single plugin process,
// and serializes concurrent Ensure calls so parallel vm.create dispatch does
// not race on the download. Use one Cache per plugin (a package-level var).
type Cache struct {
	mu     sync.Mutex
	cached string
}

// Ensure resolves the base image on the host and returns its path. A
// pre-staged Options.BaseImage wins (optionally sha256-verified); otherwise the
// image is downloaded from Options.BaseImageURL and cached.
func (c *Cache) Ensure(ctx context.Context, client *ssh.Client, opts Options, emit sdk.Emitter) (string, error) {
	// Operator-supplied local path wins. If they also pinned a sha256, honor
	// it — a stale/corrupted pre-staged image should surface here, not deep
	// inside the boot log.
	if opts.BaseImage != "" {
		if opts.BaseImageSHA256 != "" {
			emit.Progress("image_verify", 12, "verifying sha256 of pre-staged image")
			ok, err := cacheHit(ctx, client, opts.BaseImage, opts.BaseImageSHA256)
			if err != nil {
				return "", sdk.Errf(sdk.CatInternal,
					opts.ErrPrefix+".image.sha256_failed",
					"computing sha256 of pre-staged %s: %v", opts.BaseImage, err)
			}
			if !ok {
				return "", sdk.Errf(sdk.CatValidation,
					opts.ErrPrefix+".image.sha256_mismatch",
					"pre-staged %s does not match declared sha256 %s", opts.BaseImage, opts.BaseImageSHA256)
			}
		}
		return opts.BaseImage, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != "" {
		return c.cached, nil
	}

	cacheDir := opts.ImageCacheDir
	if cacheDir == "" {
		cacheDir = opts.WorkDir + "/_images"
	}
	if _, err := sshhost.Run(ctx, client, "mkdir -p "+sshhost.ShellEscape(cacheDir)); err != nil {
		return "", sdk.Errf(sdk.CatInternal,
			opts.ErrPrefix+".image.mkdir_cache_failed",
			"cannot create image cache dir %s: %v", cacheDir, err)
	}

	filename := filepath.Base(opts.BaseImageURL)
	if filename == "" || filename == "/" {
		return "", sdk.Errf(sdk.CatValidation,
			opts.ErrPrefix+".image.bad_url",
			"cannot infer filename from base_image_url %q", opts.BaseImageURL)
	}
	urlHash := shortURLHash(opts.BaseImageURL)
	dest := fmt.Sprintf("%s/%s-%s", cacheDir, urlHash, filename)

	ok, hitErr := cacheHit(ctx, client, dest, opts.BaseImageSHA256)
	emit.Log("debug", "image cache probe", map[string]any{"dest": dest, "hit": ok, "err": fmt.Sprintf("%v", hitErr)})
	if ok {
		emit.Progress("image_cache", 12, fmt.Sprintf("cached: %s", dest))
		c.cached = dest
		return dest, nil
	}

	emit.Progress("image_download", 15, fmt.Sprintf("fetching %s", opts.BaseImageURL))
	// curl with resume; write to .part then atomically rename. `-fL` fails
	// fast on 4xx/5xx and follows redirects. `--continue-at -` resumes
	// interrupted downloads. `-sS` = silent + show errors.
	dl := fmt.Sprintf(
		"curl -fL -sS --continue-at - -o %s.part %s && mv %s.part %s",
		sshhost.ShellEscape(dest), sshhost.ShellEscape(opts.BaseImageURL),
		sshhost.ShellEscape(dest), sshhost.ShellEscape(dest),
	)
	if _, err := sshhost.Run(ctx, client, dl); err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			opts.ErrPrefix+".image.download_failed",
			"downloading %s to %s: %v", opts.BaseImageURL, dest, err)
	}

	if opts.BaseImageSHA256 != "" {
		emit.Progress("image_verify", 18, "verifying sha256")
		want := strings.ToLower(opts.BaseImageSHA256)
		got, err := sshhost.Run(ctx, client, fmt.Sprintf("sha256sum %s | awk '{print $1}'", sshhost.ShellEscape(dest)))
		if err != nil {
			return "", sdk.Errf(sdk.CatInternal,
				opts.ErrPrefix+".image.sha256_failed",
				"computing sha256 of %s: %v", dest, err)
		}
		if strings.TrimSpace(strings.ToLower(got)) != want {
			return "", sdk.Errf(sdk.CatValidation,
				opts.ErrPrefix+".image.sha256_mismatch",
				"sha256 mismatch for %s: got %s, want %s", dest, strings.TrimSpace(got), want)
		}
	}

	c.cached = dest
	return dest, nil
}

// cacheHit reports whether dest is present and (if wantSHA256 is set) matches
// the expected sha256. Missing or empty file → miss.
func cacheHit(ctx context.Context, client *ssh.Client, dest, wantSHA256 string) (bool, error) {
	// Presence + size check first (cheap).
	out, err := sshhost.Run(ctx, client, fmt.Sprintf("stat -c %%s %s 2>/dev/null || echo 0", sshhost.ShellEscape(dest)))
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(out) == "0" {
		return false, nil
	}
	if wantSHA256 == "" {
		return true, nil
	}
	got, err := sshhost.Run(ctx, client, fmt.Sprintf("sha256sum %s | awk '{print $1}'", sshhost.ShellEscape(dest)))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(strings.ToLower(got)) == strings.ToLower(wantSHA256), nil
}

func shortURLHash(url string) string {
	h := sha1.Sum([]byte(url))
	return hex.EncodeToString(h[:])[:8]
}
