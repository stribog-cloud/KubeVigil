// Package image implements Phase 2 image security checkers and image reference parsing.
package image

import "strings"

// Ref represents a parsed container image reference.
type Ref struct {
	// Registry is the image registry (e.g., "docker.io", "gcr.io").
	Registry string
	// Repository is the image repository (e.g., "library/nginx", "my-org/my-app").
	Repository string
	// Tag is the image tag (e.g., "latest", "v1.2.3").
	Tag string
	// Digest is the image digest (e.g., "sha256:abc123...").
	Digest string
	// Raw is the original unparsed image string.
	Raw string
}

// HasTag reports whether the image reference includes an explicit tag.
func (r *Ref) HasTag() bool {
	return r.Tag != ""
}

// HasDigest reports whether the image reference includes a digest.
func (r *Ref) HasDigest() bool {
	return r.Digest != ""
}

// IsLatest reports whether the image reference resolves to the "latest" tag,
// either explicitly or implicitly (no tag and no digest).
func (r *Ref) IsLatest() bool {
	if r.Tag == "latest" {
		return true
	}
	return r.Tag == "" && r.Digest == ""
}

// IsMutableTag reports whether the image reference uses a mutable tag
// (i.e., a tag that could be re-pointed to a different image).
// Returns true if the image has a tag without a digest, or has neither
// tag nor digest (implicit latest).
func (r *Ref) IsMutableTag() bool {
	if r.HasDigest() {
		return false
	}
	// Has a tag without a digest, or implicit latest (no tag, no digest).
	return true
}

// EffectiveRegistry returns the registry for the image, defaulting to
// "docker.io" if no registry was specified.
func (r *Ref) EffectiveRegistry() string {
	if r.Registry != "" {
		return r.Registry
	}
	return "docker.io"
}

// ParseRef parses a container image string into its components.
// It handles registry, repository, tag, and digest extraction with
// proper Docker Hub normalization.
func ParseRef(image string) Ref {
	ref := Ref{Raw: image}

	if image == "" {
		return ref
	}

	remainder := image

	// Step 1: Split off digest (everything after @).
	if idx := strings.Index(remainder, "@"); idx != -1 {
		ref.Digest = remainder[idx+1:]
		remainder = remainder[:idx]
	}

	// Step 2: Extract tag.
	// The tag separator is the last ":" where the part after it contains no "/".
	// This distinguishes a tag from a registry port (e.g., localhost:5000/app).
	ref.Tag, remainder = splitTag(remainder)

	// Step 3: Determine registry vs repository.
	ref.Registry, ref.Repository = splitRegistryRepo(remainder)

	// Step 4: Normalize Docker Hub references.
	ref.Repository = normalizeDockerhubRepo(ref.Registry, ref.Repository)

	return ref
}

// splitTag extracts the tag from the image string, returning the tag and the
// remaining string (without the tag). The tag is the part after the last ":"
// that does not contain a "/".
func splitTag(s string) (tag, remainder string) {
	lastColon := strings.LastIndex(s, ":")
	if lastColon == -1 {
		return "", s
	}

	afterColon := s[lastColon+1:]
	// If the part after the colon contains "/", it's not a tag — it's
	// part of a registry:port/repo path.
	if strings.Contains(afterColon, "/") {
		return "", s
	}

	return afterColon, s[:lastColon]
}

// splitRegistryRepo separates the registry from the repository path.
// The first path component is the registry if it contains a ".", ":",
// or is exactly "localhost". Otherwise, the entire string is the repository
// (implying Docker Hub).
func splitRegistryRepo(s string) (registry, repo string) {
	slashIdx := strings.Index(s, "/")
	if slashIdx == -1 {
		// No slash: bare image name like "nginx".
		return "", s
	}

	firstComponent := s[:slashIdx]
	rest := s[slashIdx+1:]

	if isRegistryComponent(firstComponent) {
		return firstComponent, rest
	}

	// Not a registry — the whole thing is the repo path on Docker Hub.
	return "", s
}

// isRegistryComponent reports whether a path component looks like a
// registry hostname. It returns true if the component contains a dot,
// a colon, or is exactly "localhost".
func isRegistryComponent(component string) bool {
	if component == "localhost" {
		return true
	}
	if strings.ContainsAny(component, ".:") {
		return true
	}
	return false
}

// normalizeDockerhubRepo normalizes Docker Hub repository names.
// For Docker Hub (empty registry or "docker.io"), a single-component
// repo like "nginx" becomes "library/nginx".
func normalizeDockerhubRepo(registry, repo string) string {
	if registry != "" && registry != "docker.io" {
		return repo
	}
	// Docker Hub: single-component repos get the "library/" prefix.
	if !strings.Contains(repo, "/") {
		return "library/" + repo
	}
	return repo
}
