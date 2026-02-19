package checker

// Policies holds policy configuration that checkers use for policy-based checks.
type Policies struct {
	// Images holds image-related policy configuration.
	Images ImagePolicies `yaml:"images" json:"images"`
	// Secrets holds secrets-related policy configuration.
	Secrets SecretPolicies `yaml:"secrets" json:"secrets"`
}

// SecretPolicies holds secrets-specific policy configuration.
type SecretPolicies struct {
	// EntropyThreshold is the minimum Shannon entropy (bits/char) to flag as a potential secret.
	// Default: 4.5.
	EntropyThreshold float64 `yaml:"entropy_threshold" json:"entropy_threshold"`
	// MaxAgeDays is the maximum age in days before a secret is considered stale.
	// Default: 90.
	MaxAgeDays int `yaml:"max_age_days" json:"max_age_days"`
}

// ImagePolicies holds image-specific policy configuration.
type ImagePolicies struct {
	// AllowedRegistries is a list of allowed image registries.
	AllowedRegistries []string `yaml:"allowed_registries" json:"allowed_registries"`
	// BlockedRegistries is a list of blocked image registries.
	BlockedRegistries []string `yaml:"blocked_registries" json:"blocked_registries"`
	// RequireSignatures requires images to be signed (verified by digest).
	RequireSignatures bool `yaml:"require_signatures" json:"require_signatures"`
	// RequireSBOM requires images to have SBOM attestations (verified by digest).
	RequireSBOM bool `yaml:"require_sbom" json:"require_sbom"`
	// RequireProvenance requires images to have provenance attestations (verified by digest).
	RequireProvenance bool `yaml:"require_provenance" json:"require_provenance"`
}

// HasAllowedRegistries returns true if an allowed registries list is configured.
func (p *Policies) HasAllowedRegistries() bool {
	return p != nil && len(p.Images.AllowedRegistries) > 0
}

// HasBlockedRegistries returns true if a blocked registries list is configured.
func (p *Policies) HasBlockedRegistries() bool {
	return p != nil && len(p.Images.BlockedRegistries) > 0
}
