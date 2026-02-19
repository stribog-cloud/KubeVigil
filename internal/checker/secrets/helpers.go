// Package secrets implements secrets management security checkers.
package secrets

import (
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GVR definitions for secrets-related resource types.
var (
	// SecretGVR is the GroupVersionResource for core/v1 Secret objects.
	SecretGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	// ConfigMapGVR is the GroupVersionResource for core/v1 ConfigMap objects.
	ConfigMapGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
)

// ExternalSecret CRD GVRs for external-secrets operator.
var (
	// ExternalSecretGVR is the GroupVersionResource for external-secrets.io/v1beta1 ExternalSecret objects.
	ExternalSecretGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets",
	}
	// SecretStoreGVR is the GroupVersionResource for external-secrets.io/v1beta1 SecretStore objects.
	SecretStoreGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "secretstores",
	}
	// ClusterSecretStoreGVR is the GroupVersionResource for external-secrets.io/v1beta1 ClusterSecretStore objects.
	ClusterSecretStoreGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "clustersecretstores",
	}
)

// Default thresholds for secrets detection.
const (
	// DefaultEntropyThreshold is the minimum Shannon entropy to flag a value as potentially secret.
	DefaultEntropyThreshold = 4.5
	// DefaultMinSecretLength is the minimum string length to consider for entropy-based detection.
	DefaultMinSecretLength = 16
	// DefaultMaxAgeDays is the maximum age in days before a secret is flagged for rotation.
	DefaultMaxAgeDays = 90
)

// secretKeyPatterns contains substrings that suggest a key name holds a secret value.
var secretKeyPatterns = []string{
	"password", "passwd", "pwd",
	"secret", "token",
	"api_key", "apikey", "api-key",
	"private_key", "privatekey", "private-key",
	"access_key", "accesskey", "access-key",
	"secret_key", "secretkey", "secret-key",
	"auth", "credentials", "credential",
	"connection_string", "connectionstring", "connection-string",
	"encryption_key", "encryptionkey", "encryption-key",
}

// configFileExtensions are file extensions that indicate config files.
// Config files naturally have high entropy but are not secrets.
var configFileExtensions = []string{
	".conf", ".cfg", ".ini", ".toml",
	".yaml", ".yml", ".json", ".xml",
	".properties", ".env.example",
	".sh", ".bash", ".zsh",
	".lua", ".py", ".rb", ".js",
	".html", ".htm", ".css",
	".sql", ".hcl", ".tf",
	".rules", ".map",
}

// IsConfigFileKey returns true if a ConfigMap key looks like a config filename.
// Such keys typically contain structured config content with naturally high entropy.
func IsConfigFileKey(key string) bool {
	lower := strings.ToLower(key)
	for _, ext := range configFileExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// IsSecretKeyName checks if a key name suggests it contains a secret value.
func IsSecretKeyName(key string) bool {
	lower := strings.ToLower(key)
	for _, pattern := range secretKeyPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// HasKnownSecretPattern checks if a value matches known secret format prefixes or patterns.
func HasKnownSecretPattern(value string) bool {
	// JWT token (base64url encoded JSON header).
	if strings.HasPrefix(value, "eyJ") {
		return true
	}
	// AWS access key ID.
	if strings.HasPrefix(value, "AKIA") {
		return true
	}
	// AWS secret or session token.
	if strings.HasPrefix(value, "ASIA") {
		return true
	}
	// PEM private key.
	if strings.Contains(value, "-----BEGIN") && strings.Contains(value, "PRIVATE KEY") {
		return true
	}
	// Note: -----BEGIN CERTIFICATE----- is a public certificate, not a secret. Do not match it.
	// GitHub personal access token.
	if strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "gho_") ||
		strings.HasPrefix(value, "ghu_") || strings.HasPrefix(value, "ghs_") {
		return true
	}
	// Slack token.
	if strings.HasPrefix(value, "xoxb-") || strings.HasPrefix(value, "xoxp-") {
		return true
	}
	return false
}

// IsPublicCertificate returns true if the value contains a PEM certificate (public, not secret).
// Public certificates have high entropy but are not sensitive data.
func IsPublicCertificate(value string) bool {
	return strings.Contains(value, "-----BEGIN CERTIFICATE") && !strings.Contains(value, "PRIVATE KEY")
}

// IsLikelySecret checks if a value looks like a secret based on entropy and length thresholds.
// Values that are public certificates are excluded.
func IsLikelySecret(value string, entropyThreshold float64) bool {
	if len(value) < DefaultMinSecretLength {
		return false
	}
	if IsPublicCertificate(value) {
		return false
	}
	if entropyThreshold <= 0 {
		entropyThreshold = DefaultEntropyThreshold
	}
	return ShannonEntropy(value) > entropyThreshold
}

// SecretTypeForKeys returns the recommended Secret type based on the data keys present.
// Returns empty string if no specific type is recommended.
func SecretTypeForKeys(keys []string) string {
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}

	if keySet["tls.crt"] && keySet["tls.key"] {
		return "kubernetes.io/tls"
	}
	if keySet[".dockerconfigjson"] {
		return "kubernetes.io/dockerconfigjson"
	}
	if keySet[".dockercfg"] {
		return "kubernetes.io/dockercfg"
	}
	if keySet["username"] && keySet["password"] {
		return "kubernetes.io/basic-auth"
	}
	if keySet["ssh-privatekey"] {
		return "kubernetes.io/ssh-auth"
	}
	return ""
}
