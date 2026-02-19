package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsConfigFileKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"nginx.conf", true},
		{"default.conf", true},
		{"grafana.ini", true},
		{"config.yaml", true},
		{"settings.yml", true},
		{"dashboard.json", true},
		{"app.toml", true},
		{"schema.xml", true},
		{"init.sh", true},
		{"alertmanager.rules", true},
		{"config.properties", true},
		{"main.tf", true},
		{"policy.hcl", true},
		{"index.html", true},
		{"style.css", true},
		{"config.lua", true},
		{"source.map", true},
		{"NGINX.CONF", true},
		{"password", false},
		{"api_key", false},
		{"data_blob", false},
		{"secret", false},
		{"my-setting", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.want, IsConfigFileKey(tt.key))
		})
	}
}

func TestIsSecretKeyName(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"PASSWORD", true},
		{"db_password", true},
		{"API_KEY", true},
		{"api-key", true},
		{"PRIVATE_KEY", true},
		{"access_key_id", true},
		{"SECRET_KEY", true},
		{"auth_token", true},
		{"credentials", true},
		{"CONNECTION_STRING", true},
		{"encryption_key", true},
		{"name", false},
		{"port", false},
		{"host", false},
		{"replicas", false},
		{"LOG_LEVEL", false},
		{"DEBUG", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.want, IsSecretKeyName(tt.key))
		})
	}
}

func TestHasKnownSecretPattern(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"JWT token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig", true},
		{"AWS access key", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS session token", "ASIAXYZ123456789", true},
		{"PEM private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", true},
		{"PEM certificate (public, not secret)", "-----BEGIN CERTIFICATE-----\nMIIE...", false},
		{"GitHub PAT", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true},
		{"GitHub OAuth", "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true},
		{"Slack bot token", "xoxb-1234-5678-abcdef", true},
		{"Slack user token", "xoxp-1234-5678-abcdef", true},
		{"normal value", "hello-world", false},
		{"number", "12345", false},
		{"URL", "https://example.com", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasKnownSecretPattern(tt.value))
		})
	}
}

func TestIsLikelySecret(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"short string", "abc", false},
		{"low entropy long string", "aaaaaaaaaaaaaaaaaaaaaa", false},
		{"high entropy long string", "aB3$kL9mNp2QrS5tUv8WxYz1", true},
		{"config value", "localhost:5432", false},
		{"random token", "x7Kf9pL2mQ4nR8sT1uV3wY5zA6bC0dE9", true},
		{"PEM public certificate", "-----BEGIN CERTIFICATE-----\nMIIE0DCCArgCAQEwDQYJKoZIhvcNAQELBQAwgY0xCzAJBgNVBAY", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsLikelySecret(tt.value, DefaultEntropyThreshold))
		})
	}
}

func TestIsLikelySecretCustomThreshold(t *testing.T) {
	value := "aB3$kL9mNp2QrS5tUv8WxYz1"
	assert.True(t, IsLikelySecret(value, 3.0))
	assert.False(t, IsLikelySecret(value, 6.0))
}

func TestIsLikelySecretDefaultThreshold(t *testing.T) {
	// Zero threshold should use default.
	value := "aB3$kL9mNp2QrS5tUv8WxYz1"
	assert.True(t, IsLikelySecret(value, 0))
}

func TestSecretTypeForKeys(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		want string
	}{
		{"TLS secret", []string{"tls.crt", "tls.key"}, "kubernetes.io/tls"},
		{"Docker config", []string{".dockerconfigjson"}, "kubernetes.io/dockerconfigjson"},
		{"Docker cfg", []string{".dockercfg"}, "kubernetes.io/dockercfg"},
		{"Basic auth", []string{"username", "password"}, "kubernetes.io/basic-auth"},
		{"SSH auth", []string{"ssh-privatekey"}, "kubernetes.io/ssh-auth"},
		{"no match", []string{"config.yaml", "data"}, ""},
		{"partial TLS", []string{"tls.crt"}, ""},
		{"partial basic auth", []string{"username"}, ""},
		{"empty", []string{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SecretTypeForKeys(tt.keys))
		})
	}
}
