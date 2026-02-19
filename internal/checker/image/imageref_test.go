package image

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantReg    string
		wantRepo   string
		wantTag    string
		wantDigest string
	}{
		{
			name:     "bare image name",
			input:    "nginx",
			wantReg:  "",
			wantRepo: "library/nginx",
		},
		{
			name:     "bare image with latest tag",
			input:    "nginx:latest",
			wantReg:  "",
			wantRepo: "library/nginx",
			wantTag:  "latest",
		},
		{
			name:     "bare image with version tag",
			input:    "nginx:1.25",
			wantReg:  "",
			wantRepo: "library/nginx",
			wantTag:  "1.25",
		},
		{
			name:       "bare image with digest only",
			input:      "nginx@sha256:abc123",
			wantReg:    "",
			wantRepo:   "library/nginx",
			wantDigest: "sha256:abc123",
		},
		{
			name:       "bare image with tag and digest",
			input:      "nginx:1.25@sha256:abc123",
			wantReg:    "",
			wantRepo:   "library/nginx",
			wantTag:    "1.25",
			wantDigest: "sha256:abc123",
		},
		{
			name:     "docker hub org/repo with tag",
			input:    "myrepo/myapp:v1",
			wantReg:  "",
			wantRepo: "myrepo/myapp",
			wantTag:  "v1",
		},
		{
			name:     "gcr.io with project path",
			input:    "gcr.io/my-project/my-app:v1",
			wantReg:  "gcr.io",
			wantRepo: "my-project/my-app",
			wantTag:  "v1",
		},
		{
			name:     "artifact registry (multi-level path)",
			input:    "us-docker.pkg.dev/proj/repo/img:latest",
			wantReg:  "us-docker.pkg.dev",
			wantRepo: "proj/repo/img",
			wantTag:  "latest",
		},
		{
			name:     "localhost with port and tag",
			input:    "localhost:5000/myapp:v1",
			wantReg:  "localhost:5000",
			wantRepo: "myapp",
			wantTag:  "v1",
		},
		{
			name:     "localhost with port, no tag",
			input:    "localhost:5000/myapp",
			wantReg:  "localhost:5000",
			wantRepo: "myapp",
		},
		{
			name:     "registry with port and tag",
			input:    "registry.example.com:8080/app:v2",
			wantReg:  "registry.example.com:8080",
			wantRepo: "app",
			wantTag:  "v2",
		},
		{
			name: "empty string",
		},
		{
			name:     "docker.io explicit with library prefix",
			input:    "docker.io/library/nginx:1.25",
			wantReg:  "docker.io",
			wantRepo: "library/nginx",
			wantTag:  "1.25",
		},
		{
			name:     "docker.io single-component normalizes to library",
			input:    "docker.io/nginx:1.25",
			wantReg:  "docker.io",
			wantRepo: "library/nginx",
			wantTag:  "1.25",
		},
		{
			name:     "docker hub org repo no tag",
			input:    "myorg/myapp",
			wantReg:  "",
			wantRepo: "myorg/myapp",
		},
		{
			name:       "full reference: registry/repo:tag@digest",
			input:      "gcr.io/my-project/app:v1.2.3@sha256:deadbeef",
			wantReg:    "gcr.io",
			wantRepo:   "my-project/app",
			wantTag:    "v1.2.3",
			wantDigest: "sha256:deadbeef",
		},
		{
			name:       "registry with digest, no tag",
			input:      "gcr.io/my-project/app@sha256:deadbeef",
			wantReg:    "gcr.io",
			wantRepo:   "my-project/app",
			wantDigest: "sha256:deadbeef",
		},
		{
			name:     "quay.io with nested repo",
			input:    "quay.io/prometheus/node-exporter:v1.7.0",
			wantReg:  "quay.io",
			wantRepo: "prometheus/node-exporter",
			wantTag:  "v1.7.0",
		},
		{
			name:     "ECR registry",
			input:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest",
			wantReg:  "123456789012.dkr.ecr.us-east-1.amazonaws.com",
			wantRepo: "my-app",
			wantTag:  "latest",
		},
		{
			name:     "tag with dots",
			input:    "nginx:1.25.3",
			wantReg:  "",
			wantRepo: "library/nginx",
			wantTag:  "1.25.3",
		},
		{
			name:     "tag with hyphens",
			input:    "python:3.12-slim-bookworm",
			wantReg:  "",
			wantRepo: "library/python",
			wantTag:  "3.12-slim-bookworm",
		},
		{
			name:     "localhost without port",
			input:    "localhost/myapp:v1",
			wantReg:  "localhost",
			wantRepo: "myapp",
			wantTag:  "v1",
		},
		{
			name:       "localhost with port and digest",
			input:      "localhost:5000/myapp@sha256:abc",
			wantReg:    "localhost:5000",
			wantRepo:   "myapp",
			wantDigest: "sha256:abc",
		},
		{
			name:     "deeply nested repo path",
			input:    "registry.example.com/a/b/c/d:v1",
			wantReg:  "registry.example.com",
			wantRepo: "a/b/c/d",
			wantTag:  "v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseRef(tt.input)

			assert.Equal(t, tt.input, ref.Raw, "Raw")
			assert.Equal(t, tt.wantReg, ref.Registry, "Registry")
			assert.Equal(t, tt.wantRepo, ref.Repository, "Repository")
			assert.Equal(t, tt.wantTag, ref.Tag, "Tag")
			assert.Equal(t, tt.wantDigest, ref.Digest, "Digest")
		})
	}
}

func TestRef_HasTag(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"with tag", "nginx:1.25", true},
		{"with latest tag", "nginx:latest", true},
		{"no tag", "nginx", false},
		{"digest only", "nginx@sha256:abc", false},
		{"tag and digest", "nginx:1.25@sha256:abc", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseRef(tt.input)
			assert.Equal(t, tt.want, ref.HasTag())
		})
	}
}

func TestRef_HasDigest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"with digest", "nginx@sha256:abc", true},
		{"tag and digest", "nginx:1.25@sha256:abc", true},
		{"no digest", "nginx:1.25", false},
		{"no tag no digest", "nginx", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseRef(tt.input)
			assert.Equal(t, tt.want, ref.HasDigest())
		})
	}
}

func TestRef_IsLatest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"explicit latest", "nginx:latest", true},
		{"implicit latest (no tag, no digest)", "nginx", true},
		{"specific tag", "nginx:1.25", false},
		{"digest only", "nginx@sha256:abc", false},
		{"latest with digest", "nginx:latest@sha256:abc", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseRef(tt.input)
			assert.Equal(t, tt.want, ref.IsLatest())
		})
	}
}

func TestRef_IsMutableTag(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"implicit latest", "nginx", true},
		{"explicit latest", "nginx:latest", true},
		{"specific tag without digest", "nginx:1.25", true},
		{"tag with digest (immutable)", "nginx:1.25@sha256:abc", false},
		{"digest only (immutable)", "nginx@sha256:abc", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseRef(tt.input)
			assert.Equal(t, tt.want, ref.IsMutableTag())
		})
	}
}

func TestRef_EffectiveRegistry(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"explicit registry", "gcr.io/project/app:v1", "gcr.io"},
		{"docker hub bare", "nginx", "docker.io"},
		{"docker hub org", "myorg/myapp:v1", "docker.io"},
		{"docker.io explicit", "docker.io/library/nginx:1.25", "docker.io"},
		{"localhost", "localhost:5000/app:v1", "localhost:5000"},
		{"empty", "", "docker.io"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseRef(tt.input)
			assert.Equal(t, tt.want, ref.EffectiveRegistry())
		})
	}
}

func TestSplitTag(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantTag       string
		wantRemainder string
	}{
		{"simple tag", "nginx:1.25", "1.25", "nginx"},
		{"no tag", "nginx", "", "nginx"},
		{"port not tag", "localhost:5000/app", "", "localhost:5000/app"},
		{"port with tag", "localhost:5000/app:v1", "v1", "localhost:5000/app"},
		{"registry port path tag", "reg.io:8080/app:v2", "v2", "reg.io:8080/app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, remainder := splitTag(tt.input)
			assert.Equal(t, tt.wantTag, tag, "tag")
			assert.Equal(t, tt.wantRemainder, remainder, "remainder")
		})
	}
}

func TestSplitRegistryRepo(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantReg  string
		wantRepo string
	}{
		{"bare name", "nginx", "", "nginx"},
		{"org/repo", "myorg/myapp", "", "myorg/myapp"},
		{"dotted registry", "gcr.io/project/app", "gcr.io", "project/app"},
		{"localhost", "localhost/app", "localhost", "app"},
		{"registry with port", "localhost:5000/app", "localhost:5000", "app"},
		{"domain registry", "registry.example.com/app", "registry.example.com", "app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, repo := splitRegistryRepo(tt.input)
			assert.Equal(t, tt.wantReg, reg, "registry")
			assert.Equal(t, tt.wantRepo, repo, "repo")
		})
	}
}
