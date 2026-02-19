package crd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestCertManagerInsecureChecker_Run(t *testing.T) {
	c := &CertManagerInsecureChecker{}
	ctx := context.Background()

	assert.Equal(t, "cert-manager-insecure", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryCRD)

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("cancelled context", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := c.Run(cancelCtx, checker.NewResourceCache())
		assert.Error(t, err)
	})

	t.Run("weak RSA key", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cert := makeCertificate(t, "weak-rsa", "default",
			map[string]interface{}{
				"secretName": "tls-secret",
				"privateKey": map[string]interface{}{
					"algorithm": "RSA",
					"size":      float64(1024),
				},
			}, nil)
		cache.Add(CertificateGVR, cert)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "RSA")
	})

	t.Run("strong RSA key", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cert := makeCertificate(t, "strong-rsa", "default",
			map[string]interface{}{
				"secretName": "tls-secret",
				"privateKey": map[string]interface{}{
					"algorithm": "RSA",
					"size":      float64(4096),
				},
			}, nil)
		cache.Add(CertificateGVR, cert)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("excessively long duration", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cert := makeCertificate(t, "long-cert", "default",
			map[string]interface{}{
				"secretName": "tls-secret",
				"duration":   "17520h", // 2 years
			}, nil)
		cache.Add(CertificateGVR, cert)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "long duration")
	})

	t.Run("reasonable duration", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cert := makeCertificate(t, "good-cert", "default",
			map[string]interface{}{
				"secretName": "tls-secret",
				"duration":   "2160h", // 90 days
			}, nil)
		cache.Add(CertificateGVR, cert)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "cert-manager-insecure", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "cert-manager-insecure", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
