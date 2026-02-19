package crd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestCertManagerExpiryChecker_Run(t *testing.T) {
	c := &CertManagerExpiryChecker{}
	ctx := context.Background()

	assert.Equal(t, "cert-manager-expiry", c.Name())
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

	t.Run("expired certificate", func(t *testing.T) {
		cache := checker.NewResourceCache()
		expired := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
		cert := makeCertificate(t, "expired-cert", "default",
			map[string]interface{}{"secretName": "tls-secret"},
			map[string]interface{}{"notAfter": expired},
		)
		cache.Add(CertificateGVR, cert)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "expired")
	})

	t.Run("certificate expiring soon", func(t *testing.T) {
		cache := checker.NewResourceCache()
		soon := time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)
		cert := makeCertificate(t, "expiring-cert", "default",
			map[string]interface{}{"secretName": "tls-secret"},
			map[string]interface{}{"notAfter": soon},
		)
		cache.Add(CertificateGVR, cert)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "expires in")
	})

	t.Run("certificate far from expiry", func(t *testing.T) {
		cache := checker.NewResourceCache()
		farFuture := time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)
		cert := makeCertificate(t, "good-cert", "default",
			map[string]interface{}{"secretName": "tls-secret"},
			map[string]interface{}{"notAfter": farFuture},
		)
		cache.Add(CertificateGVR, cert)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("failed certificate", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cert := makeCertificate(t, "failed-cert", "default",
			map[string]interface{}{"secretName": "tls-secret"},
			map[string]interface{}{
				"conditions": []interface{}{
					map[string]interface{}{
						"type":   "Ready",
						"status": "False",
						"reason": "Failed",
					},
				},
			},
		)
		cache.Add(CertificateGVR, cert)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "failed")
	})
}
