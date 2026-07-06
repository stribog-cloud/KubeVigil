package secrets

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// The following base64 blobs are throwaway, self-signed test certificates
// generated solely for this test file. They contain no real key material.
// RSA-1024 and ECDSA P-224 are deliberately weak (below the 2048-bit /
// P-256 thresholds this checker enforces); RSA-2048 and P-256 are strong.
const (
	testRSAWeakCertB64     = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ4akNDQVMrZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFmTVIwd0d3WURWUVFERXhSM1pXRnIKTFhKellTNWxlR0Z0Y0d4bExtTnZiVEFlRncweU5qQTNNRFl4TURRNU16RmFGdzB5TnpBM01EWXhNRFE1TXpGYQpNQjh4SFRBYkJnTlZCQU1URkhkbFlXc3Rjbk5oTG1WNFlXMXdiR1V1WTI5dE1JR2ZNQTBHQ1NxR1NJYjNEUUVCCkFRVUFBNEdOQURDQmlRS0JnUURlUXJqZnBsclFoWlJ3aTk0VDNPb0hDcDRGYzJXSmFqZnROYkFkbElLTkpBR1QKc2VielZLVFhCOUVuVnU0NUZIaGFPNElyb2RDcVhWT2lRNnJBWmsrMk5jZzY2Wmh3djBaem5BYkJBZUN5M29sdApvbzR3UVdDS0IrZzBMWDNFT1NtL05qVDA4bmptMzMxc1hSWVdaQ1hJTzVWSGUvZ09MQmxQSmFnc1RGM1dXd0lECkFRQUJveEl3RURBT0JnTlZIUThCQWY4RUJBTUNCYUF3RFFZSktvWklodmNOQVFFTEJRQURnWUVBcTdHUVd4TUkKLzVWK1Jkbmc5UFhyL3VBVzArYWc5RkhUMzlhWFVzbWl5MXpmcnhuc1NvRXhxK2Q1Tnp1cDhLY0dVUFpuQkZhcgpiL3Q2Q2FwMVlMUzREWFZPZ2FTVmlmdENHZlR6Wm84cWFTb1NuMWlCR1pBYkpJVGVSQzhaU1hNOTFySUFCcWZBCk84VlVxQnRmZ1ZtRnBIbjBzREdheHZkWWpEeXIwbEpRVDJvPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
	testRSAStrongCertB64   = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN6ekNDQWJlZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFoTVI4d0hRWURWUVFERXhaemRISnYKYm1jdGNuTmhMbVY0WVcxd2JHVXVZMjl0TUI0WERUSTJNRGN3TmpFd05Ea3pNVm9YRFRJM01EY3dOakV3TkRregpNVm93SVRFZk1CMEdBMVVFQXhNV2MzUnliMjVuTFhKellTNWxlR0Z0Y0d4bExtTnZiVENDQVNJd0RRWUpLb1pJCmh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTDU5ME84R3hTM1hNYWt5cWRrNy85R2tPODFhSWpyNkdjNlYKVWtCNnBUYkgrbW9RTlhacXN0NFNYdG1UNDJxL2ExY1Z3YVhLYUJwbVlZQVpkS29NcXJKOWdWc0lmZXh0NHpOVQpqNzc1RGxBRE8xbi96UlJPYzB0KzF4ZE1lVkRCMVJsam5rRjduK3h2MmtVYUFTZld0b1MwWThyME42dERNNEJFCm55d2hSRmRJRHQ2T0todWRLazhVbjF4c2lDUTBkTEV2U1Uvd0M2YzRVNExUV2M0R3MwTW9hUEFSZW1HZTI2cUIKQ2didHg3NDlzYk5VSnlNRGxmMnpabHRQV3lrRU1NWEVlRmRzM0g0b1BCNU14SGpERkEzOWt6S2RuSkJnUWZpUgpjVUVIdy9OdEdnZGdJcU0rUXE4NHBHSndWU3VGYWpFTmo2cjFQc0wxUWFWOVlodWNsM1VDQXdFQUFhTVNNQkF3CkRnWURWUjBQQVFIL0JBUURBZ1dnTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCY3JMTWxJMTJiQ3RVVGpvVWsKd0svdlBTc2FSWnhGZXcvOWxFVkNSOWI4Qk02T2szTElPemh4YVFuUWV1L054ZFM2QlJUOVZWZGVqVGlqTDl5dwovMENFb0FvSXZnL3ZyRDVaNTErZy95UFY2SGhoS3k2OExXc2Mwdnl3UnpLVlVreC81bGRNQmlHTXdPMHp0K1RhCjVZVG5oQTZtQjhFK3cwbU5VTjhpK1NWbk94eUlGcEJMbkVDMlZyd1A0ZnZkWjlUcnA1c2l5akNTc1pBR2MrTFYKdFJGWUFZeFFxTmJsRGsvRU81NGxFOWxkVmdnUkptYjRqaEVDc0o3Z2crbFFob0EyNXZKMWpuQ2hBVnhYa3hnNwp0Z0JNR1RQN3BuRi8xVm90VGRhWGxtQzJiYlNGU2RYby9CaEV1dUpsUHhzeHh0UnMydkVoZEV0WFNlSlJlcSt3CkFxeVAKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	testECDSAWeakCertB64   = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJNRENCM3FBREFnRUNBZ0VCTUFvR0NDcUdTTTQ5QkFNQ01DRXhIekFkQmdOVkJBTVRGbmRsWVdzdFpXTmsKYzJFdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd056QTJNVEEwT1RNeFdoY05NamN3TnpBMk1UQTBPVE14V2pBaApNUjh3SFFZRFZRUURFeFozWldGckxXVmpaSE5oTG1WNFlXMXdiR1V1WTI5dE1FNHdFQVlIS29aSXpqMENBUVlGCks0RUVBQ0VET2dBRU05K09FUHpFU1lFM0pyRm1RR042TUZ2bzZ1MHZXL00yaWs3Yit4NmpYc0ZCc1Zod2dOWXEKWUpzdHFTN0x6aWpBbFNsNGYzYWFNb1NqRWpBUU1BNEdBMVVkRHdFQi93UUVBd0lGb0RBS0JnZ3Foa2pPUFFRRApBZ05CQURBK0FoMEF1dFRqaTArS1lhOE5FMFcxSERJZFpOLzViQVlJdDFFWHRwanZEQUlkQU11L2xaUGNMK0ppCjNIRTlJYU9DdWt3MlZ5T255RlJxOWJpcm1jND0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	testECDSAStrongCertB64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJSekNCN2FBREFnRUNBZ0VCTUFvR0NDcUdTTTQ5QkFNQ01DTXhJVEFmQmdOVkJBTVRHSE4wY205dVp5MWwKWTJSellTNWxlR0Z0Y0d4bExtTnZiVEFlRncweU5qQTNNRFl4TURRNU16RmFGdzB5TnpBM01EWXhNRFE1TXpGYQpNQ014SVRBZkJnTlZCQU1UR0hOMGNtOXVaeTFsWTJSellTNWxlR0Z0Y0d4bExtTnZiVEJaTUJNR0J5cUdTTTQ5CkFnRUdDQ3FHU000OUF3RUhBMElBQkhlYmZ1WXZzTXFVTGI1LzZ3S3BraGkycjQ4eEhnTVNWeEZ3Q0pSSWZjd0YKOXlkU2V3ME5KWVZ4UVIyWjhLQVc5aE5CbEI3SmZkRWd3MDZvcGpBanRIYWpFakFRTUE0R0ExVWREd0VCL3dRRQpBd0lGb0RBS0JnZ3Foa2pPUFFRREFnTkpBREJHQWlFQTE5ZHY0Ym9Fcm9QZVBFMW9PbVVRcTJ3VUZra3JKMGp2CjdvcnZjNUQzelhNQ0lRRFoxbDZrOXZ1WVdabU5hQTlWUnZKUFZteGtCbWthdVBMVFpva0RpeUZCNkE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
)

// tlsSecretObj builds an unstructured kubernetes.io/tls Secret with the
// given tls.crt value and optional annotations.
func tlsSecretObj(name, namespace, tlsCrt string, annotations map[string]string) unstructured.Unstructured {
	meta := map[string]interface{}{"name": name, "namespace": namespace}
	if len(annotations) > 0 {
		annMap := make(map[string]interface{}, len(annotations))
		for k, v := range annotations {
			annMap[k] = v
		}
		meta["annotations"] = annMap
	}

	data := map[string]interface{}{"tls.key": "ZHVtbXk="}
	if tlsCrt != "" {
		data["tls.crt"] = tlsCrt
	}

	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   meta,
		"type":       "kubernetes.io/tls",
		"data":       data,
	}}
}

func TestTLSWeakKeyChecker_Metadata(t *testing.T) {
	c := &TLSWeakKeyChecker{}

	assert.Equal(t, "secrets-tls-weak-key", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySecrets)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, SecretGVR, c.RequiredResources()[0])
}

func TestTLSWeakKeyChecker_Run(t *testing.T) {
	c := &TLSWeakKeyChecker{}
	ctx := context.Background()

	garbagePEM := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: []byte("this is not valid DER"),
	}))
	notPEM := base64.StdEncoding.EncodeToString([]byte("this is just plain text, not PEM at all"))

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantMessage  string
	}{
		{
			name: "RSA-1024 weak key triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("weak-rsa-tls-secret", "default", testRSAWeakCertB64, nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "weak-rsa-tls-secret",
			wantMessage:  `Secret "weak-rsa-tls-secret" contains a TLS certificate with a weak RSA key (1024 bits, minimum recommended: 2048).`,
		},
		{
			name: "RSA-2048 strong key produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("strong-rsa-tls-secret", "default", testRSAStrongCertB64, nil))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ECDSA P-224 weak key triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("weak-ecdsa-tls-secret", "default", testECDSAWeakCertB64, nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "weak-ecdsa-tls-secret",
			wantMessage:  `Secret "weak-ecdsa-tls-secret" contains a TLS certificate with a weak ECDSA key (224-bit curve, minimum recommended: P-256/256-bit).`,
		},
		{
			name: "ECDSA P-256 strong key produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("strong-ecdsa-tls-secret", "default", testECDSAStrongCertB64, nil))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "cert-manager managed secret is skipped even with a weak key",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("cert-manager-tls-secret", "default", testRSAWeakCertB64, map[string]string{
					certManagerCertificateNameAnnotation: "my-certificate",
				}))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "non-tls secret type is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secret := makeSecret("opaque-secret", "default", "Opaque", []string{"tls.crt"})
				cache.Add(SecretGVR, secret)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "missing tls.crt key is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("no-crt-secret", "default", "", nil))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "missing data map entirely is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Secret",
					"metadata":   map[string]interface{}{"name": "no-data-secret", "namespace": "default"},
					"type":       "kubernetes.io/tls",
				}})
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "data not a map is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Secret",
					"metadata":   map[string]interface{}{"name": "bad-data-secret", "namespace": "default"},
					"type":       "kubernetes.io/tls",
					"data":       "not-a-map",
				}})
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "tls.crt value not a string is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Secret",
					"metadata":   map[string]interface{}{"name": "numeric-crt-secret", "namespace": "default"},
					"type":       "kubernetes.io/tls",
					"data":       map[string]interface{}{"tls.crt": 12345},
				}})
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "invalid base64 in tls.crt is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("bad-base64-secret", "default", "!!!not-valid-base64!!!", nil))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "valid base64 but not PEM is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("not-pem-secret", "default", notPEM, nil))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "valid PEM but unparsable certificate is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("garbage-cert-secret", "default", garbagePEM, nil))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple secrets with mixed key strength",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(SecretGVR, tlsSecretObj("weak-1", "ns1", testRSAWeakCertB64, nil))
				cache.Add(SecretGVR, tlsSecretObj("strong-1", "ns1", testRSAStrongCertB64, nil))
				cache.Add(SecretGVR, tlsSecretObj("weak-2", "ns2", testECDSAWeakCertB64, nil))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)

			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				helpers.AssertAllFindingsHaveRequiredFields(t, findings)
				assert.Equal(t, "secrets-tls-weak-key", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, `.data["tls.crt"]`, findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantMessage != "" {
					assert.Equal(t, tt.wantMessage, findings[0].Message)
				}
			}
		})
	}
}

func TestTLSWeakKeyChecker_CancelledContext(t *testing.T) {
	c := &TLSWeakKeyChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(SecretGVR, tlsSecretObj("weak", "default", testRSAWeakCertB64, nil))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestTLSWeakKeyChecker_Fixtures(t *testing.T) {
	c := &TLSWeakKeyChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-tls-weak-key", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "weak-rsa-tls-secret")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "secrets-tls-weak-key", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

// TestEvaluateTLSKeyStrength_UnsupportedAlgorithm covers the default branch
// of evaluateTLSKeyStrength for a public key algorithm this check does not
// cover (e.g. Ed25519), which the spec explicitly leaves unflagged.
func TestEvaluateTLSKeyStrength_UnsupportedAlgorithm(t *testing.T) {
	cert := &x509.Certificate{PublicKey: "not-a-recognized-key-type"}
	obj := tlsSecretObj("unsupported-algo-secret", "default", "", nil)

	finding, weak := evaluateTLSKeyStrength(cert, &obj)

	assert.False(t, weak)
	assert.Equal(t, checker.Finding{}, finding)
}
