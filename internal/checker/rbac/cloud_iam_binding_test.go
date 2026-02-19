package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func makeServiceAccount(name, namespace string, annotations map[string]string) unstructured.Unstructured {
	obj := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
	}}
	if len(annotations) > 0 {
		meta := obj.Object["metadata"].(map[string]interface{})
		annMap := make(map[string]interface{})
		for k, v := range annotations {
			annMap[k] = v
		}
		meta["annotations"] = annMap
	}
	return obj
}

func TestCloudIAMBindingChecker_Metadata(t *testing.T) {
	c := &CloudIAMBindingChecker{}

	assert.Equal(t, "cloud-iam-binding", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), serviceAccountGVR)
}

func TestCloudIAMBindingChecker_Run(t *testing.T) {
	c := &CloudIAMBindingChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantMessage  string
	}{
		{
			name: "SA with no annotations produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sa := makeServiceAccount("plain-sa", "default", nil)
				cache.Add(serviceAccountGVR, sa)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "SA with non-cloud annotations produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sa := makeServiceAccount("annotated-sa", "default", map[string]string{
					"app.kubernetes.io/name": "my-app",
				})
				cache.Add(serviceAccountGVR, sa)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "SA with AWS IRSA annotation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sa := makeServiceAccount("aws-sa", "default", map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/my-role",
				})
				cache.Add(serviceAccountGVR, sa)
				return cache
			},
			wantFindings: 1,
			wantResource: "aws-sa",
			wantMessage:  "AWS IRSA",
		},
		{
			name: "SA with GCP Workload Identity annotation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sa := makeServiceAccount("gcp-sa", "default", map[string]string{
					"iam.gke.io/gcp-service-account": "my-app@my-project.iam.gserviceaccount.com",
				})
				cache.Add(serviceAccountGVR, sa)
				return cache
			},
			wantFindings: 1,
			wantResource: "gcp-sa",
			wantMessage:  "GCP Workload Identity",
		},
		{
			name: "SA with Azure Workload Identity annotation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sa := makeServiceAccount("azure-sa", "default", map[string]string{
					"azure.workload.identity/client-id": "12345678-1234-1234-1234-123456789012",
				})
				cache.Add(serviceAccountGVR, sa)
				return cache
			},
			wantFindings: 1,
			wantResource: "azure-sa",
			wantMessage:  "Azure Workload Identity",
		},
		{
			name: "SA with multiple cloud annotations triggers multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sa := makeServiceAccount("multi-cloud-sa", "default", map[string]string{
					"eks.amazonaws.com/role-arn":        "arn:aws:iam::123456789012:role/my-role",
					"iam.gke.io/gcp-service-account":    "my-app@my-project.iam.gserviceaccount.com",
					"azure.workload.identity/client-id": "12345678",
				})
				cache.Add(serviceAccountGVR, sa)
				return cache
			},
			wantFindings: 3,
			wantResource: "multi-cloud-sa",
		},
		{
			name: "multiple SAs only annotated ones trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sa1 := makeServiceAccount("plain-sa", "default", nil)
				sa2 := makeServiceAccount("aws-sa", "default", map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/my-role",
				})
				sa3 := makeServiceAccount("other-sa", "production", map[string]string{
					"some.annotation": "value",
				})
				cache.Add(serviceAccountGVR, sa1)
				cache.Add(serviceAccountGVR, sa2)
				cache.Add(serviceAccountGVR, sa3)
				return cache
			},
			wantFindings: 1,
			wantResource: "aws-sa",
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fixture: sa-aws-irsa.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "cloud-iam-binding", "sa-aws-irsa.yaml")
			},
			wantFindings: 1,
			wantResource: "aws-sa",
			wantMessage:  "AWS IRSA",
		},
		{
			name: "fixture: sa-gcp-wi.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "cloud-iam-binding", "sa-gcp-wi.yaml")
			},
			wantFindings: 1,
			wantResource: "gcp-sa",
			wantMessage:  "GCP Workload Identity",
		},
		{
			name: "fixture: sa-azure-wi.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "cloud-iam-binding", "sa-azure-wi.yaml")
			},
			wantFindings: 1,
			wantResource: "azure-sa",
			wantMessage:  "Azure Workload Identity",
		},
		{
			name: "fixture: sa-no-cloud.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "cloud-iam-binding", "sa-no-cloud.yaml")
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
				assert.Equal(t, "cloud-iam-binding", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "ServiceAccount", findings[0].Kind)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantMessage != "" {
					assert.Contains(t, findings[0].Message, tt.wantMessage)
				}
			}
		})
	}
}

func TestCloudIAMBindingChecker_CancelledContext(t *testing.T) {
	c := &CloudIAMBindingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	sa := makeServiceAccount("test-sa", "default", map[string]string{
		"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/my-role",
	})
	cache.Add(serviceAccountGVR, sa)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestCloudIAMBindingChecker_FieldPath(t *testing.T) {
	c := &CloudIAMBindingChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	sa := makeServiceAccount("aws-sa", "default", map[string]string{
		"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/my-role",
	})
	cache.Add(serviceAccountGVR, sa)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, ".metadata.annotations[eks.amazonaws.com/role-arn]", findings[0].FieldPath)
}

func TestCloudIAMBindingChecker_Namespace(t *testing.T) {
	c := &CloudIAMBindingChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	sa := makeServiceAccount("aws-sa", "production", map[string]string{
		"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/prod-role",
	})
	cache.Add(serviceAccountGVR, sa)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, "production", findings[0].Namespace)
}
