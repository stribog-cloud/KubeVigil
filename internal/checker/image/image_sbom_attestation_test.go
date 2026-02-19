package image

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestSBOMAttestationChecker_Metadata(t *testing.T) {
	c := &SBOMAttestationChecker{}

	assert.Equal(t, "image-sbom-attestation", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryImage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestSBOMAttestationChecker_Run(t *testing.T) {
	c := &SBOMAttestationChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "nil policies returns no findings (NO-OP)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("test-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "RequireSBOM false returns no findings (NO-OP)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: false,
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("test-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "image with digest produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("digest-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "image with tag and digest produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("tagged-digest-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25@sha256:abcdef1234567890"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "image without digest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("no-digest-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "no-digest-pod",
		},
		{
			name: "bare image triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("bare-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "multiple containers — only ones without digest trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("digest-pod"),
					helpers.WithContainer(helpers.NewContainer("secure", helpers.WithContainerImage("nginx@sha256:abcdef1234567890"))),
				)
				pod2 := helpers.GeneratePod(
					helpers.WithName("no-digest-pod"),
					helpers.WithContainer(helpers.NewContainer("insecure", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(podGVR, toUnstructured(t, pod2))
				return cache
			},
			wantFindings:  1,
			wantContainer: "insecure",
		},
		{
			name: "init container without digest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx@sha256:abcdef1234567890"))),
					helpers.WithInitContainer(helpers.NewContainer("init-setup", helpers.WithContainerImage("busybox:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without digest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx@sha256:abcdef1234567890"))),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy", helpers.WithContainerImage("envoyproxy/envoy:v1.28"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "fixture: pod-no-digest.yaml triggers when SBOM required",
			setup: func() *checker.ResourceCache {
				cache := helpers.LoadFixture(t, "image-sbom-attestation", "pod-no-digest.yaml")
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				return cache
			},
			wantFindings: 1,
			wantResource: "no-digest-pod",
		},
		{
			name: "fixture: pod-with-digest.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				cache := helpers.LoadFixture(t, "image-sbom-attestation", "pod-with-digest.yaml")
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						RequireSBOM: true,
					},
				})
				return cache
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
				assert.Equal(t, "image-sbom-attestation", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				assert.NotEmpty(t, findings[0].FieldPath)
				assert.Contains(t, findings[0].FieldPath, "image")
				assert.Contains(t, findings[0].Message, "SBOM attestation")

				if tt.wantContainer != "" {
					helpers.AssertFindingForContainer(t, findings, tt.wantContainer)
				}
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestSBOMAttestationChecker_CancelledContext(t *testing.T) {
	c := &SBOMAttestationChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			RequireSBOM: true,
		},
	})
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestSBOMAttestationChecker_FindingFields(t *testing.T) {
	c := &SBOMAttestationChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			RequireSBOM: true,
		},
	})
	pod := helpers.GeneratePod(
		helpers.WithName("field-test-pod"),
		helpers.WithNamespace("production"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "image-sbom-attestation", f.Checker)
	assert.Equal(t, checker.SeverityLow, f.Severity)
	assert.Equal(t, "field-test-pod", f.Resource)
	assert.Equal(t, "production", f.Namespace)
	assert.Equal(t, "Pod", f.Kind)
	assert.Equal(t, "app", f.Container)
	assert.Contains(t, f.Message, "not pinned by digest")
	assert.Contains(t, f.Message, "nginx:1.25")
	assert.Contains(t, f.Remediation, "syft")
	assert.Equal(t, ".spec.containers[0].image", f.FieldPath)
}

func TestSBOMAttestationChecker_AllWorkloadTypes(t *testing.T) {
	c := &SBOMAttestationChecker{}
	ctx := context.Background()

	workloadTypes := []struct {
		name     string
		gvr      schema.GroupVersionResource
		generate func() interface{}
	}{
		{
			name: "StatefulSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"},
			generate: func() interface{} {
				return helpers.GenerateStatefulSet(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
			},
		},
	}

	for _, wt := range workloadTypes {
		t.Run(wt.name, func(t *testing.T) {
			cache := checker.NewResourceCache()
			cache.SetPolicies(&checker.Policies{
				Images: checker.ImagePolicies{
					RequireSBOM: true,
				},
			})
			cache.Add(wt.gvr, toUnstructured(t, wt.generate()))

			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)
			assert.Len(t, findings, 1, "expected finding for %s", wt.name)
			if len(findings) > 0 {
				assert.Equal(t, wt.name, findings[0].Kind)
			}
		})
	}
}
