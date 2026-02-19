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

func TestRegistryBlocklistChecker_Metadata(t *testing.T) {
	c := &RegistryBlocklistChecker{}

	assert.Equal(t, "image-registry-blocklist", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryImage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestRegistryBlocklistChecker_Run(t *testing.T) {
	c := &RegistryBlocklistChecker{}
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
						BlockedRegistries: []string{"docker.io"},
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
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("docker.io/library/nginx:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty blocklist returns no findings (NO-OP)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("test-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("docker.io/library/nginx:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "image from blocked registry triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{"docker.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("blocked-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("docker.io/library/nginx:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "blocked-pod",
		},
		{
			name: "image from non-blocked registry produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{"docker.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("safe-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("gcr.io/my-project/app:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Docker Hub normalization: bare image matches docker.io blocklist",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{"docker.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("bare-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "multiple containers — only blocked ones trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{"quay.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("safe-pod"),
					helpers.WithContainer(helpers.NewContainer("safe", helpers.WithContainerImage("gcr.io/project/app:v1"))),
				)
				pod2 := helpers.GeneratePod(
					helpers.WithName("blocked-pod"),
					helpers.WithContainer(helpers.NewContainer("blocked", helpers.WithContainerImage("quay.io/some/app:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(podGVR, toUnstructured(t, pod2))
				return cache
			},
			wantFindings:  1,
			wantContainer: "blocked",
		},
		{
			name: "init container from blocked registry triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{"quay.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("gcr.io/project/app:v1"))),
					helpers.WithInitContainer(helpers.NewContainer("init-setup", helpers.WithContainerImage("quay.io/init/setup:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container from blocked registry triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{"docker.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("gcr.io/project/app:v1"))),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy", helpers.WithContainerImage("envoyproxy/envoy:v1.28"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "fixture: pod-blocked-registry.yaml triggers when docker.io blocked",
			setup: func() *checker.ResourceCache {
				cache := helpers.LoadFixture(t, "image-registry-blocklist", "pod-blocked-registry.yaml")
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{"docker.io"},
					},
				})
				return cache
			},
			wantFindings: 1,
			wantResource: "blocked-registry-pod",
		},
		{
			name: "fixture: pod-safe-registry.yaml produces no findings when docker.io blocked",
			setup: func() *checker.ResourceCache {
				cache := helpers.LoadFixture(t, "image-registry-blocklist", "pod-safe-registry.yaml")
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						BlockedRegistries: []string{"docker.io"},
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
				assert.Equal(t, "image-registry-blocklist", findings[0].Checker)
				assert.Equal(t, checker.SeverityCritical, findings[0].Severity)
				assert.NotEmpty(t, findings[0].FieldPath)
				assert.Contains(t, findings[0].FieldPath, "image")

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

func TestRegistryBlocklistChecker_CancelledContext(t *testing.T) {
	c := &RegistryBlocklistChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			BlockedRegistries: []string{"docker.io"},
		},
	})
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestRegistryBlocklistChecker_FindingFields(t *testing.T) {
	c := &RegistryBlocklistChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			BlockedRegistries: []string{"quay.io"},
		},
	})
	pod := helpers.GeneratePod(
		helpers.WithName("field-test-pod"),
		helpers.WithNamespace("staging"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/some/app:v1"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "image-registry-blocklist", f.Checker)
	assert.Equal(t, checker.SeverityCritical, f.Severity)
	assert.Equal(t, "field-test-pod", f.Resource)
	assert.Equal(t, "staging", f.Namespace)
	assert.Equal(t, "Pod", f.Kind)
	assert.Equal(t, "app", f.Container)
	assert.Contains(t, f.Message, "quay.io")
	assert.Contains(t, f.Message, "blocked registry")
	assert.NotEmpty(t, f.Remediation)
	assert.Equal(t, ".spec.containers[0].image", f.FieldPath)
}

func TestRegistryBlocklistChecker_MultipleBlockedRegistries(t *testing.T) {
	c := &RegistryBlocklistChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			BlockedRegistries: []string{"docker.io", "quay.io"},
		},
	})

	pod1 := helpers.GeneratePod(
		helpers.WithName("docker-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
	)
	pod2 := helpers.GeneratePod(
		helpers.WithName("quay-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/some/app:v1"))),
	)
	pod3 := helpers.GeneratePod(
		helpers.WithName("gcr-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("gcr.io/project/app:v1"))),
	)

	cache.Add(podGVR, toUnstructured(t, pod1))
	cache.Add(podGVR, toUnstructured(t, pod2))
	cache.Add(podGVR, toUnstructured(t, pod3))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	assert.Len(t, findings, 2)
}

func TestRegistryBlocklistChecker_AllWorkloadTypes(t *testing.T) {
	c := &RegistryBlocklistChecker{}
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
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/app:v1"))),
				)
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/app:v1"))),
				)
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/app:v1"))),
				)
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/app:v1"))),
				)
			},
		},
	}

	for _, wt := range workloadTypes {
		t.Run(wt.name, func(t *testing.T) {
			cache := checker.NewResourceCache()
			cache.SetPolicies(&checker.Policies{
				Images: checker.ImagePolicies{
					BlockedRegistries: []string{"quay.io"},
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
