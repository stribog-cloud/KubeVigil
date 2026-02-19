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

func TestRegistryAllowlistChecker_Metadata(t *testing.T) {
	c := &RegistryAllowlistChecker{}

	assert.Equal(t, "image-registry-allowlist", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryImage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestRegistryAllowlistChecker_Run(t *testing.T) {
	c := &RegistryAllowlistChecker{}
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
						AllowedRegistries: []string{"gcr.io"},
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
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/some/app:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty allowlist returns no findings (NO-OP)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("test-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/some/app:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "image from allowed registry produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io", "us-docker.pkg.dev"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("allowed-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("gcr.io/my-project/app:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "image from non-allowed registry triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("disallowed-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/some/app:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "disallowed-pod",
		},
		{
			name: "Docker Hub normalization: docker.io in allowlist matches bare images",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"docker.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("dockerhub-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Docker Hub normalization: bare image NOT in allowlist triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
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
			name: "multiple containers — only non-allowed ones trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("multi-pod"),
					helpers.WithContainer(helpers.NewContainer("allowed", helpers.WithContainerImage("gcr.io/project/app:v1"))),
				)
				pod2 := helpers.GeneratePod(
					helpers.WithName("multi-pod2"),
					helpers.WithContainer(helpers.NewContainer("disallowed", helpers.WithContainerImage("quay.io/some/app:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(podGVR, toUnstructured(t, pod2))
				return cache
			},
			wantFindings:  1,
			wantContainer: "disallowed",
		},
		{
			name: "init container from non-allowed registry triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
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
			name: "sidecar container from non-allowed registry triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("gcr.io/project/app:v1"))),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy", helpers.WithContainerImage("docker.io/envoyproxy/envoy:v1.28"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "finding has all required fields",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
					},
				})
				pod := helpers.GeneratePod(
					helpers.WithName("fields-pod"),
					helpers.WithNamespace("production"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/app:v1"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "deployment with non-allowed registry",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
					},
				})
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/app:v1"))),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "fixture: pod-allowed-registry.yaml produces no findings when gcr.io is allowed",
			setup: func() *checker.ResourceCache {
				cache := helpers.LoadFixture(t, "image-registry-allowlist", "pod-allowed-registry.yaml")
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
					},
				})
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-disallowed-registry.yaml triggers finding when only gcr.io allowed",
			setup: func() *checker.ResourceCache {
				cache := helpers.LoadFixture(t, "image-registry-allowlist", "pod-disallowed-registry.yaml")
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
					},
				})
				return cache
			},
			wantFindings: 1,
			wantResource: "disallowed-registry-pod",
		},
		{
			name: "fixture: pod-docker-hub.yaml matches when docker.io in allowlist",
			setup: func() *checker.ResourceCache {
				cache := helpers.LoadFixture(t, "image-registry-allowlist", "pod-docker-hub.yaml")
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"docker.io"},
					},
				})
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-docker-hub.yaml triggers when docker.io NOT in allowlist",
			setup: func() *checker.ResourceCache {
				cache := helpers.LoadFixture(t, "image-registry-allowlist", "pod-docker-hub.yaml")
				cache.SetPolicies(&checker.Policies{
					Images: checker.ImagePolicies{
						AllowedRegistries: []string{"gcr.io"},
					},
				})
				return cache
			},
			wantFindings: 1,
			wantResource: "docker-hub-pod",
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
				assert.Equal(t, "image-registry-allowlist", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
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

func TestRegistryAllowlistChecker_CancelledContext(t *testing.T) {
	c := &RegistryAllowlistChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			AllowedRegistries: []string{"gcr.io"},
		},
	})
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/app:v1"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestRegistryAllowlistChecker_FindingFields(t *testing.T) {
	c := &RegistryAllowlistChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			AllowedRegistries: []string{"gcr.io"},
		},
	})
	pod := helpers.GeneratePod(
		helpers.WithName("field-test-pod"),
		helpers.WithNamespace("production"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("quay.io/some/app:v1"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "image-registry-allowlist", f.Checker)
	assert.Equal(t, checker.SeverityHigh, f.Severity)
	assert.Equal(t, "field-test-pod", f.Resource)
	assert.Equal(t, "production", f.Namespace)
	assert.Equal(t, "Pod", f.Kind)
	assert.Equal(t, "app", f.Container)
	assert.Contains(t, f.Message, "quay.io")
	assert.Contains(t, f.Message, "non-allowed registry")
	assert.NotEmpty(t, f.Remediation)
	assert.Equal(t, ".spec.containers[0].image", f.FieldPath)
}

func TestRegistryAllowlistChecker_MultipleAllowedRegistries(t *testing.T) {
	c := &RegistryAllowlistChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			AllowedRegistries: []string{"gcr.io", "us-docker.pkg.dev", "docker.io"},
		},
	})

	pod1 := helpers.GeneratePod(
		helpers.WithName("gcr-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("gcr.io/project/app:v1"))),
	)
	pod2 := helpers.GeneratePod(
		helpers.WithName("artifact-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("us-docker.pkg.dev/proj/repo/img:v1"))),
	)
	pod3 := helpers.GeneratePod(
		helpers.WithName("dockerhub-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
	)

	cache.Add(podGVR, toUnstructured(t, pod1))
	cache.Add(podGVR, toUnstructured(t, pod2))
	cache.Add(podGVR, toUnstructured(t, pod3))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestRegistryAllowlistChecker_IndexDockerIO(t *testing.T) {
	c := &RegistryAllowlistChecker{}
	ctx := context.Background()

	// index.docker.io should match docker.io in allowlist
	cache := checker.NewResourceCache()
	cache.SetPolicies(&checker.Policies{
		Images: checker.ImagePolicies{
			AllowedRegistries: []string{"docker.io"},
		},
	})
	pod := helpers.GeneratePod(
		helpers.WithName("index-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("index.docker.io/library/nginx:1.25"))),
	)

	// index.docker.io is recognized by ParseRef as a registry
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestRegistryAllowlistChecker_AllWorkloadTypes(t *testing.T) {
	c := &RegistryAllowlistChecker{}
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
					AllowedRegistries: []string{"gcr.io"},
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
