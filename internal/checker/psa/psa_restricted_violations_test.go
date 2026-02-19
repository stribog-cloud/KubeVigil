package psa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestRestrictedViolationsChecker_Metadata(t *testing.T) {
	c := &RestrictedViolationsChecker{}

	assert.Equal(t, "psa-restricted-violations", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryPSS)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestRestrictedViolationsChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	c := &RestrictedViolationsChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		checkMsg     string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fully compliant pod produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				f := false
				tr := true
				pod := helpers.GeneratePod(
					helpers.WithName("compliant"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &tr,
					}),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &f,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod missing runAsNonRoot triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				f := false
				pod := helpers.GeneratePod(
					helpers.WithName("no-nonroot"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &f,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "no-nonroot",
			checkMsg:     "runAsNonRoot",
		},
		{
			name: "pod missing allowPrivilegeEscalation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				tr := true
				pod := helpers.GeneratePod(
					helpers.WithName("no-ape"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &tr,
					}),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						SecurityContext: &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "no-ape",
			checkMsg:     "allowPrivilegeEscalation",
		},
		{
			name: "pod with allowPrivilegeEscalation true triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				tr := true
				pod := helpers.GeneratePod(
					helpers.WithName("ape-true"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &tr,
					}),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &tr,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "ape-true",
			checkMsg:     "allowPrivilegeEscalation",
		},
		{
			name: "pod missing capabilities drop ALL triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				f := false
				tr := true
				pod := helpers.GeneratePod(
					helpers.WithName("no-drop-all"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &tr,
					}),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &f,
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "no-drop-all",
			checkMsg:     "capabilities.drop",
		},
		{
			name: "pod with no security context triggers 3 findings per container",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-sc"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 3, // runAsNonRoot + allowPrivilegeEscalation + capabilities.drop
			wantResource: "no-sc",
		},
		{
			name: "pod-level runAsNonRoot covers containers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				tr := true
				f := false
				pod := helpers.GeneratePod(
					helpers.WithName("pod-level-nonroot"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &tr,
					}),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &f,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container-level runAsNonRoot overrides pod-level",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				f := false
				tr := true
				pod := helpers.GeneratePod(
					helpers.WithName("container-override"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &tr,
					}),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
						SecurityContext: &corev1.SecurityContext{
							RunAsNonRoot:             &f,
							AllowPrivilegeEscalation: &f,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1, // runAsNonRoot false at container level overrides pod true
			checkMsg:     "runAsNonRoot",
		},
		{
			name: "multiple containers each produce findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-container"),
					helpers.WithContainer(corev1.Container{
						Name:  "app1",
						Image: "nginx:1.25",
					}),
				)
				pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
					Name:  "app2",
					Image: "nginx:1.25",
				})
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 6, // 3 per container * 2 containers
		},
		{
			name: "init container with violations triggers findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("init-violations"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
					}),
					helpers.WithInitContainer(corev1.Container{
						Name:  "init",
						Image: "busybox:1.36",
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 6, // 3 per container (regular + init)
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
				assert.Equal(t, "psa-restricted-violations", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.checkMsg != "" {
					found := false
					for i := range findings {
						if assert.ObjectsAreEqual(tt.wantResource, findings[i].Resource) || tt.wantResource == "" {
							if containsSubstring(findings[i].Message, tt.checkMsg) {
								found = true
								break
							}
						}
					}
					assert.True(t, found, "expected at least one finding message to contain %q", tt.checkMsg)
				}
			}
		})
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsCheck(s, sub))
}

func containsCheck(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestRestrictedViolationsChecker_CancelledContext(t *testing.T) {
	c := &RestrictedViolationsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(helpers.WithName("test"))
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestRestrictedViolationsChecker_Fixtures(t *testing.T) {
	c := &RestrictedViolationsChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-restricted-violations", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "non-restricted-deploy")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-restricted-violations", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
