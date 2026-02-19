package workload

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

func TestEphemeralContainerPolicyChecker_Metadata(t *testing.T) {
	c := &EphemeralContainerPolicyChecker{}

	assert.Equal(t, "ephemeral-container-policy", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryLifecycle)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestEphemeralContainerPolicyChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	c := &EphemeralContainerPolicyChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "ephemeral container with no securityContext triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("eph-no-sc"))
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{
					{
						EphemeralContainerCommon: corev1.EphemeralContainerCommon{
							Name:  "debugger",
							Image: "busybox:latest",
						},
					},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "debugger",
			wantResource:  "eph-no-sc",
		},
		{
			name: "ephemeral container with full security context produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("eph-secure"))
				trueVal := true
				falseVal := false
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{
					{
						EphemeralContainerCommon: corev1.EphemeralContainerCommon{
							Name:  "debugger",
							Image: "busybox:latest",
							SecurityContext: &corev1.SecurityContext{
								RunAsNonRoot:             &trueVal,
								AllowPrivilegeEscalation: &falseVal,
							},
						},
					},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ephemeral container with privileged true triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("eph-priv"))
				trueVal := true
				falseVal := false
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{
					{
						EphemeralContainerCommon: corev1.EphemeralContainerCommon{
							Name:  "debugger",
							Image: "busybox:latest",
							SecurityContext: &corev1.SecurityContext{
								Privileged:               &trueVal,
								RunAsNonRoot:             &trueVal,
								AllowPrivilegeEscalation: &falseVal,
							},
						},
					},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "debugger",
		},
		{
			name: "ephemeral container missing runAsNonRoot triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("eph-no-nonroot"))
				falseVal := false
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{
					{
						EphemeralContainerCommon: corev1.EphemeralContainerCommon{
							Name:  "debugger",
							Image: "busybox:latest",
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &falseVal,
							},
						},
					},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ephemeral container missing allowPrivilegeEscalation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("eph-no-ape"))
				trueVal := true
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{
					{
						EphemeralContainerCommon: corev1.EphemeralContainerCommon{
							Name:  "debugger",
							Image: "busybox:latest",
							SecurityContext: &corev1.SecurityContext{
								RunAsNonRoot: &trueVal,
							},
						},
					},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "multiple ephemeral containers — only insecure ones trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("eph-multi"))
				trueVal := true
				falseVal := false
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{
					{
						EphemeralContainerCommon: corev1.EphemeralContainerCommon{
							Name:  "secure-debug",
							Image: "busybox:latest",
							SecurityContext: &corev1.SecurityContext{
								RunAsNonRoot:             &trueVal,
								AllowPrivilegeEscalation: &falseVal,
							},
						},
					},
					{
						EphemeralContainerCommon: corev1.EphemeralContainerCommon{
							Name:  "insecure-debug",
							Image: "busybox:latest",
						},
					},
				}
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "insecure-debug",
		},
		{
			name: "no ephemeral containers produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-eph"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "ephemeral-container-policy", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "ephemeral-insecure-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "ephemeral-container-policy", "pod-passing.yaml")
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
				assert.Equal(t, "ephemeral-container-policy", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)

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

func TestEphemeralContainerPolicyChecker_CancelledContext(t *testing.T) {
	c := &EphemeralContainerPolicyChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}
