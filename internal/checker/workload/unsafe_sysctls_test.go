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

func TestUnsafeSysctlsChecker_Metadata(t *testing.T) {
	c := &UnsafeSysctlsChecker{}

	assert.Equal(t, "unsafe-sysctls", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestUnsafeSysctlsChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	c := &UnsafeSysctlsChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		checkMessage string
	}{
		{
			name: "unsafe sysctl triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("unsafe-sysctl-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						Sysctls: []corev1.Sysctl{
							{Name: "kernel.msgmax", Value: "65536"},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "unsafe-sysctl-pod",
			checkMessage: "kernel.msgmax",
		},
		{
			name: "multiple unsafe sysctls produces single finding mentioning all",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-unsafe"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						Sysctls: []corev1.Sysctl{
							{Name: "kernel.msgmax", Value: "65536"},
							{Name: "net.core.somaxconn", Value: "1024"},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			checkMessage: "kernel.msgmax",
		},
		{
			name: "safe sysctls produce no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("safe-sysctl-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						Sysctls: []corev1.Sysctl{
							{Name: "kernel.shm_rmid_forced", Value: "1"},
							{Name: "net.ipv4.ip_local_port_range", Value: "1024 65535"},
							{Name: "net.ipv4.ip_unprivileged_port_start", Value: "1024"},
							{Name: "net.ipv4.tcp_syncookies", Value: "1"},
							{Name: "net.ipv4.ping_group_range", Value: "0 2147483647"},
							{Name: "net.ipv4.ip_local_reserved_ports", Value: ""},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "mix of safe and unsafe sysctls triggers finding for unsafe only",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("mixed-sysctl"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						Sysctls: []corev1.Sysctl{
							{Name: "kernel.shm_rmid_forced", Value: "1"},
							{Name: "net.core.somaxconn", Value: "1024"},
						},
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			checkMessage: "net.core.somaxconn",
		},
		{
			name: "no sysctls produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-sysctl"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no securityContext produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-sc"))
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
				return helpers.LoadFixture(t, "unsafe-sysctls", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "unsafe-sysctl-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "unsafe-sysctls", "pod-passing.yaml")
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
				assert.Equal(t, "unsafe-sysctls", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Empty(t, findings[0].Container, "unsafe-sysctls is a pod-level check")
				assert.Equal(t, ".spec.securityContext.sysctls", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.checkMessage != "" {
					assert.Contains(t, findings[0].Message, tt.checkMessage)
				}
			}
		})
	}
}

func TestUnsafeSysctlsChecker_CancelledContext(t *testing.T) {
	c := &UnsafeSysctlsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}
