package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestGeneratePod(t *testing.T) {
	t.Run("default pod has expected fields", func(t *testing.T) {
		pod := GeneratePod()
		assert.Equal(t, "test-pod", pod.Name)
		assert.Equal(t, "default", pod.Namespace)
		assert.Equal(t, "Pod", pod.Kind)
		assert.Equal(t, "v1", pod.APIVersion)
		require.Len(t, pod.Spec.Containers, 1)
		assert.Equal(t, "app", pod.Spec.Containers[0].Name)
		assert.Equal(t, "nginx:1.25", pod.Spec.Containers[0].Image)
	})

	t.Run("WithName sets pod name", func(t *testing.T) {
		pod := GeneratePod(WithName("my-pod"))
		assert.Equal(t, "my-pod", pod.Name)
	})

	t.Run("WithNamespace sets namespace", func(t *testing.T) {
		pod := GeneratePod(WithNamespace("kube-system"))
		assert.Equal(t, "kube-system", pod.Namespace)
	})

	t.Run("WithAnnotation adds annotation", func(t *testing.T) {
		pod := GeneratePod(WithAnnotation("key", "value"))
		assert.Equal(t, "value", pod.Annotations["key"])
	})

	t.Run("WithHostPID sets hostPID", func(t *testing.T) {
		pod := GeneratePod(WithHostPID(true))
		assert.True(t, pod.Spec.HostPID)
	})

	t.Run("WithHostIPC sets hostIPC", func(t *testing.T) {
		pod := GeneratePod(WithHostIPC(true))
		assert.True(t, pod.Spec.HostIPC)
	})

	t.Run("WithHostNetwork sets hostNetwork", func(t *testing.T) {
		pod := GeneratePod(WithHostNetwork(true))
		assert.True(t, pod.Spec.HostNetwork)
	})

	t.Run("WithShareProcessNamespace sets shareProcessNamespace", func(t *testing.T) {
		pod := GeneratePod(WithShareProcessNamespace(true))
		require.NotNil(t, pod.Spec.ShareProcessNamespace)
		assert.True(t, *pod.Spec.ShareProcessNamespace)
	})

	t.Run("WithHostPathVolume adds hostPath volume", func(t *testing.T) {
		pod := GeneratePod(WithHostPathVolume("data", "/var/data"))
		require.Len(t, pod.Spec.Volumes, 1)
		assert.Equal(t, "data", pod.Spec.Volumes[0].Name)
		require.NotNil(t, pod.Spec.Volumes[0].HostPath)
		assert.Equal(t, "/var/data", pod.Spec.Volumes[0].HostPath.Path)
	})

	t.Run("WithContainer replaces default container", func(t *testing.T) {
		c := NewContainer("sidecar", WithContainerImage("redis:7"))
		pod := GeneratePod(WithContainer(c))
		require.Len(t, pod.Spec.Containers, 1)
		assert.Equal(t, "sidecar", pod.Spec.Containers[0].Name)
		assert.Equal(t, "redis:7", pod.Spec.Containers[0].Image)
	})

	t.Run("WithInitContainer adds init container", func(t *testing.T) {
		c := NewContainer("init", WithContainerImage("busybox:latest"))
		pod := GeneratePod(WithInitContainer(c))
		require.Len(t, pod.Spec.InitContainers, 1)
		assert.Equal(t, "init", pod.Spec.InitContainers[0].Name)
		// Default container still present
		require.Len(t, pod.Spec.Containers, 1)
	})

	t.Run("WithSidecarContainer adds native sidecar", func(t *testing.T) {
		c := NewContainer("sidecar", WithContainerImage("envoy:1.28"))
		pod := GeneratePod(WithSidecarContainer(c))
		require.Len(t, pod.Spec.InitContainers, 1)
		assert.Equal(t, "sidecar", pod.Spec.InitContainers[0].Name)
		require.NotNil(t, pod.Spec.InitContainers[0].RestartPolicy)
		assert.Equal(t, corev1.ContainerRestartPolicyAlways, *pod.Spec.InitContainers[0].RestartPolicy)
	})

	t.Run("WithPodSecurityContext sets pod-level securityContext", func(t *testing.T) {
		uid := int64(1000)
		pod := GeneratePod(WithPodSecurityContext(&corev1.PodSecurityContext{
			RunAsUser: &uid,
		}))
		require.NotNil(t, pod.Spec.SecurityContext)
		require.NotNil(t, pod.Spec.SecurityContext.RunAsUser)
		assert.Equal(t, int64(1000), *pod.Spec.SecurityContext.RunAsUser)
	})
}

func TestNewContainer(t *testing.T) {
	t.Run("default container", func(t *testing.T) {
		c := NewContainer("app")
		assert.Equal(t, "app", c.Name)
		assert.Equal(t, "nginx:1.25", c.Image)
	})

	t.Run("WithContainerImage", func(t *testing.T) {
		c := NewContainer("app", WithContainerImage("redis:7"))
		assert.Equal(t, "redis:7", c.Image)
	})

	t.Run("WithPrivileged", func(t *testing.T) {
		c := NewContainer("app", WithPrivileged(true))
		require.NotNil(t, c.SecurityContext)
		require.NotNil(t, c.SecurityContext.Privileged)
		assert.True(t, *c.SecurityContext.Privileged)
	})

	t.Run("WithRunAsNonRoot", func(t *testing.T) {
		c := NewContainer("app", WithRunAsNonRoot(true))
		require.NotNil(t, c.SecurityContext)
		require.NotNil(t, c.SecurityContext.RunAsNonRoot)
		assert.True(t, *c.SecurityContext.RunAsNonRoot)
	})

	t.Run("WithRunAsUser", func(t *testing.T) {
		c := NewContainer("app", WithRunAsUser(1000))
		require.NotNil(t, c.SecurityContext)
		require.NotNil(t, c.SecurityContext.RunAsUser)
		assert.Equal(t, int64(1000), *c.SecurityContext.RunAsUser)
	})

	t.Run("WithCapabilities", func(t *testing.T) {
		c := NewContainer("app", WithCapabilities(
			[]corev1.Capability{"NET_ADMIN"},
			[]corev1.Capability{"ALL"},
		))
		require.NotNil(t, c.SecurityContext)
		require.NotNil(t, c.SecurityContext.Capabilities)
		assert.Equal(t, []corev1.Capability{"NET_ADMIN"}, c.SecurityContext.Capabilities.Add)
		assert.Equal(t, []corev1.Capability{"ALL"}, c.SecurityContext.Capabilities.Drop)
	})

	t.Run("WithReadOnlyRootFilesystem", func(t *testing.T) {
		c := NewContainer("app", WithReadOnlyRootFilesystem(true))
		require.NotNil(t, c.SecurityContext)
		require.NotNil(t, c.SecurityContext.ReadOnlyRootFilesystem)
		assert.True(t, *c.SecurityContext.ReadOnlyRootFilesystem)
	})

	t.Run("WithAllowPrivilegeEscalation", func(t *testing.T) {
		c := NewContainer("app", WithAllowPrivilegeEscalation(false))
		require.NotNil(t, c.SecurityContext)
		require.NotNil(t, c.SecurityContext.AllowPrivilegeEscalation)
		assert.False(t, *c.SecurityContext.AllowPrivilegeEscalation)
	})

	t.Run("WithResourceLimits", func(t *testing.T) {
		c := NewContainer("app", WithResourceLimits("100m", "128Mi"))
		require.NotNil(t, c.Resources.Limits)
		assert.Equal(t, resource.MustParse("100m"), c.Resources.Limits[corev1.ResourceCPU])
		assert.Equal(t, resource.MustParse("128Mi"), c.Resources.Limits[corev1.ResourceMemory])
	})

	t.Run("WithResourceRequests", func(t *testing.T) {
		c := NewContainer("app", WithResourceRequests("50m", "64Mi"))
		require.NotNil(t, c.Resources.Requests)
		assert.Equal(t, resource.MustParse("50m"), c.Resources.Requests[corev1.ResourceCPU])
		assert.Equal(t, resource.MustParse("64Mi"), c.Resources.Requests[corev1.ResourceMemory])
	})

	t.Run("WithHostPort", func(t *testing.T) {
		c := NewContainer("app", WithHostPort(8080))
		require.Len(t, c.Ports, 1)
		assert.Equal(t, int32(8080), c.Ports[0].HostPort)
	})
}

func TestGenerateDeployment(t *testing.T) {
	t.Run("default deployment", func(t *testing.T) {
		dep := GenerateDeployment()
		assert.Equal(t, "test-deployment", dep.Name)
		assert.Equal(t, "default", dep.Namespace)
		assert.Equal(t, "Deployment", dep.Kind)
		assert.Equal(t, "apps/v1", dep.APIVersion)
		require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	})

	t.Run("pod options apply to template", func(t *testing.T) {
		dep := GenerateDeployment(WithHostPID(true))
		assert.True(t, dep.Spec.Template.Spec.HostPID)
	})

	t.Run("container options via WithContainer", func(t *testing.T) {
		c := NewContainer("web", WithPrivileged(true))
		dep := GenerateDeployment(WithContainer(c))
		require.Len(t, dep.Spec.Template.Spec.Containers, 1)
		assert.Equal(t, "web", dep.Spec.Template.Spec.Containers[0].Name)
	})
}

func TestGenerateStatefulSet(t *testing.T) {
	ss := GenerateStatefulSet()
	assert.Equal(t, "test-statefulset", ss.Name)
	assert.Equal(t, "StatefulSet", ss.Kind)
	assert.Equal(t, "apps/v1", ss.APIVersion)
	require.Len(t, ss.Spec.Template.Spec.Containers, 1)
}

func TestGenerateDaemonSet(t *testing.T) {
	ds := GenerateDaemonSet()
	assert.Equal(t, "test-daemonset", ds.Name)
	assert.Equal(t, "DaemonSet", ds.Kind)
	assert.Equal(t, "apps/v1", ds.APIVersion)
	require.Len(t, ds.Spec.Template.Spec.Containers, 1)
}

func TestGenerateJob(t *testing.T) {
	job := GenerateJob()
	assert.Equal(t, "test-job", job.Name)
	assert.Equal(t, "Job", job.Kind)
	assert.Equal(t, "batch/v1", job.APIVersion)
	require.Len(t, job.Spec.Template.Spec.Containers, 1)
}

func TestGenerateCronJob(t *testing.T) {
	cj := GenerateCronJob()
	assert.Equal(t, "test-cronjob", cj.Name)
	assert.Equal(t, "CronJob", cj.Kind)
	assert.Equal(t, "batch/v1", cj.APIVersion)
	require.Len(t, cj.Spec.JobTemplate.Spec.Template.Spec.Containers, 1)
}
