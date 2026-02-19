package helpers

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodOption modifies a PodSpec during generation.
type PodOption func(*corev1.PodSpec, *metav1.ObjectMeta)

// ContainerOption modifies a Container during generation.
type ContainerOption func(*corev1.Container)

// --- Pod-level options ---

// WithName sets the resource name.
func WithName(name string) PodOption {
	return func(_ *corev1.PodSpec, meta *metav1.ObjectMeta) {
		meta.Name = name
	}
}

// WithNamespace sets the resource namespace.
func WithNamespace(ns string) PodOption {
	return func(_ *corev1.PodSpec, meta *metav1.ObjectMeta) {
		meta.Namespace = ns
	}
}

// WithAnnotation adds an annotation to the resource.
func WithAnnotation(key, value string) PodOption {
	return func(_ *corev1.PodSpec, meta *metav1.ObjectMeta) {
		if meta.Annotations == nil {
			meta.Annotations = make(map[string]string)
		}
		meta.Annotations[key] = value
	}
}

// WithHostPID sets spec.hostPID.
func WithHostPID(v bool) PodOption {
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		spec.HostPID = v
	}
}

// WithHostIPC sets spec.hostIPC.
func WithHostIPC(v bool) PodOption {
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		spec.HostIPC = v
	}
}

// WithHostNetwork sets spec.hostNetwork.
func WithHostNetwork(v bool) PodOption {
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		spec.HostNetwork = v
	}
}

// WithShareProcessNamespace sets spec.shareProcessNamespace.
func WithShareProcessNamespace(v bool) PodOption {
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		spec.ShareProcessNamespace = &v
	}
}

// WithHostPathVolume adds a hostPath volume.
func WithHostPathVolume(name, path string) PodOption {
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		spec.Volumes = append(spec.Volumes, corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: path,
				},
			},
		})
	}
}

// WithPodSecurityContext sets the pod-level security context.
func WithPodSecurityContext(sc *corev1.PodSecurityContext) PodOption {
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		spec.SecurityContext = sc
	}
}

// WithContainer replaces the default container with the provided one.
func WithContainer(c corev1.Container) PodOption { //nolint:gocritic // value copy is intentional for builder API ergonomics
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		spec.Containers = []corev1.Container{c}
	}
}

// WithInitContainer adds an init container.
func WithInitContainer(c corev1.Container) PodOption { //nolint:gocritic // value copy is intentional for builder API ergonomics
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		spec.InitContainers = append(spec.InitContainers, c)
	}
}

// WithSidecarContainer adds a native sidecar (init container with restartPolicy: Always).
func WithSidecarContainer(c corev1.Container) PodOption { //nolint:gocritic // value copy is intentional for builder API ergonomics
	return func(spec *corev1.PodSpec, _ *metav1.ObjectMeta) {
		policy := corev1.ContainerRestartPolicyAlways
		c.RestartPolicy = &policy
		spec.InitContainers = append(spec.InitContainers, c)
	}
}

// --- Container-level options ---

// NewContainer creates a container with the given name and options.
func NewContainer(name string, opts ...ContainerOption) corev1.Container {
	c := corev1.Container{
		Name:  name,
		Image: "nginx:1.25",
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithContainerImage sets the container image.
func WithContainerImage(image string) ContainerOption {
	return func(c *corev1.Container) {
		c.Image = image
	}
}

// WithPrivileged sets securityContext.privileged.
func WithPrivileged(v bool) ContainerOption {
	return func(c *corev1.Container) {
		ensureSecurityContext(c)
		c.SecurityContext.Privileged = &v
	}
}

// WithRunAsNonRoot sets securityContext.runAsNonRoot.
func WithRunAsNonRoot(v bool) ContainerOption {
	return func(c *corev1.Container) {
		ensureSecurityContext(c)
		c.SecurityContext.RunAsNonRoot = &v
	}
}

// WithRunAsUser sets securityContext.runAsUser.
func WithRunAsUser(uid int64) ContainerOption {
	return func(c *corev1.Container) {
		ensureSecurityContext(c)
		c.SecurityContext.RunAsUser = &uid
	}
}

// WithRunAsGroup sets securityContext.runAsGroup.
func WithRunAsGroup(gid int64) ContainerOption {
	return func(c *corev1.Container) {
		ensureSecurityContext(c)
		c.SecurityContext.RunAsGroup = &gid
	}
}

// WithCapabilities sets securityContext.capabilities with add and drop lists.
func WithCapabilities(add, drop []corev1.Capability) ContainerOption {
	return func(c *corev1.Container) {
		ensureSecurityContext(c)
		c.SecurityContext.Capabilities = &corev1.Capabilities{
			Add:  add,
			Drop: drop,
		}
	}
}

// WithReadOnlyRootFilesystem sets securityContext.readOnlyRootFilesystem.
func WithReadOnlyRootFilesystem(v bool) ContainerOption {
	return func(c *corev1.Container) {
		ensureSecurityContext(c)
		c.SecurityContext.ReadOnlyRootFilesystem = &v
	}
}

// WithAllowPrivilegeEscalation sets securityContext.allowPrivilegeEscalation.
func WithAllowPrivilegeEscalation(v bool) ContainerOption {
	return func(c *corev1.Container) {
		ensureSecurityContext(c)
		c.SecurityContext.AllowPrivilegeEscalation = &v
	}
}

// WithResourceLimits sets container resource limits for CPU and memory.
func WithResourceLimits(cpu, memory string) ContainerOption {
	return func(c *corev1.Container) {
		if c.Resources.Limits == nil {
			c.Resources.Limits = make(corev1.ResourceList)
		}
		c.Resources.Limits[corev1.ResourceCPU] = resource.MustParse(cpu)
		c.Resources.Limits[corev1.ResourceMemory] = resource.MustParse(memory)
	}
}

// WithResourceRequests sets container resource requests for CPU and memory.
func WithResourceRequests(cpu, memory string) ContainerOption {
	return func(c *corev1.Container) {
		if c.Resources.Requests == nil {
			c.Resources.Requests = make(corev1.ResourceList)
		}
		c.Resources.Requests[corev1.ResourceCPU] = resource.MustParse(cpu)
		c.Resources.Requests[corev1.ResourceMemory] = resource.MustParse(memory)
	}
}

// WithHostPort adds a port with the specified hostPort.
func WithHostPort(port int32) ContainerOption {
	return func(c *corev1.Container) {
		c.Ports = append(c.Ports, corev1.ContainerPort{
			HostPort:      port,
			ContainerPort: port,
		})
	}
}

func ensureSecurityContext(c *corev1.Container) {
	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}
}

// --- Resource generators ---

func defaultPodSpec(opts []PodOption) (corev1.PodSpec, metav1.ObjectMeta) {
	meta := metav1.ObjectMeta{
		Name:      "test-pod",
		Namespace: "default",
	}
	spec := corev1.PodSpec{
		Containers: []corev1.Container{
			NewContainer("app"),
		},
	}
	for _, opt := range opts {
		opt(&spec, &meta)
	}
	return spec, meta
}

// GeneratePod creates a Pod with the given options.
func GeneratePod(opts ...PodOption) *corev1.Pod {
	spec, meta := defaultPodSpec(opts)
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: meta,
		Spec:       spec,
	}
}

// GenerateDeployment creates a Deployment with the given options applied to its pod template.
func GenerateDeployment(opts ...PodOption) *appsv1.Deployment {
	spec, meta := defaultPodSpec(opts)
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-deployment",
			Namespace:   meta.Namespace,
			Annotations: meta.Annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: meta,
				Spec:       spec,
			},
		},
	}
}

// GenerateStatefulSet creates a StatefulSet with the given options applied to its pod template.
func GenerateStatefulSet(opts ...PodOption) *appsv1.StatefulSet {
	spec, meta := defaultPodSpec(opts)
	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "StatefulSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-statefulset",
			Namespace:   meta.Namespace,
			Annotations: meta.Annotations,
		},
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: meta,
				Spec:       spec,
			},
		},
	}
}

// GenerateDaemonSet creates a DaemonSet with the given options applied to its pod template.
func GenerateDaemonSet(opts ...PodOption) *appsv1.DaemonSet {
	spec, meta := defaultPodSpec(opts)
	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-daemonset",
			Namespace:   meta.Namespace,
			Annotations: meta.Annotations,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: meta,
				Spec:       spec,
			},
		},
	}
}

// GenerateJob creates a Job with the given options applied to its pod template.
func GenerateJob(opts ...PodOption) *batchv1.Job {
	spec, meta := defaultPodSpec(opts)
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Job",
			APIVersion: "batch/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-job",
			Namespace:   meta.Namespace,
			Annotations: meta.Annotations,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: meta,
				Spec:       spec,
			},
		},
	}
}

// GenerateCronJob creates a CronJob with the given options applied to its pod template.
func GenerateCronJob(opts ...PodOption) *batchv1.CronJob {
	spec, meta := defaultPodSpec(opts)
	return &batchv1.CronJob{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CronJob",
			APIVersion: "batch/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-cronjob",
			Namespace:   meta.Namespace,
			Annotations: meta.Annotations,
		},
		Spec: batchv1.CronJobSpec{
			Schedule: "*/5 * * * *",
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: meta,
						Spec:       spec,
					},
				},
			},
		},
	}
}
