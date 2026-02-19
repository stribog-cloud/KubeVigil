package scheduling

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// toUnstructured converts a typed Kubernetes object to an unstructured representation.
func toUnstructured(t *testing.T, obj interface{}) unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	var result unstructured.Unstructured
	require.NoError(t, json.Unmarshal(data, &result.Object))
	return result
}

// makeDeployment creates a Deployment with the given name, namespace, replicas, and pod spec options.
func makeDeployment(t *testing.T, name, ns string, replicas int32, labels map[string]string, tolerations []corev1.Toleration) unstructured.Unstructured {
	t.Helper()
	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers:  []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					Tolerations: tolerations,
				},
			},
		},
	}
	return toUnstructured(t, dep)
}

// makeDeploymentWithSpec creates a Deployment with a custom PodSpec.
func makeDeploymentWithSpec(t *testing.T, name, ns string, replicas int32, labels map[string]string, spec corev1.PodSpec) unstructured.Unstructured {
	t.Helper()
	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       spec,
			},
		},
	}
	return toUnstructured(t, dep)
}

// makeStatefulSet creates a StatefulSet for testing.
func makeStatefulSet(t *testing.T, name, ns string, replicas int32, labels map[string]string) unstructured.Unstructured {
	t.Helper()
	ss := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				},
			},
		},
	}
	return toUnstructured(t, ss)
}

// makePDB creates a PodDisruptionBudget for testing.
func makePDB(t *testing.T, name, ns string, matchLabels map[string]string) unstructured.Unstructured {
	t.Helper()
	minAvail := intstr.FromInt32(1)
	pdb := &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &minAvail,
			Selector:     &metav1.LabelSelector{MatchLabels: matchLabels},
		},
	}
	return toUnstructured(t, pdb)
}

// makeHPA creates a HorizontalPodAutoscaler for testing.
func makeHPA(t *testing.T, name, ns, targetKind, targetName string) unstructured.Unstructured {
	t.Helper()
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		TypeMeta: metav1.TypeMeta{Kind: "HorizontalPodAutoscaler", APIVersion: "autoscaling/v2"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				Kind:       targetKind,
				Name:       targetName,
				APIVersion: "apps/v1",
			},
			MinReplicas: int32Ptr(1),
			MaxReplicas: 10,
		},
	}
	return toUnstructured(t, hpa)
}

func int32Ptr(v int32) *int32 { return &v }
