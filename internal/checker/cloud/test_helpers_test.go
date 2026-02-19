package cloud

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// toUnstructured converts a typed Kubernetes object to an unstructured representation.
func toUnstructured(t *testing.T, obj any) unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	var result unstructured.Unstructured
	require.NoError(t, json.Unmarshal(data, &result.Object))
	return result
}

// makeNode creates a Node for testing with the given labels.
func makeNode(t *testing.T, name string, labels map[string]string) unstructured.Unstructured {
	t.Helper()
	node := &corev1.Node{
		TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
	return toUnstructured(t, node)
}

// makeDeployment creates a Deployment for testing.
func makeDeployment(t *testing.T, name, ns string, spec corev1.PodSpec) unstructured.Unstructured {
	t.Helper()
	replicas := int32(1)
	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				Spec: spec,
			},
		},
	}
	return toUnstructured(t, dep)
}

// makeDaemonSet creates a DaemonSet for testing.
func makeDaemonSet(t *testing.T, name, ns string, containers []corev1.Container) unstructured.Unstructured {
	t.Helper()
	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: containers,
				},
			},
		},
	}
	return toUnstructured(t, ds)
}
