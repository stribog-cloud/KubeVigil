package supply_chain

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
func toUnstructured(t *testing.T, obj interface{}) unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	var result unstructured.Unstructured
	require.NoError(t, json.Unmarshal(data, &result.Object))
	return result
}

// makeDeployment creates a Deployment with the given spec for testing.
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

// makeDeploymentWithAnnotations creates a Deployment with annotations for testing.
func makeDeploymentWithAnnotations(t *testing.T, name, ns string, annotations map[string]string, spec corev1.PodSpec) unstructured.Unstructured {
	t.Helper()
	replicas := int32(1)
	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: annotations,
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
