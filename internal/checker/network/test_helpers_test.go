package network

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// toUnstructured converts a typed Kubernetes object to an unstructured representation for testing.
func toUnstructured(t *testing.T, obj interface{}) unstructured.Unstructured {
	t.Helper()
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	require.NoError(t, err)
	return unstructured.Unstructured{Object: data}
}

// makeService creates an unstructured Service for testing.
func makeService(t *testing.T, name, namespace, svcType string) unstructured.Unstructured {
	t.Helper()
	svc := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceType(svcType)},
	}
	return toUnstructured(t, svc)
}

// makeServiceWithExternalIPs creates an unstructured Service with externalIPs set.
func makeServiceWithExternalIPs(t *testing.T, name, namespace string, externalIPs []string) unstructured.Unstructured {
	t.Helper()
	svc := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Type:        corev1.ServiceTypeClusterIP,
			ExternalIPs: externalIPs,
		},
	}
	return toUnstructured(t, svc)
}

// makeConfigMap creates an unstructured ConfigMap for testing.
func makeConfigMap(t *testing.T, name, namespace string, data map[string]string) unstructured.Unstructured {
	t.Helper()
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       data,
	}
	return toUnstructured(t, cm)
}

// makePeerAuthentication creates an unstructured PeerAuthentication (Istio CRD) for testing.
func makePeerAuthentication(t *testing.T, name, namespace, mtlsMode string) unstructured.Unstructured {
	t.Helper()
	obj := map[string]interface{}{
		"apiVersion": "security.istio.io/v1beta1",
		"kind":       "PeerAuthentication",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"mtls": map[string]interface{}{
				"mode": mtlsMode,
			},
		},
	}
	return unstructured.Unstructured{Object: obj}
}

// makePeerAuthenticationWithSelector creates a PeerAuthentication with a target selector.
func makePeerAuthenticationWithSelector(t *testing.T, name, namespace, mtlsMode string, matchLabels map[string]string) unstructured.Unstructured {
	t.Helper()
	labels := make(map[string]interface{}, len(matchLabels))
	for k, v := range matchLabels {
		labels[k] = v
	}
	obj := map[string]interface{}{
		"apiVersion": "security.istio.io/v1beta1",
		"kind":       "PeerAuthentication",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"mtls": map[string]interface{}{
				"mode": mtlsMode,
			},
			"selector": map[string]interface{}{
				"matchLabels": labels,
			},
		},
	}
	return unstructured.Unstructured{Object: obj}
}

// makePeerAuthenticationNoMTLS creates a PeerAuthentication with no mtls field set.
func makePeerAuthenticationNoMTLS(t *testing.T, name, namespace string) unstructured.Unstructured {
	t.Helper()
	obj := map[string]interface{}{
		"apiVersion": "security.istio.io/v1beta1",
		"kind":       "PeerAuthentication",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{},
	}
	return unstructured.Unstructured{Object: obj}
}
