package k8s

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	kubetesting "k8s.io/client-go/testing"
)

var (
	podGVR    = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
)

func newPod(name, namespace string) *unstructured.Unstructured {
	pod := &unstructured.Unstructured{}
	pod.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Pod"})
	pod.SetName(name)
	pod.SetNamespace(namespace)
	return pod
}

func newDeployment(name, namespace string) *unstructured.Unstructured {
	dep := &unstructured.Unstructured{}
	dep.SetGroupVersionKind(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"})
	dep.SetName(name)
	dep.SetNamespace(namespace)
	return dep
}

func newFakeClient(objects ...runtime.Object) *fakedynamic.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return fakedynamic.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			podGVR:    "PodList",
			deployGVR: "DeploymentList",
		},
		objects...,
	)
}

func TestFetchResources_Success(t *testing.T) {
	pod1 := newPod("pod-1", "default")
	pod2 := newPod("pod-2", "kube-system")
	dep1 := newDeployment("deploy-1", "default")

	client := newFakeClient(pod1, pod2, dep1)

	cache, skipped := FetchResources(context.Background(), client, []schema.GroupVersionResource{podGVR, deployGVR})

	assert.Empty(t, skipped)
	assert.Equal(t, 3, cache.Len())

	pods := cache.List(podGVR)
	require.Len(t, pods, 2)

	deployments := cache.List(deployGVR)
	require.Len(t, deployments, 1)
	assert.Equal(t, "deploy-1", deployments[0].GetName())
}

func TestFetchResources_PartialFailure(t *testing.T) {
	pod1 := newPod("pod-1", "default")
	client := newFakeClient(pod1)

	// Inject error for deployments only.
	client.PrependReactor("list", "deployments", func(action kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("forbidden: RBAC denied")
	})

	cache, skipped := FetchResources(context.Background(), client, []schema.GroupVersionResource{podGVR, deployGVR})

	require.Len(t, skipped, 1)
	assert.Equal(t, deployGVR, skipped[0].GVR)
	assert.Contains(t, skipped[0].Error.Error(), "RBAC denied")

	// Pods should still be fetched successfully.
	assert.Equal(t, 1, cache.Len())
	pods := cache.List(podGVR)
	require.Len(t, pods, 1)
	assert.Equal(t, "pod-1", pods[0].GetName())
}

func TestFetchResources_AllFail(t *testing.T) {
	client := newFakeClient()

	client.PrependReactor("list", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("cluster unreachable")
	})

	cache, skipped := FetchResources(context.Background(), client, []schema.GroupVersionResource{podGVR, deployGVR})

	assert.Len(t, skipped, 2)
	assert.Equal(t, 0, cache.Len())
}

func TestFetchResources_EmptyCluster(t *testing.T) {
	client := newFakeClient()

	cache, skipped := FetchResources(context.Background(), client, []schema.GroupVersionResource{podGVR, deployGVR})

	assert.Empty(t, skipped)
	assert.Equal(t, 0, cache.Len())
}

func TestFetchResources_ContextCancelled(t *testing.T) {
	pod1 := newPod("pod-1", "default")
	client := newFakeClient(pod1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	// Fake client may or may not respect context cancellation.
	// We just verify it doesn't panic and returns a valid cache.
	cache, _ := FetchResources(ctx, client, []schema.GroupVersionResource{podGVR})
	assert.NotNil(t, cache)
}

func TestFetchResources_NoGVRs(t *testing.T) {
	client := newFakeClient()

	cache, skipped := FetchResources(context.Background(), client, nil)

	assert.Empty(t, skipped)
	assert.Equal(t, 0, cache.Len())
}

func TestClusterVersion(t *testing.T) {
	fakeDisc := &fakediscovery.FakeDiscovery{
		Fake: &kubetesting.Fake{},
		FakedServerVersion: &version.Info{
			GitVersion: "v1.28.0",
		},
	}

	ver, err := ClusterVersion(fakeDisc)
	require.NoError(t, err)
	assert.Equal(t, "v1.28.0", ver)
}
