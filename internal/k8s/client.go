package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// NewClient creates Kubernetes dynamic and discovery clients.
// If kubeconfig is empty, falls back to in-cluster config.
// The context parameter overrides the current-context in kubeconfig (empty = use default).
func NewClient(kubeconfig, context string) (dynamic.Interface, discovery.DiscoveryInterface, error) {
	var cfg *rest.Config
	var err error

	if kubeconfig == "" {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, nil, fmt.Errorf("creating in-cluster config: %w", err)
		}
	} else {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
		overrides := &clientcmd.ConfigOverrides{}
		if context != "" {
			overrides.CurrentContext = context
		}
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
		if err != nil {
			return nil, nil, fmt.Errorf("creating kubeconfig client: %w", err)
		}
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating dynamic client: %w", err)
	}

	discClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating discovery client: %w", err)
	}

	return dynClient, discClient, nil
}

// SkippedResource records a GVR that could not be fetched.
type SkippedResource struct {
	GVR   schema.GroupVersionResource
	Error error
}

// FetchResources fetches all resources for the given GVRs into a ResourceCache.
// On per-GVR failure (e.g., RBAC denied), the GVR is added to skipped and processing continues.
func FetchResources(ctx context.Context, client dynamic.Interface, gvrs []schema.GroupVersionResource) (*checker.ResourceCache, []SkippedResource) {
	cache := checker.NewResourceCache()
	var skipped []SkippedResource

	for _, gvr := range gvrs {
		list, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			skipped = append(skipped, SkippedResource{GVR: gvr, Error: err})
			continue
		}
		for i := range list.Items {
			cache.Add(gvr, list.Items[i])
		}
	}

	return cache, skipped
}

// ClusterVersion returns the Kubernetes server version string.
func ClusterVersion(disc discovery.DiscoveryInterface) (string, error) {
	info, err := disc.ServerVersion()
	if err != nil {
		return "", fmt.Errorf("getting server version: %w", err)
	}
	return info.GitVersion, nil
}
