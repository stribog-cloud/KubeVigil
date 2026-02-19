package image

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// ContainerImage associates a parsed image reference with its container and resource metadata.
type ContainerImage struct {
	// Ref is the parsed image reference.
	Ref Ref
	// ContainerName is the name of the container.
	ContainerName string
	// ContainerType is the type of container (regular, init, sidecar).
	ContainerType workload.ContainerType
	// ContainerIdx is the index of the container in its array.
	ContainerIdx int
	// ResourceName is the name of the owning resource.
	ResourceName string
	// Namespace is the namespace of the owning resource.
	Namespace string
	// Kind is the kind of the owning resource.
	Kind string
	// PullPolicy is the imagePullPolicy of the container.
	PullPolicy string
}

// ExtractContainerImages extracts all container images from workload resources in the cache.
// It parses each container's image string into an Ref and associates it with
// the container and resource metadata.
func ExtractContainerImages(cache *checker.ResourceCache) []ContainerImage {
	specs := workload.ExtractPodSpecs(cache)
	var images []ContainerImage

	for i := range specs {
		info := &specs[i]
		workload.IterateContainers(info, func(c corev1.Container, ct workload.ContainerType, idx int) {
			images = append(images, ContainerImage{
				Ref:           ParseRef(c.Image),
				ContainerName: c.Name,
				ContainerType: ct,
				ContainerIdx:  idx,
				ResourceName:  info.ResourceName,
				Namespace:     info.Namespace,
				Kind:          info.Kind,
				PullPolicy:    string(c.ImagePullPolicy),
			})
		})
	}

	return images
}

// containerFieldPath returns the JSON field path for a container field.
func containerFieldPath(ct workload.ContainerType, idx int, field string) string {
	switch ct {
	case workload.ContainerTypeInit, workload.ContainerTypeSidecar:
		return fmt.Sprintf(".spec.initContainers[%d].%s", idx, field)
	default:
		return fmt.Sprintf(".spec.containers[%d].%s", idx, field)
	}
}

// registryMatches checks if a registry matches a pattern.
// Handles Docker Hub normalization (docker.io == index.docker.io == registry-1.docker.io)
// and performs case-insensitive comparison.
func registryMatches(registry, pattern string) bool {
	return strings.EqualFold(normalizeRegistry(registry), normalizeRegistry(pattern))
}

// normalizeRegistry normalizes Docker Hub registry variants to "docker.io".
func normalizeRegistry(reg string) string {
	reg = strings.TrimSuffix(reg, "/")
	switch reg {
	case "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		return "docker.io"
	case "":
		return "docker.io"
	default:
		return reg
	}
}
