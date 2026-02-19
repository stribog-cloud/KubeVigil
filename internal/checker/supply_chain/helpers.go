// Package supply_chain implements supply chain security checkers.
// These checkers detect container runtime socket mounts, missing probes,
// lifecycle hook concerns, and stale images.
package supply_chain

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// runtimeSocketPaths contains known container runtime socket paths.
var runtimeSocketPaths = map[string]bool{
	"/var/run/docker.sock":                true,
	"/run/containerd/containerd.sock":     true,
	"/var/run/crio/crio.sock":             true,
	"/run/docker.sock":                    true,
	"/var/run/containerd/containerd.sock": true,
}

// containerFieldPath builds a JSON-path field reference for a container field.
func containerFieldPath(ct workload.ContainerType, idx int, field string) string {
	switch ct {
	case workload.ContainerTypeInit, workload.ContainerTypeSidecar:
		return fmt.Sprintf(".spec.initContainers[%d].%s", idx, field)
	default:
		return fmt.Sprintf(".spec.containers[%d].%s", idx, field)
	}
}

// GVRs returns the GVRs required by supply chain checkers (same as workload).
func GVRs() []schema.GroupVersionResource {
	return workload.GVRs()
}
