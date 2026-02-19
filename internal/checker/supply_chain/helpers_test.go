package supply_chain

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TestContainerFieldPath tests the containerFieldPath helper function
// covering all branches: ContainerTypeInit, ContainerTypeSidecar, and default (regular).
func TestContainerFieldPath(t *testing.T) {
	testCases := []struct {
		name  string
		ct    workload.ContainerType
		idx   int
		field string
		want  string
	}{
		{
			name:  "init container produces initContainers path",
			ct:    workload.ContainerTypeInit,
			idx:   0,
			field: "image",
			want:  ".spec.initContainers[0].image",
		},
		{
			name:  "init container with non-zero index",
			ct:    workload.ContainerTypeInit,
			idx:   2,
			field: "volumeMounts",
			want:  ".spec.initContainers[2].volumeMounts",
		},
		{
			name:  "sidecar container produces initContainers path",
			ct:    workload.ContainerTypeSidecar,
			idx:   0,
			field: "securityContext",
			want:  ".spec.initContainers[0].securityContext",
		},
		{
			name:  "sidecar container with non-zero index",
			ct:    workload.ContainerTypeSidecar,
			idx:   1,
			field: "resources",
			want:  ".spec.initContainers[1].resources",
		},
		{
			name:  "regular container produces containers path",
			ct:    workload.ContainerTypeRegular,
			idx:   0,
			field: "image",
			want:  ".spec.containers[0].image",
		},
		{
			name:  "regular container with non-zero index",
			ct:    workload.ContainerTypeRegular,
			idx:   3,
			field: "ports",
			want:  ".spec.containers[3].ports",
		},
		{
			name:  "unknown container type defaults to containers path",
			ct:    workload.ContainerType(99),
			idx:   0,
			field: "image",
			want:  ".spec.containers[0].image",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := containerFieldPath(tc.ct, tc.idx, tc.field)
			assert.Equal(t, tc.want, got)
		})
	}
}
