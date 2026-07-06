package fix

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestParseDocuments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantDocs int
		wantErr  bool
	}{
		{
			name: "single document",
			input: `apiVersion: v1
kind: Pod
metadata:
  name: test
`,
			wantDocs: 1,
		},
		{
			name: "two documents with separator",
			input: `apiVersion: v1
kind: Pod
metadata:
  name: first
---
apiVersion: v1
kind: Pod
metadata:
  name: second
`,
			wantDocs: 2,
		},
		{
			name: "three documents",
			input: `---
apiVersion: v1
kind: Pod
metadata:
  name: first
---
apiVersion: v1
kind: Service
metadata:
  name: second
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: third
`,
			wantDocs: 3,
		},
		{
			name:     "empty input",
			input:    "",
			wantDocs: 0,
		},
		{
			name:     "whitespace only",
			input:    "   \n  \n  ",
			wantDocs: 0,
		},
		{
			name: "leading separator",
			input: `---
apiVersion: v1
kind: Pod
`,
			wantDocs: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs, err := ParseDocuments([]byte(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, docs, tt.wantDocs)
		})
	}
}

func TestSerializeDocuments(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: first
---
apiVersion: v1
kind: Service
metadata:
  name: second
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 2)

	output, err := SerializeDocuments(docs)
	require.NoError(t, err)

	// Unmodified documents should be preserved verbatim (raw bytes).
	assert.Contains(t, string(output), "name: first")
	assert.Contains(t, string(output), "name: second")
	assert.Contains(t, string(output), "---")
}

func TestRoundTrip(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
  labels:
    app: web
spec:
  containers:
  - name: app
    image: nginx:latest
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 1)

	// No modifications — unmodified documents use raw bytes.
	output, err := SerializeDocuments(docs)
	require.NoError(t, err)
	assert.Equal(t, input, string(output))
}

func TestRoundTripComments(t *testing.T) {
	input := `# Top-level comment
apiVersion: v1
kind: Pod
metadata:
  name: test # inline comment
  # Comment above labels
  labels:
    app: web
spec:
  containers:
  - name: app
    image: nginx:latest # image comment
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 1)

	// Unmodified: raw bytes are used, so comments are preserved exactly.
	output, err := SerializeDocuments(docs)
	require.NoError(t, err)
	assert.Equal(t, input, string(output))
}

func TestRoundTripBlankLines(t *testing.T) {
	// Blank lines are preserved for unmodified documents via raw bytes.
	input := `apiVersion: v1
kind: Pod

metadata:
  name: test

spec:
  containers:
  - name: app
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 1)

	output, err := SerializeDocuments(docs)
	require.NoError(t, err)
	assert.Equal(t, input, string(output))
}

func TestRoundTripKeyOrder(t *testing.T) {
	input := `kind: Pod
apiVersion: v1
metadata:
  name: test
  namespace: default
  labels:
    app: web
    tier: frontend
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 1)

	// Unmodified: raw bytes preserve key order.
	output, err := SerializeDocuments(docs)
	require.NoError(t, err)
	assert.Equal(t, input, string(output))
}

func TestFindNode(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
  labels:
    app: web
spec:
  containers:
  - name: app
    image: nginx:latest
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	tests := []struct {
		name      string
		path      string
		wantValue string
		wantNil   bool
	}{
		{
			name:      "top level field",
			path:      "apiVersion",
			wantValue: "v1",
		},
		{
			name:      "nested field",
			path:      "metadata.name",
			wantValue: "test",
		},
		{
			name:      "deeply nested",
			path:      "metadata.labels.app",
			wantValue: "web",
		},
		{
			name:      "kind field",
			path:      "kind",
			wantValue: "Pod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := FindNode(node, tt.path)
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, found)
			} else {
				require.NotNil(t, found)
				assert.Equal(t, tt.wantValue, found.Value)
			}
		})
	}
}

func TestFindNodeNested(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Navigate to deeply nested securityContext.privileged.
	found, err := FindNode(node, "spec.template.spec.containers[0].securityContext.privileged")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "true", found.Value)

	// Navigate to securityContext.allowPrivilegeEscalation.
	found, err = FindNode(node, "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "true", found.Value)

	// Navigate to the container name.
	found, err = FindNode(node, "spec.template.spec.containers[0].name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "app", found.Value)
}

func TestFindNodeArray(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: first
    image: nginx
  - name: second
    image: alpine
  - name: third
    image: busybox
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Index 0.
	found, err := FindNode(node, "spec.containers[0].name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "first", found.Value)

	// Index 1.
	found, err = FindNode(node, "spec.containers[1].name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "second", found.Value)

	// Index 2.
	found, err = FindNode(node, "spec.containers[2].image")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "busybox", found.Value)

	// Out of bounds.
	found, err = FindNode(node, "spec.containers[5].name")
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestFindNodeNotFound(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "nonexistent top-level key",
			path: "nonexistent",
		},
		{
			name: "nonexistent nested key",
			path: "metadata.labels.app",
		},
		{
			name: "deep nonexistent path",
			path: "spec.template.spec.containers",
		},
		{
			name: "index on non-sequence",
			path: "metadata[0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := FindNode(node, tt.path)
			require.NoError(t, err)
			assert.Nil(t, found, "expected nil for path %q", tt.path)
		})
	}
}

func TestSetNode(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Set an existing field.
	err = SetNode(node, "metadata.name", "updated")
	require.NoError(t, err)

	found, err := FindNode(node, "metadata.name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "updated", found.Value)

	// Set a boolean.
	err = SetNode(node, "kind", "Service")
	require.NoError(t, err)

	found, err = FindNode(node, "kind")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "Service", found.Value)
}

func TestSetNodeCreateIntermediate(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Set a deeply nested value that doesn't exist yet.
	err = SetNode(node, "spec.template.spec.securityContext.runAsNonRoot", true)
	require.NoError(t, err)

	// Verify the intermediate nodes were created.
	found, err := FindNode(node, "spec.template.spec.securityContext.runAsNonRoot")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "true", found.Value)

	// Verify existing fields are untouched.
	found, err = FindNode(node, "metadata.name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "test", found.Value)
}

func TestSetNodePreservesComments(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  # This is a comment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true  # DANGER
          allowPrivilegeEscalation: true
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Set privileged to false.
	err = SetNode(node, "spec.template.spec.containers[0].securityContext.privileged", false)
	require.NoError(t, err)

	// Verify the value changed.
	found, err := FindNode(node, "spec.template.spec.containers[0].securityContext.privileged")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "false", found.Value)

	// Verify the inline comment on "privileged" is preserved.
	// yaml.v3 stores LineComment with the "# " prefix.
	assert.Equal(t, "# DANGER", found.LineComment)

	// Verify the neighbor field allowPrivilegeEscalation is untouched.
	found, err = FindNode(node, "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "true", found.Value)

	// Serialize and verify comment in output.
	serialized, err := SerializeNode(node)
	require.NoError(t, err)
	assert.Contains(t, string(serialized), "# DANGER")
}

func TestAddNode(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Add a new field.
	err = AddNode(node, "metadata.labels", map[string]any{"app": "web"})
	require.NoError(t, err)

	// Verify it was added.
	found, err := FindNode(node, "metadata.labels.app")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "web", found.Value)
}

func TestAddNodeAlreadyExists(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Try to add a field that already exists.
	err = AddNode(node, "metadata.name", "new-name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Verify original value is unchanged.
	found, err := FindNode(node, "metadata.name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "test", found.Value)
}

func TestRemoveNode(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
  labels:
    app: web
    tier: frontend
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Remove a field.
	err = RemoveNode(node, "metadata.labels.tier")
	require.NoError(t, err)

	// Verify it was removed.
	found, err := FindNode(node, "metadata.labels.tier")
	require.NoError(t, err)
	assert.Nil(t, found)

	// Verify sibling is still there.
	found, err = FindNode(node, "metadata.labels.app")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "web", found.Value)

	// Verify other fields untouched.
	found, err = FindNode(node, "metadata.name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "test", found.Value)
}

func TestRemoveNodeIdempotent(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Remove a field that doesn't exist — should not error.
	err = RemoveNode(node, "metadata.labels")
	require.NoError(t, err)

	// Remove from a path where the parent doesn't exist.
	err = RemoveNode(node, "spec.containers[0].securityContext")
	require.NoError(t, err)

	// Remove a deeply nonexistent field.
	err = RemoveNode(node, "nonexistent.deep.path")
	require.NoError(t, err)
}

func TestMergeNode(t *testing.T) {
	t.Run("merge into map", func(t *testing.T) {
		input := `apiVersion: v1
kind: Pod
metadata:
  name: test
  labels:
    app: web
`
		node, err := ParseYAML([]byte(input))
		require.NoError(t, err)

		// Merge new keys into the labels map.
		err = MergeNode(node, "metadata.labels", map[string]any{
			"tier":    "frontend",
			"version": "v1",
			"app":     "should-not-overwrite",
		})
		require.NoError(t, err)

		// New keys were added.
		found, err := FindNode(node, "metadata.labels.tier")
		require.NoError(t, err)
		require.NotNil(t, found)
		assert.Equal(t, "frontend", found.Value)

		found, err = FindNode(node, "metadata.labels.version")
		require.NoError(t, err)
		require.NotNil(t, found)
		assert.Equal(t, "v1", found.Value)

		// Existing key was NOT overwritten.
		found, err = FindNode(node, "metadata.labels.app")
		require.NoError(t, err)
		require.NotNil(t, found)
		assert.Equal(t, "web", found.Value)
	})

	t.Run("merge into list", func(t *testing.T) {
		input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx
`
		node, err := ParseYAML([]byte(input))
		require.NoError(t, err)

		// Merge (append) a list item.
		newContainer := map[string]any{
			"name":  "sidecar",
			"image": "envoy",
		}
		err = MergeNode(node, "spec.containers", []any{newContainer})
		require.NoError(t, err)

		// Verify we now have 2 containers.
		containers, err := FindNode(node, "spec.containers")
		require.NoError(t, err)
		require.NotNil(t, containers)
		assert.Equal(t, yaml.SequenceNode, containers.Kind)
		assert.Len(t, containers.Content, 2)
	})
}

func TestMultiDocModifyOne(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: first
---
apiVersion: v1
kind: Pod
metadata:
  name: second
---
apiVersion: v1
kind: Pod
metadata:
  name: third
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 3)

	// Modify only the second document.
	err = SetNode(docs[1].Node, "metadata.name", "modified-second")
	require.NoError(t, err)
	docs[1].Modified = true

	output, err := SerializeDocuments(docs)
	require.NoError(t, err)
	outputStr := string(output)

	// The first document should be byte-for-byte identical (raw).
	assert.Contains(t, outputStr, "name: first")
	// The second document should be modified.
	assert.Contains(t, outputStr, "name: modified-second")
	// The third document should be byte-for-byte identical (raw).
	assert.Contains(t, outputStr, "name: third")

	// Verify structure: should have two --- separators.
	separatorCount := strings.Count(outputStr, "---")
	assert.Equal(t, 2, separatorCount)

	// Verify the first and third documents are truly unmodified.
	// Split on --- and check.
	parts := strings.SplitN(outputStr, "---\n", 3)
	require.Len(t, parts, 3)

	firstRaw := `apiVersion: v1
kind: Pod
metadata:
  name: first
`
	assert.Equal(t, firstRaw, parts[0], "first document should be verbatim")

	thirdRaw := `apiVersion: v1
kind: Pod
metadata:
  name: third
`
	assert.Equal(t, thirdRaw, parts[2], "third document should be verbatim")
}

func TestEmptyDocument(t *testing.T) {
	// Empty input.
	docs, err := ParseDocuments([]byte(""))
	require.NoError(t, err)
	assert.Nil(t, docs)

	// Serialize empty docs.
	output, err := SerializeDocuments(nil)
	require.NoError(t, err)
	assert.Nil(t, output)
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantSegs []pathSegment
		wantErr  bool
	}{
		{
			name: "simple key",
			path: "apiVersion",
			wantSegs: []pathSegment{
				{Key: "apiVersion", Index: -1},
			},
		},
		{
			name: "nested keys",
			path: "metadata.name",
			wantSegs: []pathSegment{
				{Key: "metadata", Index: -1},
				{Key: "name", Index: -1},
			},
		},
		{
			name: "key with array index",
			path: "spec.containers[0].name",
			wantSegs: []pathSegment{
				{Key: "spec", Index: -1},
				{Key: "containers", Index: -1},
				{Index: 0},
				{Key: "name", Index: -1},
			},
		},
		{
			name: "key with wildcard",
			path: "spec.containers[*].securityContext",
			wantSegs: []pathSegment{
				{Key: "spec", Index: -1},
				{Key: "containers", Index: -1},
				{Wildcard: true, Index: -1},
				{Key: "securityContext", Index: -1},
			},
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segs, err := parsePath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSegs, segs)
		})
	}
}

func TestValueToNode(t *testing.T) {
	tests := []struct {
		name      string
		value     any
		wantKind  yaml.Kind
		wantTag   string
		wantValue string
	}{
		{
			name:      "bool true",
			value:     true,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!bool",
			wantValue: "true",
		},
		{
			name:      "bool false",
			value:     false,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!bool",
			wantValue: "false",
		},
		{
			name:      "int",
			value:     42,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!int",
			wantValue: "42",
		},
		{
			name:      "string",
			value:     "hello",
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!str",
			wantValue: "hello",
		},
		{
			name:     "nil",
			value:    nil,
			wantKind: yaml.ScalarNode,
			wantTag:  "!!null",
		},
		{
			name:     "string slice",
			value:    []string{"ALL"},
			wantKind: yaml.SequenceNode,
			wantTag:  "!!seq",
		},
		{
			name:     "map",
			value:    map[string]any{"key": "val"},
			wantKind: yaml.MappingNode,
			wantTag:  "!!map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := valueToNode(tt.value)
			require.NotNil(t, node)
			assert.Equal(t, tt.wantKind, node.Kind)
			assert.Equal(t, tt.wantTag, node.Tag)
			if tt.wantValue != "" {
				assert.Equal(t, tt.wantValue, node.Value)
			}
		})
	}
}

func TestSetNodeSecurityContext(t *testing.T) {
	// Realistic test: set privileged: false in a Deployment.
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  # This is a comment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true  # DANGER
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = SetNode(node, "spec.template.spec.containers[0].securityContext.privileged", false)
	require.NoError(t, err)

	found, err := FindNode(node, "spec.template.spec.containers[0].securityContext.privileged")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "false", found.Value)
	assert.Equal(t, "!!bool", found.Tag)

	// Serialize and verify.
	serialized, err := SerializeNode(node)
	require.NoError(t, err)
	output := string(serialized)
	assert.Contains(t, output, "privileged: false")
	assert.NotContains(t, output, "privileged: true")
	// The comment should be preserved.
	assert.Contains(t, output, "# DANGER")
	// The metadata comment should be preserved.
	assert.Contains(t, output, "# This is a comment")
}

func TestFindNodes(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: first
    image: nginx
  - name: second
    image: alpine
  - name: third
    image: busybox
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Wildcard: find all container names.
	nodes, err := FindNodes(node, "spec.containers[*].name")
	require.NoError(t, err)
	require.Len(t, nodes, 3)
	assert.Equal(t, "first", nodes[0].Value)
	assert.Equal(t, "second", nodes[1].Value)
	assert.Equal(t, "third", nodes[2].Value)
}

func TestSetNodeNewFieldInExistingMap(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: true
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Add a new field to an existing securityContext.
	err = SetNode(node, "spec.containers[0].securityContext.privileged", false)
	require.NoError(t, err)

	found, err := FindNode(node, "spec.containers[0].securityContext.privileged")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "false", found.Value)

	// Existing field still there.
	found, err = FindNode(node, "spec.containers[0].securityContext.allowPrivilegeEscalation")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "true", found.Value)
}

func TestRemoveNodeFromSequence(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: first
  - name: second
  - name: third
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Remove the second container (index 1).
	err = RemoveNode(node, "spec.containers[1]")
	require.NoError(t, err)

	// Verify we now have 2 containers.
	containers, err := FindNode(node, "spec.containers")
	require.NoError(t, err)
	require.NotNil(t, containers)
	assert.Len(t, containers.Content, 2)

	// First is still "first".
	found, err := FindNode(node, "spec.containers[0].name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "first", found.Value)

	// Second is now "third" (was at index 2).
	found, err = FindNode(node, "spec.containers[1].name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "third", found.Value)
}

func TestSetNodeWithStringSlice(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      capabilities:
        add:
        - NET_ADMIN
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Replace capabilities.drop with a list.
	err = SetNode(node, "spec.containers[0].securityContext.capabilities.drop", []string{"ALL"})
	require.NoError(t, err)

	found, err := FindNode(node, "spec.containers[0].securityContext.capabilities.drop")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, yaml.SequenceNode, found.Kind)
	require.Len(t, found.Content, 1)
	assert.Equal(t, "ALL", found.Content[0].Value)

	// Original 'add' is still there.
	found, err = FindNode(node, "spec.containers[0].securityContext.capabilities.add")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, yaml.SequenceNode, found.Kind)
}

func TestDetectIndent(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantIndent int
	}{
		{
			name: "2-space indent",
			input: `apiVersion: v1
metadata:
  name: test
`,
			wantIndent: 2,
		},
		{
			name: "4-space indent",
			input: `apiVersion: v1
metadata:
    name: test
`,
			wantIndent: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseYAML([]byte(tt.input))
			require.NoError(t, err)
			got := detectIndent(node)
			assert.Equal(t, tt.wantIndent, got)
		})
	}
}

func TestSetNodeOnNilRoot(t *testing.T) {
	var node yaml.Node
	node.Kind = yaml.DocumentNode
	err := SetNode(&node, "spec.foo", "bar")
	require.Error(t, err)
}

func TestMergeNodeNotFound(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = MergeNode(node, "spec.nonexistent", map[string]any{"key": "val"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMultiDocRoundTripNoModification(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: first
---
apiVersion: v1
kind: Service
metadata:
  name: second
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 2)

	// No modifications: output should exactly match input.
	output, err := SerializeDocuments(docs)
	require.NoError(t, err)
	assert.Equal(t, input, string(output))
}

func TestSetNodeCreatesSecurityContext(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Create securityContext.runAsNonRoot on a container that has none.
	err = SetNode(node, "spec.containers[0].securityContext.runAsNonRoot", true)
	require.NoError(t, err)

	found, err := FindNode(node, "spec.containers[0].securityContext.runAsNonRoot")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "true", found.Value)

	// Verify it serializes correctly.
	serialized, err := SerializeNode(node)
	require.NoError(t, err)
	assert.Contains(t, string(serialized), "runAsNonRoot: true")
}

func TestAddNodeCreatesIntermediates(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Add a deeply nested field where intermediates don't exist.
	err = AddNode(node, "spec.securityContext.runAsNonRoot", true)
	require.NoError(t, err)

	found, err := FindNode(node, "spec.securityContext.runAsNonRoot")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "true", found.Value)
}

func TestSerializeDocumentsEmpty(t *testing.T) {
	output, err := SerializeDocuments([]*Document{})
	require.NoError(t, err)
	assert.Nil(t, output)
}

func TestRoundTripModifiedDocument(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
  labels:
    app: web
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 1)

	// Modify the document.
	err = SetNode(docs[0].Node, "spec.containers[0].securityContext.privileged", false)
	require.NoError(t, err)
	docs[0].Modified = true

	output, err := SerializeDocuments(docs)
	require.NoError(t, err)

	// The modified document should have privileged: false.
	outputStr := string(output)
	assert.Contains(t, outputStr, "privileged: false")
	assert.NotContains(t, outputStr, "privileged: true")

	// Key order should be preserved (apiVersion, kind, metadata, spec).
	apiIdx := strings.Index(outputStr, "apiVersion:")
	kindIdx := strings.Index(outputStr, "kind:")
	metaIdx := strings.Index(outputStr, "metadata:")
	specIdx := strings.Index(outputStr, "spec:")
	assert.Less(t, apiIdx, kindIdx)
	assert.Less(t, kindIdx, metaIdx)
	assert.Less(t, metaIdx, specIdx)
}

// --- navigateExisting tests ---

func TestNavigateExisting_SequenceIndex(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: first
  - name: second
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	content := contentNode(node)
	require.NotNil(t, content)

	// Navigate to spec.
	specNode := navigateExisting(content, pathSegment{Key: "spec", Index: -1})
	require.NotNil(t, specNode)

	// Navigate to containers.
	containersNode := navigateExisting(specNode, pathSegment{Key: "containers", Index: -1})
	require.NotNil(t, containersNode)
	assert.Equal(t, yaml.SequenceNode, containersNode.Kind)

	// Navigate through sequence index 0.
	first := navigateExisting(containersNode, pathSegment{Index: 0})
	require.NotNil(t, first)
	assert.Equal(t, yaml.MappingNode, first.Kind)

	// Navigate through sequence index 1.
	second := navigateExisting(containersNode, pathSegment{Index: 1})
	require.NotNil(t, second)
	assert.Equal(t, yaml.MappingNode, second.Kind)

	// Out of bounds returns nil.
	oob := navigateExisting(containersNode, pathSegment{Index: 5})
	assert.Nil(t, oob)
}

func TestNavigateExisting_KeyNotFound(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	content := contentNode(node)
	require.NotNil(t, content)

	result := navigateExisting(content, pathSegment{Key: "nonexistent", Index: -1})
	assert.Nil(t, result)
}

func TestNavigateExisting_EmptyKey(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	content := contentNode(node)
	require.NotNil(t, content)

	result := navigateExisting(content, pathSegment{Key: "", Index: -1})
	assert.Nil(t, result)
}

func TestNavigateExisting_NonMappingWithKey(t *testing.T) {
	// Create a sequence node and try navigating with a key.
	seqNode := &yaml.Node{
		Kind: yaml.SequenceNode,
		Tag:  "!!seq",
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "item1"},
		},
	}

	result := navigateExisting(seqNode, pathSegment{Key: "somekey", Index: -1})
	assert.Nil(t, result)
}

// --- SetNode/setNodeAt additional branch tests ---

func TestSetNode_SequenceIndex(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: first
  - name: second
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Set a value at a specific sequence index.
	err = SetNode(node, "spec.containers[1].name", "replaced")
	require.NoError(t, err)

	found, err := FindNode(node, "spec.containers[1].name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "replaced", found.Value)

	// Index 0 should be untouched.
	found, err = FindNode(node, "spec.containers[0].name")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "first", found.Value)
}

func TestSetNode_IndexOutOfBounds(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: only
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = SetNode(node, "spec.containers[5].name", "nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of bounds")
}

func TestSetNode_EmptyKeyInFinalSegment(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// parsePath won't normally produce an empty key, but let's test setNodeAt directly.
	content := contentNode(node)
	require.NotNil(t, content)

	segments := []pathSegment{
		{Key: "metadata", Index: -1},
		{Key: "", Index: -1}, // empty key in final segment
	}
	err = setNodeAt(content, segments, "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty key")
}

// --- navigatePathMulti additional branch tests ---

func TestNavigatePathMulti_SpecificArrayIndex(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: first
    image: nginx
  - name: second
    image: alpine
  - name: third
    image: busybox
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Find a specific index (not wildcard).
	nodes, err := FindNodes(node, "spec.containers[1].name")
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "second", nodes[0].Value)
}

func TestNavigatePathMulti_NonSequenceWithIndex(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// metadata is a mapping, not a sequence. Using an index should skip it.
	nodes, err := FindNodes(node, "metadata[0].name")
	require.NoError(t, err)
	assert.Nil(t, nodes)
}

func TestNavigatePathMulti_NonMappingWithKey(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: first
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// containers[0] is a mapping, but containers itself is a sequence.
	// Trying to use a key on a sequence should skip.
	nodes, err := FindNodes(node, "spec.containers.name")
	require.NoError(t, err)
	assert.Nil(t, nodes)
}

// TestQuotingStylePreserved verifies that YAML quoting styles on unmodified
// fields are preserved through a round-trip that modifies a different field.
// This is the acceptance test for KubeVigil-a17x.
func TestQuotingStylePreserved(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: "quoted-name"
  labels:
    app: 'single-quoted'
    version: unquoted
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: web
        image: nginx:latest
        securityContext:
          privileged: true
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 1)

	// Modify a field deep in the spec — securityContext.privileged.
	err = SetNode(docs[0].Node, "spec.template.spec.containers[0].securityContext.privileged", false)
	require.NoError(t, err)
	docs[0].Modified = true

	out, err := SerializeDocuments(docs)
	require.NoError(t, err)
	result := string(out)

	// The fix should have been applied.
	assert.Contains(t, result, "privileged: false")

	// Quoting styles on UNMODIFIED fields must be preserved.
	assert.Contains(t, result, `"quoted-name"`, "double-quoted metadata.name should be preserved")
	assert.Contains(t, result, "'single-quoted'", "single-quoted label value should be preserved")
	assert.Contains(t, result, "version: unquoted", "unquoted label value should stay unquoted")
}

func TestSetNode_EmptyPath(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)
	err = SetNode(node, "", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty path")
}

func TestSetNode_NilRoot(t *testing.T) {
	err := SetNode(nil, "key", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil root")
}

func TestSetNode_CreateNewKey(t *testing.T) {
	node, err := ParseYAML([]byte("existing: value"))
	require.NoError(t, err)
	err = SetNode(node, "newKey", "newValue")
	require.NoError(t, err)

	result, err := SerializeNode(node)
	require.NoError(t, err)
	assert.Contains(t, string(result), "newKey: newValue")
	assert.Contains(t, string(result), "existing: value")
}

func TestSetNode_NonMappingForKey(t *testing.T) {
	// Create a scalar node and try to set a key on it.
	node := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "hello", Tag: "!!str"},
	}}
	err := SetNode(node, "key", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected mapping node")
}

func TestFindNode_WildcardError(t *testing.T) {
	input := `
items:
  - name: a
  - name: b
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)
	_, err = FindNode(node, "items[*].name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard")
}

func TestFindNode_NilRoot(t *testing.T) {
	result, err := FindNode(nil, "key")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestFindNodes_NilRoot(t *testing.T) {
	result, err := FindNodes(nil, "key")
	require.NoError(t, err)
	assert.Nil(t, result)
}

// --- Additional edge case tests for coverage ---

func TestSetNodeAt_DeepNestedPathCreation(t *testing.T) {
	// Test creating deeply nested intermediate nodes that don't exist yet.
	input := `apiVersion: v1
kind: Pod
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Create a deeply nested path: spec.template.spec.securityContext.runAsNonRoot
	err = SetNode(node, "spec.template.spec.securityContext.runAsNonRoot", true)
	require.NoError(t, err)

	found, err := FindNode(node, "spec.template.spec.securityContext.runAsNonRoot")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "true", found.Value)
}

func TestSetNodeAt_IntermediateIsScalar(t *testing.T) {
	// Test where intermediate path is a scalar (error case).
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// metadata.name is a scalar; trying to navigate deeper should error.
	err = SetNode(node, "metadata.name.nested.deep", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected mapping node")
}

func TestSetNodeAt_SetSequenceIndexDirectly(t *testing.T) {
	// Test setting value at a direct sequence index as the final segment.
	input := `items:
- first
- second
- third
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Set items[1] to "replaced"
	err = SetNode(node, "items[1]", "replaced")
	require.NoError(t, err)

	found, err := FindNode(node, "items[1]")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "replaced", found.Value)

	// Verify items[0] untouched.
	found, err = FindNode(node, "items[0]")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "first", found.Value)
}

func TestSetNodeAt_SequenceIndexOutOfBoundsOnFinalSegment(t *testing.T) {
	// Setting at a final sequence index that's out of bounds.
	input := `items:
- only
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = SetNode(node, "items[5]", "nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of bounds")
}

func TestSetNodeAt_FinalSegmentOnNonSequence(t *testing.T) {
	// Setting a sequence index where the node is a mapping.
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)

	content := contentNode(node)
	require.NotNil(t, content)

	segments := []pathSegment{
		{Index: 0}, // sequence index on a mapping node
	}
	err = setNodeAt(content, segments, "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected sequence node")
}

func TestSetNodeAt_PreservesCommentsOnSequenceReplace(t *testing.T) {
	input := `items:
- first  # important item
- second
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = SetNode(node, "items[0]", "replaced")
	require.NoError(t, err)

	found, err := FindNode(node, "items[0]")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "replaced", found.Value)
	assert.Equal(t, "# important item", found.LineComment)
}

func TestAddNode_EmptyDocument(t *testing.T) {
	// Add to an empty mapping.
	input := `{}`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = AddNode(node, "newKey", "newValue")
	require.NoError(t, err)

	found, err := FindNode(node, "newKey")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "newValue", found.Value)
}

func TestAddNode_NilRootNode(t *testing.T) {
	// A nil pointer to AddNode triggers the "nil root" error.
	err := AddNode(nil, "key", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil root")
}

func TestAddNode_EmptyDocumentNode(t *testing.T) {
	// An empty DocumentNode (no content) has contentNode return itself (kind 1),
	// which is not a mapping, so we get "expected mapping" error.
	var node yaml.Node
	node.Kind = yaml.DocumentNode
	err := AddNode(&node, "key", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected mapping node")
}

func TestAddNode_EmptyPathError(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)
	err = AddNode(node, "", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty path")
}

func TestAddNode_NonMappingParent(t *testing.T) {
	// Trying to add a key where the parent is a scalar.
	input := `key: scalarvalue`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// key is a scalar, so key.newfield should fail.
	err = AddNode(node, "key.newfield", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected mapping node")
}

func TestAddNode_IndexBasedFinalSegment(t *testing.T) {
	// AddNode requires a key-based final segment. Index should fail.
	input := `items:
- first
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = AddNode(node, "items[0]", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key-based final path segment")
}

func TestRemoveNode_EmptyPath(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)
	err = RemoveNode(node, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty path")
}

func TestRemoveNode_NilRoot(t *testing.T) {
	err := RemoveNode(nil, "key")
	require.NoError(t, err)
}

func TestRemoveNode_SequenceIndexOutOfBounds(t *testing.T) {
	// Removing from a sequence at an out-of-bounds index should be no-op.
	input := `items:
- first
- second
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = RemoveNode(node, "items[10]")
	require.NoError(t, err)

	// Items should still have 2 elements.
	items, err := FindNode(node, "items")
	require.NoError(t, err)
	require.NotNil(t, items)
	assert.Len(t, items.Content, 2)
}

func TestRemoveNode_NonSequenceForIndex(t *testing.T) {
	// Removing a sequence index from a mapping should be no-op.
	input := `metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = RemoveNode(node, "metadata[0]")
	require.NoError(t, err)
}

func TestRemoveNode_EmptyKeyInFinalSegment(t *testing.T) {
	// Directly test with an empty key segment — should be no-op.
	input := `key: value`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// RemoveNode navigates to parent, then checks final segment.
	err = RemoveNode(node, "key")
	require.NoError(t, err)

	// The key should be gone.
	found, err := FindNode(node, "key")
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestRemoveNode_NonMappingForKey(t *testing.T) {
	// Removing a key from a sequence node should be no-op.
	input := `items:
- first
- second
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// items is a sequence, not a mapping. Trying "items.nonexistent" should navigate
	// into items (a sequence) and fail silently because items is not a mapping.
	err = RemoveNode(node, "items.nonexistent")
	require.NoError(t, err)
}

func TestRemoveNode_LastKeyInMapping(t *testing.T) {
	input := `metadata:
  name: only-key
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = RemoveNode(node, "metadata.name")
	require.NoError(t, err)

	found, err := FindNode(node, "metadata.name")
	require.NoError(t, err)
	assert.Nil(t, found)

	// metadata should still exist as a mapping (now empty).
	meta, err := FindNode(node, "metadata")
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, yaml.MappingNode, meta.Kind)
	assert.Len(t, meta.Content, 0)
}

func TestMergeNode_EmptyPath(t *testing.T) {
	// Merging at the root level (empty segments after parse).
	input := `key1: val1`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = MergeNode(node, "key1", map[string]any{"nested": "val"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot merge")
}

func TestMergeNode_NilRoot(t *testing.T) {
	// A nil pointer triggers "nil root" error.
	err := MergeNode(nil, "key", map[string]any{"a": "b"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil root")
}

func TestMergeNode_EmptyDocumentNode(t *testing.T) {
	// Empty DocumentNode: contentNode returns itself, navigation fails.
	var node yaml.Node
	node.Kind = yaml.DocumentNode
	err := MergeNode(&node, "key", map[string]any{"a": "b"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMergeNode_ParseError(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)
	err = MergeNode(node, "", map[string]any{"a": "b"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty path")
}

func TestMergeNode_IntoScalar(t *testing.T) {
	input := `key: scalarvalue`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = MergeNode(node, "key", map[string]any{"nested": "val"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot merge into node of kind")
}

func TestMergeNode_MapIntoScalar(t *testing.T) {
	input := `metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// metadata.name is a scalar; merging a map into it should fail.
	err = MergeNode(node, "metadata.name", map[string]any{"key": "val"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot merge")
}

func TestMergeNode_NonMappingValueIntoMapping(t *testing.T) {
	input := `metadata:
  labels:
    app: web
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Merging a string value into a mapping should error.
	err = MergeNode(node, "metadata.labels", "not-a-map")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot merge non-mapping value into mapping node")
}

func TestMergeNode_SingleItemIntoSequence(t *testing.T) {
	input := `items:
- first
- second
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Merge a single non-sequence item into a sequence (should append).
	err = MergeNode(node, "items", "third")
	require.NoError(t, err)

	items, err := FindNode(node, "items")
	require.NoError(t, err)
	require.NotNil(t, items)
	assert.Len(t, items.Content, 3)
	assert.Equal(t, "third", items.Content[2].Value)
}

func TestMergeNode_OverlappingKeys(t *testing.T) {
	input := `metadata:
  labels:
    app: existing
    tier: frontend
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = MergeNode(node, "metadata.labels", map[string]any{
		"app": "should-not-overwrite",
		"new": "added",
	})
	require.NoError(t, err)

	// Existing "app" should NOT be overwritten.
	found, err := FindNode(node, "metadata.labels.app")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "existing", found.Value)

	// New key should be added.
	found, err = FindNode(node, "metadata.labels.new")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "added", found.Value)
}

func TestValueToNode_AllTypes(t *testing.T) {
	tests := []struct {
		name      string
		value     any
		wantKind  yaml.Kind
		wantTag   string
		wantValue string
	}{
		{
			name:      "bool true",
			value:     true,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!bool",
			wantValue: "true",
		},
		{
			name:      "bool false",
			value:     false,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!bool",
			wantValue: "false",
		},
		{
			name:      "int zero",
			value:     0,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!int",
			wantValue: "0",
		},
		{
			name:      "int positive",
			value:     42,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!int",
			wantValue: "42",
		},
		{
			name:      "int negative",
			value:     -7,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!int",
			wantValue: "-7",
		},
		{
			name:      "int64",
			value:     int64(9999999999),
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!int",
			wantValue: "9999999999",
		},
		{
			name:      "float64",
			value:     3.14,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!float",
			wantValue: "3.14",
		},
		{
			name:      "float64 integer value",
			value:     1.0,
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!float",
			wantValue: "1",
		},
		{
			name:      "string",
			value:     "hello world",
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!str",
			wantValue: "hello world",
		},
		{
			name:      "empty string",
			value:     "",
			wantKind:  yaml.ScalarNode,
			wantTag:   "!!str",
			wantValue: "",
		},
		{
			name:     "nil",
			value:    nil,
			wantKind: yaml.ScalarNode,
			wantTag:  "!!null",
		},
		{
			name:     "string slice",
			value:    []string{"ALL", "NET_RAW"},
			wantKind: yaml.SequenceNode,
			wantTag:  "!!seq",
		},
		{
			name:     "empty string slice",
			value:    []string{},
			wantKind: yaml.SequenceNode,
			wantTag:  "!!seq",
		},
		{
			name:     "any slice",
			value:    []any{"one", 2, true},
			wantKind: yaml.SequenceNode,
			wantTag:  "!!seq",
		},
		{
			name:     "map string any",
			value:    map[string]any{"key": "val", "num": 42},
			wantKind: yaml.MappingNode,
			wantTag:  "!!map",
		},
		{
			name:     "empty map",
			value:    map[string]any{},
			wantKind: yaml.MappingNode,
			wantTag:  "!!map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := valueToNode(tt.value)
			require.NotNil(t, node)
			assert.Equal(t, tt.wantKind, node.Kind, "wrong Kind")
			assert.Equal(t, tt.wantTag, node.Tag, "wrong Tag")
			if tt.wantValue != "" {
				assert.Equal(t, tt.wantValue, node.Value, "wrong Value")
			}
		})
	}
}

func TestValueToNode_YamlNodePointer(t *testing.T) {
	original := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: "original",
	}
	result := valueToNode(original)
	assert.Equal(t, original, result, "should return the same *yaml.Node pointer")
}

func TestValueToNode_YamlNodeValue(t *testing.T) {
	original := yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: "value-type",
	}
	result := valueToNode(original)
	assert.Equal(t, yaml.ScalarNode, result.Kind)
	assert.Equal(t, "value-type", result.Value)
}

func TestValueToNode_FallbackType(t *testing.T) {
	// Use a type that doesn't match any explicit case — e.g., map[string]string.
	// This should use the fallback marshal/unmarshal path.
	input := map[string]string{"cpu": "500m", "memory": "256Mi"}
	result := valueToNode(input)
	require.NotNil(t, result)
	// map[string]string goes through marshal/unmarshal fallback and becomes a MappingNode.
	assert.Equal(t, yaml.MappingNode, result.Kind)
}

func TestValueToNode_NestedStructure(t *testing.T) {
	// Nested: map containing slice containing map.
	value := map[string]any{
		"containers": []any{
			map[string]any{
				"name":  "web",
				"image": "nginx",
			},
		},
	}
	result := valueToNode(value)
	require.NotNil(t, result)
	assert.Equal(t, yaml.MappingNode, result.Kind)
	// Should have "containers" key.
	require.True(t, len(result.Content) >= 2, "should have at least one key-value pair")
}

func TestSerializeNode_NilNode(t *testing.T) {
	// SerializeNode with a nil node — yaml encoder handles nil gracefully
	// by encoding "null".
	result, err := SerializeNode(nil)
	require.NoError(t, err)
	assert.Contains(t, string(result), "null")
}

func TestSerializeNode_EmptyDocumentNode(t *testing.T) {
	// An empty document node (no content) causes an encode error.
	node := &yaml.Node{
		Kind: yaml.DocumentNode,
	}
	_, err := SerializeNode(node)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encoding YAML")
}

func TestSerializeNode_WithComments(t *testing.T) {
	input := `# Top comment
apiVersion: v1
kind: Pod # inline comment
metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	serialized, err := SerializeNode(node)
	require.NoError(t, err)

	output := string(serialized)
	assert.Contains(t, output, "# Top comment")
	assert.Contains(t, output, "# inline comment")
}

func TestDetectIndent_NilNode(t *testing.T) {
	got := detectIndent(nil)
	assert.Equal(t, 2, got, "nil node should default to indent 2")
}

func TestDetectIndent_FlatDocument(t *testing.T) {
	// A document with no nested mappings — should default to 2.
	input := `key1: value1
key2: value2
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)
	got := detectIndent(node)
	assert.Equal(t, 2, got, "flat document with no nesting should default to 2")
}

func TestParsePath_UnclosedBracket(t *testing.T) {
	_, err := parsePath("items[0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unclosed bracket")
}

func TestParsePath_InvalidIndex(t *testing.T) {
	_, err := parsePath("items[abc]")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid array index")
}

func TestFindNode_EmptyPathError(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)

	_, err = FindNode(node, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty path")
}

func TestFindNodes_EmptyPathError(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)

	_, err = FindNodes(node, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty path")
}

func TestNavigatePathMulti_WildcardOnNonSequence(t *testing.T) {
	input := `metadata:
  name: test
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// metadata is a mapping; wildcard should skip it.
	nodes, err := FindNodes(node, "metadata[*].name")
	require.NoError(t, err)
	assert.Nil(t, nodes)
}

func TestNavigateOrCreate_SequenceIndexOutOfBounds(t *testing.T) {
	seqNode := &yaml.Node{
		Kind: yaml.SequenceNode,
		Tag:  "!!seq",
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "only"},
		},
	}

	_, err := navigateOrCreate(seqNode, pathSegment{Index: 5})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of bounds")
}

func TestNavigateOrCreate_NonSequenceForIndex(t *testing.T) {
	mapNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}

	_, err := navigateOrCreate(mapNode, pathSegment{Index: 0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected sequence node")
}

func TestNavigateOrCreate_EmptyKey(t *testing.T) {
	mapNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}

	_, err := navigateOrCreate(mapNode, pathSegment{Key: "", Index: -1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty key")
}

func TestNavigateOrCreate_NonMappingForKey(t *testing.T) {
	scalarNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "hello",
	}

	_, err := navigateOrCreate(scalarNode, pathSegment{Key: "sub", Index: -1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected mapping node")
}

func TestNavigateExisting_SequenceIndexOnNonSequence(t *testing.T) {
	scalarNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "hello",
	}

	result := navigateExisting(scalarNode, pathSegment{Index: 0})
	assert.Nil(t, result)
}

func TestParseDocuments_EmptyDocBetweenSeparators(t *testing.T) {
	// Two separators with content before and after.
	input := `apiVersion: v1
kind: Pod
metadata:
  name: first
---
apiVersion: v1
kind: Service
metadata:
  name: second
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	assert.Len(t, docs, 2)
}

func TestSerializeDocuments_ModifiedDocWithSerializeError(t *testing.T) {
	// Create a document that's marked modified but has a node that should serialize okay.
	doc := &Document{
		Node:     &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}},
		Modified: true,
	}

	output, err := SerializeDocuments([]*Document{doc})
	require.NoError(t, err)
	assert.NotNil(t, output)
}

func TestContentNode_NilInput(t *testing.T) {
	result := contentNode(nil)
	assert.Nil(t, result)
}

func TestContentNode_NonDocumentNode(t *testing.T) {
	mapNode := &yaml.Node{Kind: yaml.MappingNode}
	result := contentNode(mapNode)
	assert.Equal(t, mapNode, result, "non-document node should be returned as-is")
}

func TestContentNode_EmptyDocumentNode(t *testing.T) {
	docNode := &yaml.Node{Kind: yaml.DocumentNode}
	result := contentNode(docNode)
	assert.Equal(t, docNode, result, "empty document node has no content, should return self")
}

func TestSetNode_OverwriteExistingWithDifferentType(t *testing.T) {
	input := `metadata:
  count: 42
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Overwrite an int with a string.
	err = SetNode(node, "metadata.count", "not-a-number")
	require.NoError(t, err)

	found, err := FindNode(node, "metadata.count")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "not-a-number", found.Value)
	assert.Equal(t, "!!str", found.Tag)
}

func TestSetNode_OverwriteScalarWithMap(t *testing.T) {
	input := `metadata:
  labels: none
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Overwrite a scalar with a map.
	err = SetNode(node, "metadata.labels", map[string]any{"app": "web"})
	require.NoError(t, err)

	found, err := FindNode(node, "metadata.labels.app")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "web", found.Value)
}

func TestMergeNode_EmptySegments(t *testing.T) {
	// When path has no segments (after parsePath) but is valid, it should merge at root.
	// Actually, parsePath("") returns an error. Let's test a valid root-level merge by
	// using a top-level key path.
	input := `labels:
  app: web
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// Merge into the top-level labels map.
	err = MergeNode(node, "labels", map[string]any{"tier": "frontend"})
	require.NoError(t, err)

	found, err := FindNode(node, "labels.tier")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "frontend", found.Value)
}

func TestSplitDocuments_OnlySeparator(t *testing.T) {
	// Just "---" with nothing else.
	docs := splitDocuments([]byte("---"))
	assert.NotEmpty(t, docs)
}

func TestSplitDocuments_MultipleSeparators(t *testing.T) {
	input := `---
kind: Pod
---
kind: Service
---
kind: ConfigMap
`
	docs := splitDocuments([]byte(input))
	assert.Len(t, docs, 3)
}

func TestParseDocuments_EmptyDocumentBetweenSeparators(t *testing.T) {
	// Content with an empty document between two real documents.
	input := `kind: Pod
---
---
kind: Service
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	// Should have 3 docs: Pod, empty, Service.
	assert.GreaterOrEqual(t, len(docs), 2)
}

func TestSerializeDocuments_ErrorOnModifiedDoc(t *testing.T) {
	// A modified document with an empty DocumentNode (no content) will fail to serialize.
	doc := &Document{
		Node:     &yaml.Node{Kind: yaml.DocumentNode}, // no content
		Modified: true,
	}
	_, err := SerializeDocuments([]*Document{doc})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "serializing document")
}

func TestSerializeDocuments_MixedModifiedUnmodified(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: first
`
	docs, err := ParseDocuments([]byte(input))
	require.NoError(t, err)
	require.Len(t, docs, 1)

	// Add a second modified document.
	secondNode, err := ParseYAML([]byte(`apiVersion: v1
kind: Service
metadata:
  name: second
`))
	require.NoError(t, err)

	docs = append(docs, &Document{
		Node:     secondNode,
		Modified: true,
	})

	output, err := SerializeDocuments(docs)
	require.NoError(t, err)
	result := string(output)
	assert.Contains(t, result, "name: first")
	assert.Contains(t, result, "name: second")
	assert.Contains(t, result, "---")
}

func TestSetNode_EmptyPathSegments(t *testing.T) {
	// SetNode with an empty path should fail.
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)

	err = SetNode(node, "", "new")
	require.Error(t, err)
}

func TestAddNode_DeeplyNestedNewKey(t *testing.T) {
	// Add a deeply nested key where all intermediates must be created.
	input := `apiVersion: v1`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = AddNode(node, "spec.template.spec.securityContext.runAsUser", 1000)
	require.NoError(t, err)

	found, err := FindNode(node, "spec.template.spec.securityContext.runAsUser")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "1000", found.Value)
}

func TestRemoveNode_SequenceIndexValid(t *testing.T) {
	// Remove first element from a 3-element sequence.
	input := `items:
- alpha
- beta
- gamma
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = RemoveNode(node, "items[0]")
	require.NoError(t, err)

	items, err := FindNode(node, "items")
	require.NoError(t, err)
	require.NotNil(t, items)
	assert.Len(t, items.Content, 2)
	assert.Equal(t, "beta", items.Content[0].Value)
	assert.Equal(t, "gamma", items.Content[1].Value)
}

func TestValueToNode_FallbackMarshalUnmarshalError(t *testing.T) {
	// Use a custom struct that yaml can marshal.
	type customStruct struct {
		Name  string `yaml:"name"`
		Count int    `yaml:"count"`
	}
	result := valueToNode(customStruct{Name: "test", Count: 5})
	require.NotNil(t, result)
	assert.Equal(t, yaml.MappingNode, result.Kind)
}

func TestNavigatePath_NilCurrentNode(t *testing.T) {
	result, err := navigatePath(nil, []pathSegment{{Key: "test", Index: -1}})
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestNavigatePathMulti_NilNodeInSlice(t *testing.T) {
	// navigatePathMulti with nil nodes in the slice should skip them.
	result, err := navigatePathMulti([]*yaml.Node{nil}, []pathSegment{{Key: "test", Index: -1}})
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestParseDocuments_ExceedsMaxDocumentCount(t *testing.T) {
	// Build a YAML file with more than maxDocumentCount documents.
	var b strings.Builder
	for i := 0; i <= maxDocumentCount; i++ {
		b.WriteString("---\nkind: Pod\n")
	}

	_, err := ParseDocuments([]byte(b.String()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeding maximum")
}

func TestParseDocuments_AtMaxDocumentCount(t *testing.T) {
	// Build a YAML file with exactly maxDocumentCount documents — should succeed.
	// Use a small count to keep the test fast.
	var b strings.Builder
	for i := 0; i < 100; i++ {
		if i > 0 {
			b.WriteString("---\n")
		}
		b.WriteString("kind: Pod\n")
	}

	docs, err := ParseDocuments([]byte(b.String()))
	require.NoError(t, err)
	assert.Len(t, docs, 100)
}

// --- parsePath: direct coverage of the "skip empty path segment" branch ---
// (leading/doubled/trailing dots produce empty parts between separators).

func TestParsePath_SkipsEmptySegments(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantSegs []pathSegment
	}{
		{
			name: "leading dot",
			path: ".spec.hostPID",
			wantSegs: []pathSegment{
				{Key: "spec", Index: -1},
				{Key: "hostPID", Index: -1},
			},
		},
		{
			name: "doubled dot mid-path",
			path: "spec..hostPID",
			wantSegs: []pathSegment{
				{Key: "spec", Index: -1},
				{Key: "hostPID", Index: -1},
			},
		},
		{
			name:     "all-dots path yields zero segments",
			path:     "...",
			wantSegs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segs, err := parsePath(tt.path)
			require.NoError(t, err, "empty segments between separators must not be an error")
			assert.Equal(t, tt.wantSegs, segs)
		})
	}
}

// --- SetNode/AddNode/RemoveNode/MergeNode: "successfully parsed path yields
// zero segments" branch. This differs from an empty-string path (which
// parsePath itself rejects with a wrapped error) — a dots-only path parses
// without error but decomposes to no segments at all.

func TestSetNode_AllDotsPathYieldsEmptySegments(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)

	err = SetNode(node, "...", "x")
	require.Error(t, err)
	// Unwrapped "empty path" (not "parsing path: empty path") proves this hit
	// SetNode's own len(segments)==0 guard, not parsePath's own empty-string check.
	assert.Equal(t, "empty path", err.Error())
}

func TestAddNode_AllDotsPathYieldsEmptySegments(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)

	err = AddNode(node, "...", "x")
	require.Error(t, err)
	assert.Equal(t, "empty path", err.Error())
}

func TestRemoveNode_AllDotsPathYieldsEmptySegments(t *testing.T) {
	node, err := ParseYAML([]byte("key: value"))
	require.NoError(t, err)

	err = RemoveNode(node, "...")
	require.Error(t, err)
	assert.Equal(t, "empty path", err.Error())
}

func TestMergeNode_AllDotsPathMergesAtRoot(t *testing.T) {
	// A dots-only path parses to zero segments, so MergeNode targets the
	// document root itself (contentNode(root)) rather than erroring.
	input := `apiVersion: v1
kind: Pod
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = MergeNode(node, "...", map[string]any{"newField": "rootMerge"})
	require.NoError(t, err)

	found, err := FindNode(node, "newField")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "rootMerge", found.Value)

	// Existing top-level fields are untouched.
	found, err = FindNode(node, "apiVersion")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "v1", found.Value)
}

// --- AddNode: navigateOrCreate error while navigating to the PARENT (not the
// final segment) — an intermediate sequence index that's out of bounds.

func TestAddNode_ParentNavigationIndexOutOfBounds(t *testing.T) {
	input := `spec:
  containers:
  - name: only
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	// "containers[9]" is an intermediate segment, not the final one — the
	// out-of-bounds error must surface while AddNode is still walking to the
	// parent of "foo".
	err = AddNode(node, "spec.containers[9].foo", "bar")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "navigating to")
	assert.Contains(t, err.Error(), "out of bounds")
}

// --- RemoveNode: final path segment is a [*] wildcard. RemoveNode has no
// defined "remove all matches" semantics, so the final-segment handling
// falls through the empty-key no-op branch, leaving the sequence untouched.

func TestRemoveNode_WildcardFinalSegmentIsNoOp(t *testing.T) {
	input := `items:
- a
- b
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = RemoveNode(node, "items[*]")
	require.NoError(t, err)

	items, err := FindNode(node, "items")
	require.NoError(t, err)
	require.NotNil(t, items)
	assert.Len(t, items.Content, 2, "wildcard removal is a no-op, not a bulk delete")
}

// --- MergeNode: navigatePath returns a genuine error (wildcard segments are
// rejected), which MergeNode must propagate rather than swallow.

func TestMergeNode_WildcardPathNavigationError(t *testing.T) {
	input := `items:
- a
- b
`
	node, err := ParseYAML([]byte(input))
	require.NoError(t, err)

	err = MergeNode(node, "items[*]", "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard")
}

// --- detectIndent: the recursive walk closure's defensive nil-child guard.
// yaml.v3's real parser (and every function in this package that builds
// nodes) never places a nil entry in a Content slice, so this exercises the
// guard directly with a hand-built tree.

func TestDetectIndent_NilChildNodeInContent(t *testing.T) {
	node := &yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{
			{
				Kind:    yaml.SequenceNode,
				Content: []*yaml.Node{nil},
			},
		},
	}
	got := detectIndent(node)
	assert.Equal(t, 2, got, "should fall back to the default indent when a nil child is encountered")
}

// --- detectIndent: the direct "parentCol > 0 && firstKey.Column > parentCol"
// comparison at the top of walk(), reached via the recursive
// "walk into children" path rather than the sibling nested-mapping check.
// A sequence sits between the document root and the mapping so that the
// mapping is only ever visited through the recursive walk (with a non-zero
// parentCol carried from the sequence node's own Column), never via the
// sibling nested-mapping-value check.

func TestDetectIndent_DirectParentColumnBranch(t *testing.T) {
	node := &yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{
			{
				Kind:   yaml.SequenceNode,
				Column: 3,
				Content: []*yaml.Node{
					{
						Kind: yaml.MappingNode,
						Content: []*yaml.Node{
							{Kind: yaml.ScalarNode, Value: "key", Column: 5},
							{Kind: yaml.ScalarNode, Value: "val", Column: 10},
						},
					},
				},
			},
		},
	}
	got := detectIndent(node)
	assert.Equal(t, 2, got, "5 (firstKey.Column) - 3 (parentCol) == 2")
}

// --- valueToNode: the fallback marshal/unmarshal path's yaml.Marshal error
// branch. A type implementing yaml.Marshaler that returns an error triggers
// this cleanly and safely (unlike chan/func values, which yaml.v3's encoder
// handles with a raw, unrecoverable panic rather than a returned error — see
// investigation notes in the accompanying task report).

type failingMarshaler struct{}

func (failingMarshaler) MarshalYAML() (interface{}, error) {
	return nil, fmt.Errorf("intentional marshal failure")
}

func TestValueToNode_FallbackMarshalError(t *testing.T) {
	value := failingMarshaler{}
	result := valueToNode(value)
	require.NotNil(t, result)
	assert.Equal(t, yaml.ScalarNode, result.Kind)
	assert.Equal(t, "!!str", result.Tag)
	assert.Equal(t, fmt.Sprintf("%v", value), result.Value)
}
