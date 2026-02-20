package fix

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document represents a single YAML document with its content and original separator.
type Document struct {
	// Node is the parsed yaml.Node tree for this document.
	Node *yaml.Node
	// Raw holds the original raw bytes for verbatim output if unmodified.
	Raw []byte
	// Modified indicates whether the document was modified by a fix operation.
	Modified bool
}

// maxDocumentCount is the maximum number of YAML documents allowed in a single file.
// Combined with the 10 MiB file size limit, this prevents excessive memory use
// from files with many tiny documents.
const maxDocumentCount = 10000

// ParseDocuments parses multi-document YAML (separated by ---) into individual
// Document structs. Preserves all comments, formatting, key ordering, and
// indentation via the yaml.v3 Node API.
func ParseDocuments(data []byte) ([]*Document, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	rawDocs := splitDocuments(data)
	if len(rawDocs) > maxDocumentCount {
		return nil, fmt.Errorf("YAML contains %d documents, exceeding maximum of %d", len(rawDocs), maxDocumentCount)
	}
	docs := make([]*Document, 0, len(rawDocs))

	for _, raw := range rawDocs {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			// Preserve empty documents as-is (they might just be separators).
			docs = append(docs, &Document{
				Node: &yaml.Node{Kind: yaml.DocumentNode},
				Raw:  raw,
			})
			continue
		}

		node, err := ParseYAML(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing document: %w", err)
		}
		docs = append(docs, &Document{
			Node: node,
			Raw:  raw,
		})
	}

	return docs, nil
}

// splitDocuments splits multi-document YAML data on --- separators.
// It returns the raw bytes of each document, preserving original formatting.
func splitDocuments(data []byte) [][]byte {
	var docs [][]byte
	s := string(data)

	// Split on lines that are exactly "---" (possibly with trailing whitespace).
	lines := strings.Split(s, "\n")
	var current []string
	first := true

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "---" {
			if first {
				// If the very first line is ---, skip it as a document separator
				// but only if there's nothing before it.
				if len(current) == 0 {
					first = false
					continue
				}
			}
			// End the current document.
			docStr := strings.Join(current, "\n")
			if strings.TrimSpace(docStr) != "" || len(docs) > 0 {
				docs = append(docs, []byte(docStr))
			}
			current = nil
			first = false
			continue
		}
		first = false
		current = append(current, line)
	}

	// Append the last document.
	if len(current) > 0 {
		docStr := strings.Join(current, "\n")
		docs = append(docs, []byte(docStr))
	}

	// If we got nothing (e.g., just "---"), return at least one empty doc.
	if len(docs) == 0 {
		docs = append(docs, data)
	}

	return docs
}

// SerializeDocuments serializes documents back to bytes, preserving original
// formatting for unmodified documents and using the yaml.v3 encoder for
// modified ones.
func SerializeDocuments(docs []*Document) ([]byte, error) {
	if len(docs) == 0 {
		return nil, nil
	}

	var buf bytes.Buffer
	for i, doc := range docs {
		if i > 0 {
			buf.WriteString("---\n")
		}

		if !doc.Modified {
			// Unmodified: use raw bytes verbatim.
			buf.Write(doc.Raw)
			// Ensure a trailing newline for consistent output.
			if len(doc.Raw) > 0 && doc.Raw[len(doc.Raw)-1] != '\n' {
				buf.WriteByte('\n')
			}
		} else {
			// Modified: serialize through yaml.v3 encoder.
			serialized, err := SerializeNode(doc.Node)
			if err != nil {
				return nil, fmt.Errorf("serializing document %d: %w", i, err)
			}
			buf.Write(serialized)
		}
	}

	return buf.Bytes(), nil
}

// ParseYAML parses a single YAML document preserving all formatting.
// It returns the top-level yaml.Node (a DocumentNode wrapping the content).
func ParseYAML(data []byte) (*yaml.Node, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	return &node, nil
}

// SerializeNode serializes a yaml.Node back to bytes.
// Uses yaml.v3 encoder with the same indentation as detected from the node.
func SerializeNode(node *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(detectIndent(node))

	if err := enc.Encode(node); err != nil {
		return nil, fmt.Errorf("encoding YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("closing YAML encoder: %w", err)
	}

	return buf.Bytes(), nil
}

// detectIndent attempts to detect the indentation level used in the YAML node tree.
// Defaults to 2 if indentation cannot be determined.
func detectIndent(node *yaml.Node) int {
	if node == nil {
		return 2
	}

	// Walk the tree looking for a mapping node with children that have
	// column information we can use.
	var walk func(n *yaml.Node, parentCol int) int
	walk = func(n *yaml.Node, parentCol int) int {
		if n == nil {
			return 0
		}
		if n.Kind == yaml.MappingNode && len(n.Content) > 0 {
			firstKey := n.Content[0]
			if parentCol > 0 && firstKey.Column > parentCol {
				return firstKey.Column - parentCol
			}
			// Check nested mappings.
			for i := 1; i < len(n.Content); i += 2 {
				val := n.Content[i]
				if val.Kind == yaml.MappingNode && len(val.Content) > 0 {
					key := n.Content[i-1]
					nestedKey := val.Content[0]
					if nestedKey.Column > key.Column {
						return nestedKey.Column - key.Column
					}
				}
			}
		}
		// Recurse into content.
		for _, child := range n.Content {
			if indent := walk(child, n.Column); indent > 0 {
				return indent
			}
		}
		return 0
	}

	if indent := walk(node, 0); indent > 0 {
		return indent
	}
	return 2
}

// pathSegment represents a single segment of a YAML navigation path.
type pathSegment struct {
	Key      string // Mapping key name
	Index    int    // Sequence index (-1 if not an index)
	Wildcard bool   // Whether this is a [*] wildcard
}

// parsePath parses a dot-separated YAML path into segments.
// Supports paths like "spec.containers[0].securityContext.privileged"
// and "spec.containers[*].securityContext" (wildcard matches all indices).
func parsePath(path string) ([]pathSegment, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}

	var segments []pathSegment
	parts := strings.Split(path, ".")

	for _, part := range parts {
		if part == "" {
			continue
		}

		// Check for array index: key[N] or key[*]
		if idx := strings.Index(part, "["); idx >= 0 {
			key := part[:idx]
			bracketContent := part[idx:]

			if key != "" {
				segments = append(segments, pathSegment{Key: key, Index: -1})
			}

			// Parse bracket content: [0], [*], [1], etc.
			if !strings.HasSuffix(bracketContent, "]") {
				return nil, fmt.Errorf("unclosed bracket in path segment: %q", part)
			}
			inner := bracketContent[1 : len(bracketContent)-1]
			if inner == "*" {
				segments = append(segments, pathSegment{Wildcard: true, Index: -1})
			} else {
				idx, err := strconv.Atoi(inner)
				if err != nil {
					return nil, fmt.Errorf("invalid array index in path segment: %q", part)
				}
				segments = append(segments, pathSegment{Index: idx})
			}
		} else {
			segments = append(segments, pathSegment{Key: part, Index: -1})
		}
	}

	return segments, nil
}

// contentNode unwraps a DocumentNode to get to the actual content node.
// If the node is already a non-document node, it returns it as-is.
func contentNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

// FindNode navigates to a field by dot-separated path.
// Supports paths like "spec.containers[0].securityContext.privileged"
// and "spec.containers[*].securityContext" (wildcard [*] matches all indices).
// Returns nil, nil if the path doesn't exist (not found is not an error).
func FindNode(root *yaml.Node, path string) (*yaml.Node, error) {
	segments, err := parsePath(path)
	if err != nil {
		return nil, fmt.Errorf("parsing path: %w", err)
	}

	node := contentNode(root)
	if node == nil {
		return nil, nil
	}

	return navigatePath(node, segments)
}

// navigatePath walks the yaml.Node tree following the parsed path segments.
func navigatePath(node *yaml.Node, segments []pathSegment) (*yaml.Node, error) {
	current := node

	for _, seg := range segments {
		if current == nil {
			return nil, nil
		}

		switch {
		case seg.Wildcard:
			// Wildcard is not directly navigable to a single node.
			return nil, fmt.Errorf("wildcard [*] segments are not supported in FindNode; use FindNodes instead")

		case seg.Index >= 0:
			// Navigate into a sequence by index.
			if current.Kind != yaml.SequenceNode {
				return nil, nil
			}
			if seg.Index >= len(current.Content) {
				return nil, nil
			}
			current = current.Content[seg.Index]

		case seg.Key != "":
			// Navigate into a mapping by key.
			if current.Kind != yaml.MappingNode {
				return nil, nil
			}
			found := false
			for i := 0; i < len(current.Content)-1; i += 2 {
				if current.Content[i].Value == seg.Key {
					current = current.Content[i+1]
					found = true
					break
				}
			}
			if !found {
				return nil, nil
			}
		}
	}

	return current, nil
}

// FindNodes navigates to potentially multiple nodes when using wildcard [*] paths.
// Returns all matching nodes. Returns nil, nil if no matches are found.
func FindNodes(root *yaml.Node, path string) ([]*yaml.Node, error) {
	segments, err := parsePath(path)
	if err != nil {
		return nil, fmt.Errorf("parsing path: %w", err)
	}

	node := contentNode(root)
	if node == nil {
		return nil, nil
	}

	return navigatePathMulti([]*yaml.Node{node}, segments)
}

// navigatePathMulti walks the yaml.Node tree following path segments,
// expanding wildcards into multiple nodes.
func navigatePathMulti(nodes []*yaml.Node, segments []pathSegment) ([]*yaml.Node, error) {
	current := nodes

	for _, seg := range segments {
		if len(current) == 0 {
			return nil, nil
		}

		var next []*yaml.Node
		for _, node := range current {
			if node == nil {
				continue
			}

			switch {
			case seg.Wildcard:
				if node.Kind != yaml.SequenceNode {
					continue
				}
				next = append(next, node.Content...)

			case seg.Index >= 0:
				if node.Kind != yaml.SequenceNode {
					continue
				}
				if seg.Index < len(node.Content) {
					next = append(next, node.Content[seg.Index])
				}

			case seg.Key != "":
				if node.Kind != yaml.MappingNode {
					continue
				}
				for i := 0; i < len(node.Content)-1; i += 2 {
					if node.Content[i].Value == seg.Key {
						next = append(next, node.Content[i+1])
						break
					}
				}
			}
		}
		current = next
	}

	if len(current) == 0 {
		return nil, nil
	}
	return current, nil
}

// SetNode sets a field value at the given path. Creates intermediate nodes if
// needed. The value is converted to a yaml.Node. Does NOT disturb sibling
// fields or comments.
func SetNode(root *yaml.Node, path string, value any) error {
	segments, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("parsing path: %w", err)
	}
	if len(segments) == 0 {
		return fmt.Errorf("empty path")
	}

	content := contentNode(root)
	if content == nil {
		return fmt.Errorf("nil root node")
	}

	return setNodeAt(content, segments, value)
}

// setNodeAt navigates to the parent of the target and sets the value.
func setNodeAt(node *yaml.Node, segments []pathSegment, value any) error {
	// Navigate to the parent, creating intermediates as needed.
	current := node
	for i := 0; i < len(segments)-1; i++ {
		seg := segments[i]
		next, err := navigateOrCreate(current, seg)
		if err != nil {
			return fmt.Errorf("navigating to %q: %w", seg.Key, err)
		}
		current = next
	}

	// Handle the final segment.
	lastSeg := segments[len(segments)-1]
	newVal := valueToNode(value)

	if lastSeg.Index >= 0 {
		// Setting a sequence element.
		if current.Kind != yaml.SequenceNode {
			return fmt.Errorf("expected sequence node at path, got kind %d", current.Kind)
		}
		if lastSeg.Index >= len(current.Content) {
			return fmt.Errorf("index %d out of bounds (length %d)", lastSeg.Index, len(current.Content))
		}
		// Preserve comments from the old node.
		old := current.Content[lastSeg.Index]
		newVal.HeadComment = old.HeadComment
		newVal.LineComment = old.LineComment
		newVal.FootComment = old.FootComment
		current.Content[lastSeg.Index] = newVal
		return nil
	}

	if lastSeg.Key == "" {
		return fmt.Errorf("empty key in final path segment")
	}

	if current.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node for key %q, got kind %d", lastSeg.Key, current.Kind)
	}

	// Search for existing key.
	for i := 0; i < len(current.Content)-1; i += 2 {
		if current.Content[i].Value != lastSeg.Key {
			continue
		}
		// Preserve comments from the old value node.
		old := current.Content[i+1]
		newVal.HeadComment = old.HeadComment
		newVal.LineComment = old.LineComment
		newVal.FootComment = old.FootComment
		current.Content[i+1] = newVal
		return nil
	}

	// Key doesn't exist; create it.
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: lastSeg.Key,
	}
	current.Content = append(current.Content, keyNode, newVal)
	return nil
}

// navigateOrCreate navigates to the child described by seg, creating
// intermediate mapping or sequence nodes as needed.
func navigateOrCreate(current *yaml.Node, seg pathSegment) (*yaml.Node, error) {
	if seg.Index >= 0 {
		// Sequence index navigation.
		if current.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("expected sequence node, got kind %d", current.Kind)
		}
		if seg.Index >= len(current.Content) {
			return nil, fmt.Errorf("index %d out of bounds (length %d)", seg.Index, len(current.Content))
		}
		return current.Content[seg.Index], nil
	}

	if seg.Key == "" {
		return nil, fmt.Errorf("empty key in path segment")
	}

	if current.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node for key %q, got kind %d", seg.Key, current.Kind)
	}

	// Search for existing key.
	for i := 0; i < len(current.Content)-1; i += 2 {
		if current.Content[i].Value == seg.Key {
			return current.Content[i+1], nil
		}
	}

	// Create intermediate mapping node.
	newMapping := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: seg.Key,
	}
	current.Content = append(current.Content, keyNode, newMapping)
	return newMapping, nil
}

// AddNode adds a new field at the given path. Returns an error if the field
// already exists. Creates intermediate mapping nodes as needed.
func AddNode(root *yaml.Node, path string, value any) error {
	segments, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("parsing path: %w", err)
	}
	if len(segments) == 0 {
		return fmt.Errorf("empty path")
	}

	content := contentNode(root)
	if content == nil {
		return fmt.Errorf("nil root node")
	}

	// Navigate to the parent.
	current := content
	for i := 0; i < len(segments)-1; i++ {
		seg := segments[i]
		next, err := navigateOrCreate(current, seg)
		if err != nil {
			return fmt.Errorf("navigating to %q: %w", seg.Key, err)
		}
		current = next
	}

	lastSeg := segments[len(segments)-1]

	if lastSeg.Key == "" {
		return fmt.Errorf("AddNode requires a key-based final path segment")
	}

	if current.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node for key %q, got kind %d", lastSeg.Key, current.Kind)
	}

	// Check if the key already exists.
	for i := 0; i < len(current.Content)-1; i += 2 {
		if current.Content[i].Value == lastSeg.Key {
			return fmt.Errorf("field %q already exists", lastSeg.Key)
		}
	}

	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: lastSeg.Key,
	}
	current.Content = append(current.Content, keyNode, valueToNode(value))
	return nil
}

// RemoveNode removes a field at the given path.
// Returns nil if the field doesn't exist (idempotent).
func RemoveNode(root *yaml.Node, path string) error {
	segments, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("parsing path: %w", err)
	}
	if len(segments) == 0 {
		return fmt.Errorf("empty path")
	}

	content := contentNode(root)
	if content == nil {
		return nil
	}

	// Navigate to the parent of the target.
	current := content
	for i := 0; i < len(segments)-1; i++ {
		seg := segments[i]
		next := navigateExisting(current, seg)
		if next == nil {
			return nil // Parent doesn't exist; nothing to remove.
		}
		current = next
	}

	lastSeg := segments[len(segments)-1]

	if lastSeg.Index >= 0 {
		// Remove a sequence element.
		if current.Kind != yaml.SequenceNode {
			return nil
		}
		if lastSeg.Index >= len(current.Content) {
			return nil
		}
		current.Content = append(current.Content[:lastSeg.Index], current.Content[lastSeg.Index+1:]...)
		return nil
	}

	if lastSeg.Key == "" {
		return nil
	}

	if current.Kind != yaml.MappingNode {
		return nil
	}

	// Find and remove the key/value pair.
	for i := 0; i < len(current.Content)-1; i += 2 {
		if current.Content[i].Value == lastSeg.Key {
			current.Content = append(current.Content[:i], current.Content[i+2:]...)
			return nil
		}
	}

	return nil // Key not found; idempotent.
}

// navigateExisting navigates to the child described by seg, returning nil
// if the child doesn't exist (does not create intermediate nodes).
func navigateExisting(current *yaml.Node, seg pathSegment) *yaml.Node {
	if seg.Index >= 0 {
		if current.Kind != yaml.SequenceNode {
			return nil
		}
		if seg.Index >= len(current.Content) {
			return nil
		}
		return current.Content[seg.Index]
	}

	if seg.Key == "" {
		return nil
	}

	if current.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i < len(current.Content)-1; i += 2 {
		if current.Content[i].Value == seg.Key {
			return current.Content[i+1]
		}
	}
	return nil
}

// MergeNode merges a value into an existing map or list at the given path.
// For maps: adds new keys, doesn't overwrite existing.
// For lists: appends items.
func MergeNode(root *yaml.Node, path string, value any) error {
	segments, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("parsing path: %w", err)
	}

	content := contentNode(root)
	if content == nil {
		return fmt.Errorf("nil root node")
	}

	// Navigate to the target node.
	var target *yaml.Node
	if len(segments) == 0 {
		target = content
	} else {
		var navErr error
		target, navErr = navigatePath(content, segments)
		if navErr != nil {
			return navErr
		}
	}

	if target == nil {
		return fmt.Errorf("target node not found at path %q", path)
	}

	mergeVal := valueToNode(value)

	switch target.Kind {
	case yaml.MappingNode:
		if mergeVal.Kind != yaml.MappingNode {
			return fmt.Errorf("cannot merge non-mapping value into mapping node")
		}
		// Add keys that don't already exist.
		for i := 0; i < len(mergeVal.Content)-1; i += 2 {
			key := mergeVal.Content[i].Value
			exists := false
			for j := 0; j < len(target.Content)-1; j += 2 {
				if target.Content[j].Value == key {
					exists = true
					break
				}
			}
			if !exists {
				target.Content = append(target.Content, mergeVal.Content[i], mergeVal.Content[i+1])
			}
		}

	case yaml.SequenceNode:
		if mergeVal.Kind == yaml.SequenceNode {
			target.Content = append(target.Content, mergeVal.Content...)
		} else {
			// Append a single item.
			target.Content = append(target.Content, mergeVal)
		}

	default:
		return fmt.Errorf("cannot merge into node of kind %d", target.Kind)
	}

	return nil
}

// valueToNode converts a Go value to a yaml.Node with appropriate Tag and Kind.
func valueToNode(value any) *yaml.Node {
	if value == nil {
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!null",
			Value: "null",
		}
	}

	switch v := value.(type) {
	case bool:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!bool",
			Value: strconv.FormatBool(v),
		}
	case int:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!int",
			Value: strconv.Itoa(v),
		}
	case int64:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!int",
			Value: strconv.FormatInt(v, 10),
		}
	case float64:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!float",
			Value: strconv.FormatFloat(v, 'f', -1, 64),
		}
	case string:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: v,
		}
	case []string:
		seq := &yaml.Node{
			Kind: yaml.SequenceNode,
			Tag:  "!!seq",
		}
		for _, s := range v {
			seq.Content = append(seq.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: s,
			})
		}
		return seq
	case []any:
		seq := &yaml.Node{
			Kind: yaml.SequenceNode,
			Tag:  "!!seq",
		}
		for _, item := range v {
			seq.Content = append(seq.Content, valueToNode(item))
		}
		return seq
	case map[string]any:
		mapping := &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}
		for key, val := range v {
			keyNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: key,
			}
			mapping.Content = append(mapping.Content, keyNode, valueToNode(val))
		}
		return mapping
	case *yaml.Node:
		return v
	case yaml.Node:
		return &v
	default:
		// Fallback: convert via marshal/unmarshal for complex types.
		var node yaml.Node
		data, err := yaml.Marshal(value)
		if err != nil {
			return &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: fmt.Sprintf("%v", value),
			}
		}
		if err := yaml.Unmarshal(data, &node); err != nil {
			return &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: fmt.Sprintf("%v", value),
			}
		}
		if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
			return node.Content[0]
		}
		return &node
	}
}
