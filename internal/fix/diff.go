package fix

import (
	"bytes"
	"fmt"
	"strings"
)

// ANSI color codes for diff colorization.
const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiRed   = "\033[31m"
	ansiGreen = "\033[32m"
	ansiCyan  = "\033[36m"
)

// GenerateDiff produces a unified diff between original and patched content.
// filePath is used in the diff header only. Returns empty string if no changes.
func GenerateDiff(filePath string, original, patched []byte) string {
	if bytes.Equal(original, patched) {
		return ""
	}

	origLines := splitLines(original)
	patchLines := splitLines(patched)

	// Compute the LCS table for the two line slices.
	lcs := computeLCS(origLines, patchLines)

	// Build the list of edit operations from the LCS.
	edits := buildEdits(origLines, patchLines, lcs)

	// Group edits into hunks with 3 lines of context.
	hunks := groupHunks(edits, 3)

	if len(hunks) == 0 {
		return ""
	}

	var buf strings.Builder
	fmt.Fprintf(&buf, "--- a/%s\n", filePath)
	fmt.Fprintf(&buf, "+++ b/%s\n", filePath)

	for _, h := range hunks {
		fmt.Fprintf(&buf, "@@ -%d,%d +%d,%d @@\n", h.origStart+1, h.origCount, h.patchStart+1, h.patchCount)
		for _, line := range h.lines {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}

	return buf.String()
}

// ColorDiff adds ANSI color codes to a unified diff string.
// Red for removed lines (-), green for added lines (+), cyan for hunk headers (@@), bold for file headers.
func ColorDiff(diff string) string {
	if diff == "" {
		return ""
	}

	lines := strings.Split(diff, "\n")
	var buf strings.Builder

	for i, line := range lines {
		colored := colorLine(line)
		buf.WriteString(colored)
		if i < len(lines)-1 {
			buf.WriteByte('\n')
		}
	}

	return buf.String()
}

// colorLine applies ANSI color to a single diff line based on its prefix.
func colorLine(line string) string {
	switch {
	case strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ "):
		return ansiBold + line + ansiReset
	case strings.HasPrefix(line, "@@"):
		return ansiCyan + line + ansiReset
	case strings.HasPrefix(line, "-"):
		return ansiRed + line + ansiReset
	case strings.HasPrefix(line, "+"):
		return ansiGreen + line + ansiReset
	default:
		return line
	}
}

// splitLines splits content into lines, handling the trailing newline correctly.
// An empty input produces an empty slice. A trailing newline does not produce
// an extra empty element.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	s := string(data)
	// Remove a single trailing newline to avoid a spurious empty line.
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// editOp represents a single edit operation in the diff.
type editOp struct {
	kind     byte   // ' ' = context, '-' = remove, '+' = add
	origIdx  int    // line index in original (for '-' and ' ')
	patchIdx int    // line index in patched (for '+' and ' ')
	text     string // line text
}

// hunk represents a group of changes with surrounding context.
type hunk struct {
	origStart  int      // 0-based start line in original
	origCount  int      // number of original lines in hunk
	patchStart int      // 0-based start line in patched
	patchCount int      // number of patched lines in hunk
	lines      []string // diff lines (prefixed with ' ', '-', or '+')
}

// lcsTable is a flat-allocated LCS table that stores an (m+1)x(n+1) matrix
// in a single []int slice. This eliminates m+1 separate row allocations
// compared to the [][]int approach, significantly reducing GC pressure.
type lcsTable struct {
	data []int
	cols int // number of columns (n+1)
}

// get returns the LCS value at position (i, j).
func (t lcsTable) get(i, j int) int {
	return t.data[i*t.cols+j]
}

// computeLCS builds a longest common subsequence table for two string slices.
// Returns a flat-allocated table where lcs.get(i,j) is the LCS length of a[:i] and b[:j].
func computeLCS(a, b []string) lcsTable {
	m := len(a)
	n := len(b)
	cols := n + 1
	data := make([]int, (m+1)*cols)
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			idx := i*cols + j
			switch {
			case a[i-1] == b[j-1]:
				data[idx] = data[(i-1)*cols+j-1] + 1
			case data[(i-1)*cols+j] >= data[i*cols+j-1]:
				data[idx] = data[(i-1)*cols+j]
			default:
				data[idx] = data[i*cols+j-1]
			}
		}
	}
	return lcsTable{data: data, cols: cols}
}

// buildEdits traces back through the LCS table to produce a sequence of edit operations.
func buildEdits(origLines, patchLines []string, lcs lcsTable) []editOp {
	var edits []editOp
	i := len(origLines)
	j := len(patchLines)

	// Trace back through the LCS table to build edits in reverse order.
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && origLines[i-1] == patchLines[j-1]:
			edits = append(edits, editOp{kind: ' ', origIdx: i - 1, patchIdx: j - 1, text: origLines[i-1]})
			i--
			j--
		case j > 0 && (i == 0 || lcs.get(i, j-1) >= lcs.get(i-1, j)):
			edits = append(edits, editOp{kind: '+', patchIdx: j - 1, text: patchLines[j-1]})
			j--
		default:
			edits = append(edits, editOp{kind: '-', origIdx: i - 1, text: origLines[i-1]})
			i--
		}
	}

	// Reverse to get forward order.
	for left, right := 0, len(edits)-1; left < right; left, right = left+1, right-1 {
		edits[left], edits[right] = edits[right], edits[left]
	}

	return edits
}

// groupHunks groups edit operations into hunks with the given number of context lines.
// Adjacent hunks are merged if their context windows overlap.
func groupHunks(edits []editOp, contextLines int) []hunk {
	// Find indices of change operations.
	var changeIndices []int
	for i, e := range edits {
		if e.kind != ' ' {
			changeIndices = append(changeIndices, i)
		}
	}

	if len(changeIndices) == 0 {
		return nil
	}

	// Group change indices into ranges that should share a hunk.
	type indexRange struct {
		start, end int // inclusive indices into edits slice
	}

	var groups []indexRange
	groupStart := changeIndices[0]
	groupEnd := changeIndices[0]

	for k := 1; k < len(changeIndices); k++ {
		// If the gap between the last change and this one is small enough
		// that context windows overlap, merge into the same group.
		if changeIndices[k]-groupEnd <= 2*contextLines {
			groupEnd = changeIndices[k]
		} else {
			groups = append(groups, indexRange{groupStart, groupEnd})
			groupStart = changeIndices[k]
			groupEnd = changeIndices[k]
		}
	}
	groups = append(groups, indexRange{groupStart, groupEnd})

	// Build hunks from groups.
	var hunks []hunk
	for _, g := range groups {
		// Expand context around the group.
		hunkStart := g.start - contextLines
		if hunkStart < 0 {
			hunkStart = 0
		}
		hunkEnd := g.end + contextLines
		if hunkEnd >= len(edits) {
			hunkEnd = len(edits) - 1
		}

		var h hunk
		origCount := 0
		patchCount := 0
		origStartSet := false
		patchStartSet := false

		for idx := hunkStart; idx <= hunkEnd; idx++ {
			e := edits[idx]
			switch e.kind {
			case ' ':
				h.lines = append(h.lines, " "+e.text)
				if !origStartSet {
					h.origStart = e.origIdx
					origStartSet = true
				}
				if !patchStartSet {
					h.patchStart = e.patchIdx
					patchStartSet = true
				}
				origCount++
				patchCount++
			case '-':
				h.lines = append(h.lines, "-"+e.text)
				if !origStartSet {
					h.origStart = e.origIdx
					origStartSet = true
				}
				if !patchStartSet {
					// For a deletion at the start, the patch position is the
					// corresponding position in the patched file.
					h.patchStart = e.origIdx - origCount + patchCount
				}
				origCount++
			case '+':
				h.lines = append(h.lines, "+"+e.text)
				if !patchStartSet {
					h.patchStart = e.patchIdx
					patchStartSet = true
				}
				if !origStartSet {
					// For an addition at the start, the orig position is derived.
					h.origStart = e.patchIdx - patchCount + origCount
				}
				patchCount++
			}
		}

		h.origCount = origCount
		h.patchCount = patchCount
		hunks = append(hunks, h)
	}

	return hunks
}
