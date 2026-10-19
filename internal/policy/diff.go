package policy

import (
	"bytes"
	"encoding/json"
	"strings"
)

// A tool description is usually one long line of prose, so a line diff would
// mark the whole thing as changed. The diff here works on sentence-sized chunks
// instead, which is the granularity at which a rug pull actually reads: one
// extra sentence appended to a harmless description.

// DiffLine is one line of a rendered diff.
type DiffLine struct {
	// Op is ' ' for unchanged text, '-' for removed and '+' for added.
	Op   byte
	Text string
}

// String renders the line the way `diff -u` would.
func (l DiffLine) String() string { return string(l.Op) + " " + l.Text }

// DiffSnapshots compares two advertisements of the same tool. Either side may
// be nil (a store written before snapshots existed); a missing side is treated
// as empty, so the other side shows up entirely as added or removed.
func DiffSnapshots(old, updated *ToolSnapshot) []DiffLine {
	var oldDesc, newDesc, oldSchema, newSchema string
	if old != nil {
		oldDesc, oldSchema = old.Description, prettySchema(old.InputSchema)
	}
	if updated != nil {
		newDesc, newSchema = updated.Description, prettySchema(updated.InputSchema)
	}

	var out []DiffLine
	out = append(out, diffChunks(descriptionChunks(oldDesc), descriptionChunks(newDesc))...)

	if oldSchema != newSchema {
		out = append(out, DiffLine{Op: ' ', Text: "input schema:"})
		out = append(out, diffChunks(splitLines(oldSchema), splitLines(newSchema))...)
	}
	return out
}

// HasChanges reports whether a diff contains anything other than unchanged
// lines.
func HasChanges(lines []DiffLine) bool {
	for _, l := range lines {
		if l.Op != ' ' {
			return true
		}
	}
	return false
}

// prettySchema indents a canonical schema so that each property sits on its own
// line and the diff can point at it.
func prettySchema(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// descriptionChunks splits prose into lines and then into sentences.
func descriptionChunks(s string) []string {
	var chunks []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		start := 0
		for i := 0; i+1 < len(line); i++ {
			if (line[i] == '.' || line[i] == '!' || line[i] == '?') && line[i+1] == ' ' {
				chunks = append(chunks, strings.TrimSpace(line[start:i+1]))
				start = i + 1
			}
		}
		if rest := strings.TrimSpace(line[start:]); rest != "" {
			chunks = append(chunks, rest)
		}
	}
	return chunks
}

// diffChunks is a longest-common-subsequence diff. Tool descriptions are tens
// of chunks long at most, so the quadratic table is irrelevant.
func diffChunks(a, b []string) []DiffLine {
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var out []DiffLine
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, DiffLine{' ', a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, DiffLine{'-', a[i]})
			i++
		default:
			out = append(out, DiffLine{'+', b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, DiffLine{'-', a[i]})
	}
	for ; j < len(b); j++ {
		out = append(out, DiffLine{'+', b[j]})
	}
	return out
}
