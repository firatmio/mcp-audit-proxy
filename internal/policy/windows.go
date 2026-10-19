package policy

import (
	"bytes"
	"sort"
)

// Two of the result rules are slow on large text: a case-insensitive pattern
// with word boundaries and bounded gaps costs Go's regexp engine about 3.5 ms
// per 64 KiB, which is most of what scanning a large result costs. But every
// match of those rules has to begin at one of a handful of words, so the
// pattern only needs to run near where those words occur. keywordRule finds
// the words with a plain byte search and runs the pattern on windows around
// them.
//
// The windows are built so the answer is the same as running the pattern on
// the whole text — windowed_test.go checks that — rather than "usually the
// same":
//   - they start well before the word and are widened to a word boundary at
//     both ends, so \b means what it means in the full text;
//   - they reach back over any run of whitespace before the word, because
//     "do\s+not" lets an arbitrary amount of it sit before "not";
//   - they extend far enough forward to hold the longest match the pattern
//     can make after its first word (about 350 bytes for these two; the
//     window reaches 512, so the end-of-window widening is a safeguard for
//     a future pattern rather than something today's patterns need);
//   - overlapping windows are merged and searched in order, so the first
//     match found is the leftmost one, as FindString would return.

// keywordRule is a pattern rule plus the words its matches start at.
type keywordRule struct {
	patternRule
	// keywords are lower-case ASCII. Empty means: run on the whole text.
	keywords []string
	// back and forward are how far a window reaches either side of a
	// keyword, before widening to word boundaries.
	back, forward int
}

// resultKeywords lists, for the slow rules, the words every match begins at
// (or, for "do not", ends the first phrase with).
var resultKeywords = map[string]keywordRule{
	RuleInstructionOverride: {
		keywords: []string{"ignore", "disregard", "forget", "override"},
		back:     16,
		// keyword + up to 40 runes + keyword + up to 40 runes + keyword:
		// 40 runes is at most 160 bytes of UTF-8.
		forward: 512,
	},
	RuleConcealment: {
		keywords: []string{"not", "don", "never", "without"},
		back:     16,
		forward:  512,
	},
}

func (r keywordRule) find(text string, lower []byte) string {
	if len(r.keywords) == 0 {
		return r.pattern.FindString(text)
	}

	type window struct{ start, end int }
	var windows []window
	for _, kw := range r.keywords {
		for from := 0; from < len(lower); {
			i := bytes.Index(lower[from:], []byte(kw))
			if i < 0 {
				break
			}
			at := from + i
			from = at + len(kw)

			start := at - r.back
			if start < 0 {
				start = 0
			}
			// Reach back over whitespace before the word, then to a word
			// boundary.
			for start > 0 && isSpace(text[start-1]) {
				start--
			}
			for start > 0 && isWordByte(text[start-1]) {
				start--
			}

			end := at + r.forward
			if end > len(text) {
				end = len(text)
			}
			for end < len(text) && isWordByte(text[end]) {
				end++
			}
			windows = append(windows, window{start, end})
		}
	}
	if len(windows) == 0 {
		return ""
	}

	sort.Slice(windows, func(i, j int) bool { return windows[i].start < windows[j].start })
	merged := windows[:1]
	for _, w := range windows[1:] {
		last := &merged[len(merged)-1]
		if w.start <= last.end {
			if w.end > last.end {
				last.end = w.end
			}
			continue
		}
		merged = append(merged, w)
	}

	for _, w := range merged {
		if m := r.pattern.FindString(text[w.start:w.end]); m != "" {
			return m
		}
	}
	return ""
}

// asciiLower returns text with A–Z folded to a–z and every other byte
// unchanged, so byte offsets in the result are offsets in text.
func asciiLower(text string) []byte {
	b := []byte(text)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return b
}

// isWordByte matches regexp's \b definition: ASCII letters, digits, underscore.
func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// isSpace matches regexp's \s: ASCII whitespace.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}
