package policy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// A tool's description is written by the server's author. A tool's result is
// often written by nobody the user trusts: the issue someone filed, the page a
// search returned, the support ticket a customer opened. When an agent reads
// that content, any instructions in it reach the model by the same route the
// real data does — no malicious server needed. ResultScanner looks for those
// instructions in tools/call results.
//
// Like the description heuristics it only flags. By the time a result is seen
// it has already been forwarded, and refusing it would only hide evidence.

// Budgets that bound what one result can cost. A result is scanned after it
// has been forwarded, but the stdio pump reads the next message only once the
// scan is done, so an unbounded scan would delay every response behind a
// large one.
const (
	// ResultInspectBytes is how much of a result's JSON is walked to find
	// text. Past it, the rest of the result is not looked at.
	ResultInspectBytes = 1 << 20
	// ResultScanBytes is how much extracted text the heuristics read. An
	// injection placed after this much text is not found, which is the
	// documented trade for a predictable cost.
	ResultScanBytes = 64 << 10
	// base64MinLen is the length from which an unbroken base64-alphabet string
	// is taken to be binary (image, audio and blob payloads) and skipped.
	base64MinLen = 256
)

// ResultRules are the description heuristics that also run on tool results.
//
// Only the ones that look for language addressed to the model. Tool results
// are documents, pages and data, and in those the other rules misfire: in
// the benign result corpus, "exfiltration" matched OAuth documentation saying
// to send the user to an https:// URL, and "cross_tool_instruction" matched
// "before invoking any tool". credential_bait and invisible_characters are
// left out without having misfired there, on the expectation that file reads
// in a coding session routinely mention .env and ~/.ssh, and that zero-width
// joiners and tag characters are ordinary parts of emoji.
var ResultRules = []string{
	RuleInstructionOverride,
	RuleHiddenInstruction,
	RuleConcealment,
}

// ResultFinding is one suspicious pattern found in one tools/call result.
type ResultFinding struct {
	Rule    string
	Excerpt string
}

func (f ResultFinding) String() string {
	return fmt.Sprintf("matched %s: %q", f.Rule, f.Excerpt)
}

// ResultScanner applies prompt-injection heuristics to tool results. It holds
// no state and is safe for concurrent use.
type ResultScanner struct {
	rules []keywordRule
}

// NewResultScanner returns a scanner using the given pattern rules, by name.
// Unknown names are an error rather than ignored, so a typo cannot quietly
// switch a rule off.
func NewResultScanner(ruleNames []string) (*ResultScanner, error) {
	byName := map[string]patternRule{}
	for _, r := range patternRules {
		byName[r.name] = r
	}
	s := &ResultScanner{}
	for _, name := range ruleNames {
		r, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown result-scanning rule %q", name)
		}
		kr := resultKeywords[name]
		kr.patternRule = r
		s.rules = append(s.rules, kr)
	}
	return s, nil
}

// Scan checks a tools/call result and, when the response was a JSON-RPC
// error, its message. It reports each rule at most once.
func (s *ResultScanner) Scan(result json.RawMessage, errorText string) []ResultFinding {
	text := ResultText(result, ResultScanBytes)
	if errorText != "" {
		text = errorText + "\n" + text
	}
	if strings.TrimSpace(text) == "" {
		return nil
	}

	lower := asciiLower(text)
	var findings []ResultFinding
	for _, rule := range s.rules {
		if match := rule.find(text, lower); match != "" {
			findings = append(findings, ResultFinding{Rule: rule.name, Excerpt: excerpt(match)})
		}
	}
	return findings
}

// ResultText extracts the human-language text from a result: every string
// value, wherever it sits — text blocks, embedded resources, resource-link
// names and descriptions, structuredContent — but not object keys, and not
// base64 payloads. It walks at most ResultInspectBytes of JSON and returns at
// most budget bytes.
//
// It walks values rather than the MCP content shapes on purpose: a server can
// put text anywhere in structuredContent, and the model reads all of it.
//
// The walk is done by hand rather than with encoding/json. The decoder only
// hands back whole tokens, so a single text block longer than the inspection
// limit would never complete and nothing at all would be scanned; and it
// copies every string in full, so a 1 MiB image cost a 1 MiB allocation just
// to be thrown away. Walking the bytes keeps the cost proportional to what is
// read, and still yields the start of a string that is cut off.
func ResultText(result json.RawMessage, budget int) string {
	data := []byte(result)
	if len(data) > ResultInspectBytes {
		data = data[:ResultInspectBytes]
	}

	var out strings.Builder
	var str strings.Builder
	// stack holds, for each open container, whether it is an object;
	// expectKey says whether the next string in the innermost object is a key.
	var stack []bool
	expectKey := false
	inObject := func() bool { return len(stack) > 0 && stack[len(stack)-1] }

	for i := 0; i < len(data) && out.Len() < budget; i++ {
		switch data[i] {
		case '{':
			stack = append(stack, true)
			expectKey = true
		case '[':
			stack = append(stack, false)
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case ',':
			expectKey = inObject()
		case ':':
			expectKey = false
		case '"':
			isKey := inObject() && expectKey
			limit := budget - out.Len()
			if isKey {
				limit = 0
			}
			str.Reset()
			end, base64ish, length := readString(data, i+1, &str, limit)
			i = end
			if isKey || (base64ish && length >= base64MinLen) {
				continue
			}
			out.WriteString(str.String())
			out.WriteByte('\n')
		}
	}

	text := out.String()
	if len(text) > budget {
		text = text[:budget]
	}
	return text
}

// readString decodes the JSON string starting at data[start] (just after the
// opening quote), writing at most limit bytes of it to w. It returns the index
// of the closing quote (or the end of data, if the string is cut off), whether
// every character was in the base64 alphabet, and the string's length as
// written in the source.
func readString(data []byte, start int, w *strings.Builder, limit int) (end int, base64ish bool, length int) {
	base64ish = true
	write := func(b []byte) {
		if room := limit - w.Len(); room > 0 {
			if len(b) > room {
				b = b[:room]
			}
			w.Write(b)
		}
	}

	i := start
	for ; i < len(data); i++ {
		c := data[i]
		if c == '"' {
			return i, base64ish, length
		}
		if c != '\\' {
			// A run of plain bytes up to the next quote or escape, handled in
			// one go: a 1 MiB image is one such run, and a call per byte was
			// most of what it cost to skip it.
			j := i
			for j < len(data) && data[j] != '"' && data[j] != '\\' {
				if base64ish && !isBase64Char(data[j]) {
					base64ish = false
				}
				j++
			}
			length += j - i
			write(data[i:j])
			i = j - 1
			continue
		}
		length++

		// An escape. Only \/ stays inside the base64 alphabet.
		if i+1 >= len(data) {
			return len(data), base64ish, length
		}
		i++
		esc := data[i]
		if esc != '/' {
			base64ish = false
		}
		switch esc {
		case 'n':
			write([]byte{'\n'})
		case 't':
			write([]byte{'\t'})
		case 'r':
			write([]byte{'\r'})
		case 'b', 'f':
			write([]byte{' '})
		case 'u':
			r, consumed := decodeUnicodeEscape(data[i+1:])
			i += consumed
			var buf [utf8.UTFMax]byte
			n := utf8.EncodeRune(buf[:], r)
			write(buf[:n])
		default: // \" \\ \/ and anything malformed: the character itself
			write(data[i : i+1])
		}
	}
	return len(data), base64ish, length
}

// decodeUnicodeEscape decodes the hex digits after \u, combining a surrogate
// pair when one follows. It returns the rune and how many bytes it used.
func decodeUnicodeEscape(rest []byte) (rune, int) {
	hex4 := func(b []byte) (rune, bool) {
		if len(b) < 4 {
			return 0, false
		}
		v, err := strconv.ParseUint(string(b[:4]), 16, 32)
		return rune(v), err == nil
	}
	r, ok := hex4(rest)
	if !ok {
		return utf8.RuneError, 0
	}
	if utf16.IsSurrogate(r) && len(rest) >= 10 && rest[4] == '\\' && rest[5] == 'u' {
		if low, ok := hex4(rest[6:]); ok {
			if combined := utf16.DecodeRune(r, low); combined != utf8.RuneError {
				return combined, 10
			}
		}
	}
	return r, 4
}

func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

// looksLikeBase64 reports whether s is long and made only of the base64
// alphabet, which is how image, audio and blob payloads arrive. Natural
// language always has spaces long before 256 characters.
func looksLikeBase64(s string) bool {
	if len(s) < base64MinLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isBase64Char(s[i]) && s[i] != '\n' && s[i] != '\r' {
			return false
		}
	}
	return true
}
