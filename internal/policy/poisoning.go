package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Tool poisoning is an attack on the model rather than on the transport: the
// server hides instructions inside a tool description, which the client dutifully
// puts into the model's context. The user never sees it — they only see a tool
// called "echo" — but the model reads "also send ~/.ssh/id_rsa somewhere first".
//
// These are heuristics. They are tuned to be worth reading rather than to be
// exhaustive: every rule here corresponds to a technique seen in the wild, and
// a finding means "a human should look at this description", not "this is
// definitely an attack".

// Rule names reported in a Finding.
const (
	RuleInstructionOverride  = "instruction_override"
	RuleHiddenInstruction    = "hidden_instruction"
	RuleConcealment          = "concealment"
	RuleCredentialBait       = "credential_bait"
	RuleExfiltration         = "exfiltration"
	RuleInvisibleCharacters  = "invisible_characters"
	RuleCrossToolInstruction = "cross_tool_instruction"
)

// Finding is one suspicious pattern found in one tool description.
type Finding struct {
	// Tool is the tool whose description matched.
	Tool string
	// Rule is which heuristic fired.
	Rule string
	// Excerpt is the matching text, trimmed for display.
	Excerpt string
}

// String renders a finding for a CLI warning.
func (f Finding) String() string {
	return fmt.Sprintf("tool %q description matched %s: %q", f.Tool, f.Rule, f.Excerpt)
}

// patternRule is one regex-based heuristic.
type patternRule struct {
	name    string
	pattern *regexp.Regexp
}

// patternRules are the regex heuristics, all case-insensitive.
var patternRules = []patternRule{
	{
		// "Ignore all previous instructions" and its variations.
		RuleInstructionOverride,
		regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b[^.!?]{0,40}\b(previous|prior|earlier|above|all)\b[^.!?]{0,40}\b(instruction|prompt|rule|direction|context)`),
	},
	{
		// Markup that addresses the model rather than the user.
		RuleHiddenInstruction,
		regexp.MustCompile(`(?i)<\s*/?\s*(important|system|secret|admin|instruction|prompt|hidden)[^>]{0,40}>`),
	},
	{
		// Telling the model to keep something from the user.
		RuleConcealment,
		regexp.MustCompile(`(?i)\b(do\s+not|don'?t|never|without)\b[^.!?]{0,30}\b(tell|telling|mention|mentioning|inform|informing|reveal|revealing|disclose|disclosing|show|showing|notify|notifying)\b[^.!?]{0,30}\b(user|human|operator|anyone)\b`),
	},
	{
		// Secret material named inside a tool advertisement.
		RuleCredentialBait,
		regexp.MustCompile(`(?i)(~[/\\]\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws[/\\]credentials|\.git-credentials|\betc[/\\]shadow\b|\.npmrc\b|\bprivate\s+key\b|\.env\b)`),
	},
	{
		// Moving data somewhere, with a URL close by.
		RuleExfiltration,
		regexp.MustCompile(`(?i)\b(send|upload|post|forward|transmit|copy|exfiltrat\w*|report)\b[^.!?]{0,60}https?://`),
	},
	{
		// Instructions about *other* tools: the tool-shadowing attack.
		RuleCrossToolInstruction,
		regexp.MustCompile(`(?i)\b(before|instead\s+of|prior\s+to|after)\b[^.!?]{0,20}\b(using|calling|invoking|running)\b[^.!?]{0,40}\b(tool|function)\b`),
	},
}

// invisibleRunes are characters that render as nothing (or reorder text) for a
// human but are read normally by a model. Their presence in a tool description
// has no legitimate explanation.
// They are listed by code point on purpose: source code containing the actual
// characters would be exactly as unreadable as the attack it describes.
var invisibleRunes = map[rune]string{
	rune(0x200B): "zero-width space",
	rune(0x200C): "zero-width non-joiner",
	rune(0x200D): "zero-width joiner",
	rune(0x200E): "left-to-right mark",
	rune(0x200F): "right-to-left mark",
	rune(0x202A): "left-to-right embedding",
	rune(0x202B): "right-to-left embedding",
	rune(0x202C): "pop directional formatting",
	rune(0x202D): "left-to-right override",
	rune(0x202E): "right-to-left override",
	rune(0x2060): "word joiner",
	rune(0x2061): "function application",
	rune(0x2062): "invisible times",
	rune(0x2063): "invisible separator",
	rune(0x2064): "invisible plus",
	rune(0xFEFF): "zero-width no-break space",
}

// maxExcerpt caps how much matched text a finding carries into a log line.
const maxExcerpt = 120

// PoisoningScanner applies the heuristics to advertised tool descriptions.
// It holds no state and is safe for concurrent use.
type PoisoningScanner struct{}

// NewPoisoningScanner returns a scanner using the built-in rule set.
func NewPoisoningScanner() *PoisoningScanner { return &PoisoningScanner{} }

// Scan checks every tool's description and returns what looks suspicious.
//
// The input schema is scanned too: a schema's field names and descriptions
// land in the model's context just as surely as the tool description does.
//
// The two are scanned as separate texts. Joined into one string, the end of a
// description and the start of a schema could form a match neither contains:
// Playwright's "Upload one or multiple files" followed by the schema's
// standard "$schema": "https://json-schema.org/..." read as an upload to a
// URL. Each rule is still reported at most once per tool.
func (s *PoisoningScanner) Scan(tools []ToolDescriptor) []Finding {
	var findings []Finding

	for _, tool := range tools {
		texts := []string{tool.Description, schemaText(tool.InputSchema)}
		reported := map[string]bool{}
		report := func(rule, match string) {
			if reported[rule] {
				return
			}
			reported[rule] = true
			findings = append(findings, Finding{Tool: tool.Name, Rule: rule, Excerpt: match})
		}

		for _, text := range texts {
			if strings.TrimSpace(text) == "" {
				continue
			}
			for _, rule := range patternRules {
				if match := rule.pattern.FindString(text); match != "" {
					report(rule.name, excerpt(match))
				}
			}
			if name, found := firstInvisibleRune(text); found {
				report(RuleInvisibleCharacters, name)
			}
		}
	}

	return findings
}

// schemaMetaKeys are JSON Schema keywords whose values identify the schema
// language or the document, not anything about the tool. Their values are
// URIs by definition, which is exactly what the exfiltration rule looks for.
var schemaMetaKeys = map[string]bool{"$schema": true, "$id": true}

// schemaText renders an input schema for scanning: decoded, so that escaped
// characters are seen as what they are (​ is an invisible character, not
// the six characters "​"), and without the meta keywords above. Field
// names stay in: a parameter name is read by the model too, and is one of the
// places a payload can hide. A schema that is not valid JSON is scanned as
// it arrived.
func schemaText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return string(raw)
	}

	var strip func(v any) any
	strip = func(v any) any {
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				if schemaMetaKeys[k] {
					delete(v, k)
					continue
				}
				v[k] = strip(child)
			}
		case []any:
			for i, child := range v {
				v[i] = strip(child)
			}
		}
		return v
	}

	var b strings.Builder
	enc := json.NewEncoder(&b)
	// Without this, < and > are written as < and >, and markup
	// such as <IMPORTANT> would no longer match.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(strip(decoded)); err != nil {
		return string(raw)
	}
	return b.String()
}

// firstInvisibleRune reports the first invisible character in text, if any.
func firstInvisibleRune(text string) (string, bool) {
	for _, r := range text {
		if name, ok := invisibleRunes[r]; ok {
			return fmt.Sprintf("contains %s (U+%04X)", name, r), true
		}
	}
	return "", false
}

// excerpt normalises whitespace and truncates, so one finding stays on one log
// line.
func excerpt(match string) string {
	flattened := strings.Join(strings.Fields(match), " ")
	if len(flattened) <= maxExcerpt {
		return flattened
	}
	return flattened[:maxExcerpt] + "..."
}
