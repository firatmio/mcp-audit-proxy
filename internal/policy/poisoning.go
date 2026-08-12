package policy

import (
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
// The input schema is scanned too: a schema's field descriptions land in the
// model's context just as surely as the tool description does.
func (s *PoisoningScanner) Scan(tools []ToolDescriptor) []Finding {
	var findings []Finding

	for _, tool := range tools {
		text := tool.Description
		if len(tool.InputSchema) > 0 {
			text += "\n" + string(tool.InputSchema)
		}
		if strings.TrimSpace(text) == "" {
			continue
		}

		for _, rule := range patternRules {
			if match := rule.pattern.FindString(text); match != "" {
				findings = append(findings, Finding{
					Tool:    tool.Name,
					Rule:    rule.name,
					Excerpt: excerpt(match),
				})
			}
		}

		if name, found := firstInvisibleRune(text); found {
			findings = append(findings, Finding{
				Tool:    tool.Name,
				Rule:    RuleInvisibleCharacters,
				Excerpt: name,
			})
		}
	}

	return findings
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
