package interceptor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// The promise mcp-audit makes is that the user does not notice it. ARCHITECTURE.md
// puts a number on that: the added p99 latency on the stdio pipe should stay
// under 5ms. Parsing is the only per-message work on that path — everything
// else (policy, sinks) either runs on a tool call alone or hands off to another
// goroutine — so this is the benchmark that has to hold.

// benchmark payloads, from smallest to largest realistic message.
var (
	benchNotification = []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	benchToolCall = []byte(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts","encoding":"utf-8"}}}`)

	benchToolResult = []byte(`{"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"text","text":"127.0.0.1 localhost\n::1 localhost\n"}],"isError":false}}`)
)

// benchLargeToolList is a tools/list result with 40 tools, which is what a
// well-stocked MCP server actually returns.
var benchLargeToolList = buildToolList(40)

func buildToolList(n int) []byte {
	tools := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		tools = append(tools, map[string]any{
			"name": fmt.Sprintf("tool_%d", i),
			"description": "Does something useful with the given input and returns a result. " +
				strings.Repeat("More description text. ", 8),
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string", "description": "The path to operate on."},
					"count": map[string]any{"type": "number", "description": "How many times."},
				},
				"required": []string{"path"},
			},
		})
	}
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  map[string]any{"tools": tools},
	})
	if err != nil {
		panic(err)
	}
	return payload
}

func BenchmarkParseNotification(b *testing.B) {
	benchmarkParse(b, DirectionRequest, benchNotification)
}

func BenchmarkParseToolCall(b *testing.B) {
	benchmarkParse(b, DirectionRequest, benchToolCall)
}

func BenchmarkParseToolResult(b *testing.B) {
	benchmarkParse(b, DirectionResponse, benchToolResult)
}

func BenchmarkParseLargeToolList(b *testing.B) {
	benchmarkParse(b, DirectionResponse, benchLargeToolList)
}

func benchmarkParse(b *testing.B, direction string, payload []byte) {
	ic := New(Options{ServerName: "bench"})
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := ic.Parse(direction, payload); err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkRequestResponseRoundTrip measures a full exchange: the request is
// parsed and remembered, then the response is parsed and correlated back. This
// is the cost the proxy adds to one tool call.
func BenchmarkRequestResponseRoundTrip(b *testing.B) {
	ic := New(Options{ServerName: "bench"})
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := ic.Parse(DirectionRequest, benchToolCall); err != nil {
			b.Fatalf("Parse error: %v", err)
		}
		if _, err := ic.Parse(DirectionResponse, benchToolResult); err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// TestParseLatencyStaysUnderBudget is the assertion behind the benchmark: it
// measures a realistic message mix and fails if the interceptor starts costing
// real time.
//
// It measures batches rather than individual messages on purpose. One Parse
// call is faster than the operating system clock can resolve — on Windows a
// single sample quantises to a ~1ms tick, which produces a "p99" that measures
// the clock rather than the code. Timing a batch of messages and dividing puts
// the measurement well above the tick, and taking the p99 *across batches*
// still catches a stall: a batch that hit one would carry the cost.
//
// The budget is far tighter than the 5ms in ARCHITECTURE.md. 5ms is the promise
// to the user for the whole pipe; 250µs per message is the line at which we
// would want to know something regressed, with enough headroom that a loaded
// CI machine does not cry wolf.
func TestParseLatencyStaysUnderBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement skipped in short mode")
	}
	if raceEnabled {
		t.Skip("latency measurement is meaningless under -race, which instruments every memory access")
	}

	const (
		batches         = 200
		messagesInBatch = 100
		budget          = 250 * time.Microsecond
	)

	ic := New(Options{ServerName: "bench"})
	payloads := []struct {
		direction string
		payload   []byte
	}{
		{DirectionRequest, benchToolCall},
		{DirectionResponse, benchToolResult},
		{DirectionRequest, benchNotification},
		{DirectionResponse, benchLargeToolList},
	}

	perMessage := make([]time.Duration, 0, batches)
	for b := 0; b < batches; b++ {
		start := time.Now()
		for i := 0; i < messagesInBatch; i++ {
			p := payloads[i%len(payloads)]
			if _, err := ic.Parse(p.direction, p.payload); err != nil {
				t.Fatalf("Parse error: %v", err)
			}
		}
		perMessage = append(perMessage, time.Since(start)/messagesInBatch)
	}

	sort.Slice(perMessage, func(i, j int) bool { return perMessage[i] < perMessage[j] })
	p50 := perMessage[len(perMessage)*50/100]
	p99 := perMessage[len(perMessage)*99/100]
	worst := perMessage[len(perMessage)-1]

	t.Logf("interceptor parse cost over %d messages (%d batches of %d): p50 %s, p99 %s, worst batch %s",
		batches*messagesInBatch, batches, messagesInBatch, p50, p99, worst)

	if p99 > budget {
		t.Errorf("p99 per-message parse cost = %s, want under %s (ARCHITECTURE.md budgets 5ms end to end)",
			p99, budget)
	}
}

// TestCorrelationTableDoesNotLeak guards the other half of the performance
// promise: a long-running proxy must not grow without bound.
func TestCorrelationTableDoesNotLeak(t *testing.T) {
	ic := New(Options{ServerName: "bench", MaxPending: 128})

	for i := 0; i < 100_000; i++ {
		request := []byte(fmt.Sprintf(
			`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"t"}}`, i))
		if _, err := ic.Parse(DirectionRequest, request); err != nil {
			t.Fatalf("Parse error: %v", err)
		}
	}

	ic.mu.Lock()
	pending, order := len(ic.pending), len(ic.order)
	ic.mu.Unlock()

	if pending > 128 || order > 128 {
		t.Errorf("after 100k unanswered requests the table holds %d entries (order %d), want at most 128",
			pending, order)
	}
}
