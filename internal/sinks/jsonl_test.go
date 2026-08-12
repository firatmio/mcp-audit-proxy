package sinks

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
)

func testEvent(tool string) interceptor.ToolCallEvent {
	return interceptor.ToolCallEvent{
		Timestamp:  time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC),
		EventID:    interceptor.NewEventID(),
		ServerName: "dummy",
		Direction:  interceptor.DirectionRequest,
		Method:     interceptor.MethodToolsCall,
		ToolName:   tool,
		Arguments:  json.RawMessage(`{"path":"/tmp/x"}`),
	}
}

// readLines returns the non-empty lines of a file.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("cannot open %s: %v", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			lines = append(lines, scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	return lines
}

func TestJSONLWritesOneLinePerEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}

	for _, tool := range []string{"read_file", "list_users"} {
		if err := sink.Write(context.Background(), testEvent(tool)); err != nil {
			t.Fatalf("Write error = %v", err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("wrote %d lines, want 2", len(lines))
	}
	var decoded interceptor.ToolCallEvent
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if decoded.ToolName != "read_file" {
		t.Errorf("tool_name = %q, want read_file", decoded.ToolName)
	}
}

func TestJSONLCreatesMissingDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deep", "nested", "events.jsonl")

	sink, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v, it must create parent directories", err)
	}
	defer sink.Close()

	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("parent directory was not created: %v", err)
	}
}

func TestJSONLAppendsToAnExistingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")

	first, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}
	if err := first.Write(context.Background(), testEvent("a")); err != nil {
		t.Fatalf("Write error = %v", err)
	}
	first.Close()

	second, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("reopening error = %v", err)
	}
	if err := second.Write(context.Background(), testEvent("b")); err != nil {
		t.Fatalf("Write error = %v", err)
	}
	second.Close()

	if lines := readLines(t, path); len(lines) != 2 {
		t.Errorf("log has %d lines, want 2; reopening must append, not truncate", len(lines))
	}
}

func TestJSONLExpandsHomePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows

	sink, err := NewJSONL("~/.mcp-audit/logs/events.jsonl")
	if err != nil {
		t.Fatalf("NewJSONL(~) error = %v", err)
	}
	defer sink.Close()

	want := filepath.Join(home, ".mcp-audit", "logs", "events.jsonl")
	if sink.Path() != want {
		t.Errorf("Path() = %q, want %q", sink.Path(), want)
	}
}

func TestJSONLConcurrentWritesDoNotInterleave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sink.Write(context.Background(), testEvent("concurrent")); err != nil {
				t.Errorf("Write error = %v", err)
			}
		}()
	}
	wg.Wait()
	sink.Close()

	lines := readLines(t, path)
	if len(lines) != 50 {
		t.Fatalf("wrote %d lines, want 50", len(lines))
	}
	for i, line := range lines {
		var ev interceptor.ToolCallEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d is not valid JSON (writes interleaved): %v", i+1, err)
		}
	}
}

func TestJSONLWriteAfterCloseIsAnError(t *testing.T) {
	sink, err := NewJSONL(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}
	sink.Close()

	if err := sink.Write(context.Background(), testEvent("x")); err == nil {
		t.Error("Write after Close error = nil, want an error rather than a silent drop")
	}
}

func TestNewJSONLReportsAnUnusableePath(t *testing.T) {
	// A path whose parent is an existing file cannot become a directory.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("cannot write blocker file: %v", err)
	}

	if _, err := NewJSONL(filepath.Join(blocker, "events.jsonl")); err == nil {
		t.Fatal("NewJSONL error = nil, an unusable audit log path must fail at startup")
	}
}

// failingSink records what it was asked to write and always errors.
type failingSink struct {
	mu    sync.Mutex
	calls int
}

func (f *failingSink) Name() string { return "failing" }

func (f *failingSink) Write(context.Context, interceptor.ToolCallEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return errors.New("network is down")
}

// blockingSink never returns from Write until released, so an optional sink can
// be made to fall behind on purpose.
type blockingSink struct {
	release chan struct{}
	seen    chan struct{}
}

func newBlockingSink() *blockingSink {
	return &blockingSink{release: make(chan struct{}), seen: make(chan struct{}, 1)}
}

func (b *blockingSink) Name() string { return "blocking" }

func (b *blockingSink) Write(context.Context, interceptor.ToolCallEvent) error {
	select {
	case b.seen <- struct{}{}:
	default:
	}
	<-b.release
	return nil
}

func TestDispatcherDeliversToEverySink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	jsonl, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}
	failing := &failingSink{}

	d := NewDispatcher(log.New(os.Stderr, "", 0))
	d.Add(jsonl, true)
	d.Add(failing, false)

	for i := 0; i < 5; i++ {
		d.Dispatch(testEvent("read_file"))
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	if lines := readLines(t, path); len(lines) != 5 {
		t.Errorf("jsonl has %d lines, want 5", len(lines))
	}
	failing.mu.Lock()
	calls := failing.calls
	failing.mu.Unlock()
	if calls != 5 {
		t.Errorf("optional sink saw %d events, want 5", calls)
	}
	if stat := d.Stats()["failing"]; stat.Failed != 5 {
		t.Errorf("Stats()[failing].Failed = %d, want 5", stat.Failed)
	}
}

func TestFailingSinkDoesNotStopTheLocalLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	jsonl, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}

	d := NewDispatcher(nil)
	d.Add(&failingSink{}, false)
	d.Add(jsonl, true)

	d.Dispatch(testEvent("still_logged"))
	d.Close()

	lines := readLines(t, path)
	if len(lines) != 1 || !strings.Contains(lines[0], "still_logged") {
		t.Errorf("local log = %v, want the event despite the other sink failing", lines)
	}
}

func TestSlowOptionalSinkDropsInsteadOfBlocking(t *testing.T) {
	blocking := newBlockingSink()
	d := NewDispatcher(nil)
	d.Add(blocking, false)

	// Wait until the worker is stuck inside Write, then overflow the queue.
	d.Dispatch(testEvent("first"))
	select {
	case <-blocking.seen:
	case <-time.After(2 * time.Second):
		t.Fatal("the sink worker never started")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < defaultQueueSize+100; i++ {
			d.Dispatch(testEvent("overflow"))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Dispatch blocked on a stalled optional sink; it must drop instead")
	}

	if dropped := d.Stats()["blocking"].Dropped; dropped == 0 {
		t.Error("Stats().Dropped = 0, want the overflow to be counted")
	}

	close(blocking.release)
	d.Close()
}

func TestDispatchConcurrentWithCloseDoesNotPanic(t *testing.T) {
	// The dangerous interleaving, which the "after Close" test below does not
	// reach: Dispatch passes its shutdown check, Close runs, and only then
	// does Dispatch reach the queue. In stdio mode the request pump is
	// deliberately not waited on, so it really can still be dispatching while
	// main is shutting the dispatcher down.
	for attempt := 0; attempt < 50; attempt++ {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		jsonl, err := NewJSONL(path)
		if err != nil {
			t.Fatalf("NewJSONL error = %v", err)
		}

		d := NewDispatcher(nil)
		d.Add(jsonl, true)
		d.Add(&failingSink{}, false)

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for j := 0; j < 50; j++ {
					d.Dispatch(testEvent("racing"))
				}
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d.Close()
		}()

		close(start)
		wg.Wait() // a panic here fails the test by crashing it
		d.Close()
	}
}

func TestDispatchAfterCloseIsSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	jsonl, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}

	d := NewDispatcher(nil)
	d.Add(jsonl, true)
	d.Close()

	// Must not panic on a send to a closed channel.
	d.Dispatch(testEvent("after_close"))

	if err := d.Close(); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
}

func TestDispatchAllQueuesEveryEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	jsonl, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL error = %v", err)
	}

	d := NewDispatcher(nil)
	d.Add(jsonl, true)
	d.DispatchAll([]interceptor.ToolCallEvent{testEvent("a"), testEvent("b"), testEvent("c")})
	d.Close()

	if lines := readLines(t, path); len(lines) != 3 {
		t.Errorf("log has %d lines, want 3", len(lines))
	}
}
