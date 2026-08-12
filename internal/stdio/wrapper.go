// Package stdio wraps a local MCP server process and audits the
// newline-delimited JSON-RPC traffic flowing over its stdin and stdout.
//
// Transparency is the contract: every byte the client sends reaches the server
// unchanged, and every byte the server sends reaches the client unchanged. The
// only exception is a tool call the policy engine refuses, which is answered
// with a JSON-RPC error instead of being forwarded.
package stdio

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/firatmio/mcp-audit-proxy/internal/interceptor"
	"github.com/firatmio/mcp-audit-proxy/internal/policy"
	"github.com/firatmio/mcp-audit-proxy/internal/sinks"
)

// maxParseBytes caps the size of a message we will attempt to parse. Anything
// larger is forwarded untouched and logged, because holding up an MCP session
// to parse a 32 MB blob helps nobody.
const maxParseBytes = 8 << 20 // 8 MiB

// readBufferSize is the initial per-direction read buffer. Messages larger than
// this still work; the buffer simply grows.
const readBufferSize = 64 << 10

// Wrapper runs an MCP server as a child process with its stdio piped through
// the audit pipeline.
type Wrapper struct {
	// Command and Args are the MCP server to run.
	Command string
	Args    []string

	// Interceptor, Policy and Dispatcher form the audit pipeline. All three
	// are required.
	Interceptor *interceptor.Interceptor
	Policy      *policy.Engine
	Dispatcher  *sinks.Dispatcher

	// Logger receives proxy diagnostics. It must not write to Out: on stdio
	// that stream belongs to the MCP protocol. Defaults to stderr.
	Logger *log.Logger

	// In, Out and ServerErr default to the process's own stdio. In carries
	// client-to-server traffic, Out carries server-to-client traffic, and
	// ServerErr receives the child's stderr verbatim.
	In        io.Reader
	Out       io.Writer
	ServerErr io.Writer

	// Env is the child's environment. Nil means inherit ours.
	Env []string
}

// Run starts the child process and pumps traffic until either side closes.
// It returns the child's exit code.
func (w *Wrapper) Run(ctx context.Context) (int, error) {
	if w.Command == "" {
		return 1, errors.New("no MCP server command given; usage: mcp-audit run -- <command> [args...]")
	}
	if w.Interceptor == nil || w.Policy == nil || w.Dispatcher == nil {
		return 1, errors.New("stdio wrapper is missing its audit pipeline")
	}

	in := w.In
	if in == nil {
		in = os.Stdin
	}
	out := w.Out
	if out == nil {
		out = os.Stdout
	}
	serverErr := w.ServerErr
	if serverErr == nil {
		serverErr = os.Stderr
	}
	logger := w.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "mcp-audit: ", 0)
	}

	cmd := exec.CommandContext(ctx, w.Command, w.Args...)
	cmd.Stderr = serverErr
	cmd.Env = w.Env

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("cannot open a pipe to the MCP server's stdin: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("cannot open a pipe from the MCP server's stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("cannot start MCP server %q: %w", w.Command, err)
	}

	// Out is written by both pumps: responses from the server, and policy
	// denials generated here. Serialise them.
	clientOut := &syncWriter{w: out}

	// The request pump is deliberately not waited on. A read of the client's
	// stdin can block forever, so if the server dies first we must not hang
	// waiting for a client message that will never come. Closing the server's
	// stdin is what tells a well-behaved MCP server the client has gone away.
	go func() {
		defer serverIn.Close()
		if err := w.pumpToServer(in, serverIn, clientOut, logger); err != nil {
			logger.Printf("client-to-server stream ended: %v", err)
		}
	}()

	// The response pump ends when the server closes its stdout, which is the
	// signal that the session is over.
	responses := make(chan error, 1)
	go func() {
		responses <- w.pumpToClient(serverOut, clientOut, logger)
	}()

	if err := <-responses; err != nil {
		logger.Printf("server-to-client stream ended: %v", err)
	}
	waitErr := cmd.Wait()

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return 1, fmt.Errorf("MCP server %q failed: %w", w.Command, waitErr)
		}
	}
	return exitCode, nil
}

// pumpToServer forwards client requests, auditing each one and refusing the
// ones policy blocks.
func (w *Wrapper) pumpToServer(src io.Reader, dst io.Writer, clientOut io.Writer, logger *log.Logger) error {
	reader := bufio.NewReaderSize(src, readBufferSize)
	for {
		line, readErr := readMessage(reader)
		if len(line) > 0 {
			if err := w.handleRequest(line, dst, clientOut, logger); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

// handleRequest audits one client message and either forwards it or answers it
// with a policy denial.
func (w *Wrapper) handleRequest(line []byte, dst, clientOut io.Writer, logger *log.Logger) error {
	events := w.parse(interceptor.DirectionRequest, line, logger)

	// Policy runs before forwarding so a denial actually prevents the call.
	// Batches are audited but never blocked: they carry several ids and the
	// current MCP spec no longer uses them, so a partial refusal would be
	// more surprising than useful.
	if len(events) == 1 && !interceptor.IsBatch(line) {
		if decision := w.Policy.Evaluate(&events[0]); !decision.Allowed {
			w.Dispatcher.DispatchAll(events)
			return w.denyRequest(line, decision, clientOut, logger)
		}
	} else {
		for i := range events {
			if decision := w.Policy.Evaluate(&events[i]); !decision.Allowed {
				logger.Printf("policy would have blocked %q inside a JSON-RPC batch, forwarding anyway: %s",
					events[i].ToolName, decision.Reason)
			}
		}
	}

	if _, err := dst.Write(line); err != nil {
		return fmt.Errorf("cannot forward request to the MCP server: %w", err)
	}
	w.Dispatcher.DispatchAll(events)
	return nil
}

// denyRequest answers a blocked call with a JSON-RPC error instead of passing
// it to the server.
func (w *Wrapper) denyRequest(line []byte, decision policy.Decision, clientOut io.Writer, logger *log.Logger) error {
	logger.Printf("blocked: %s", decision.Reason)

	id := interceptor.RequestID(line)
	if id == nil {
		// A notification gets no reply, so dropping it is the whole of the
		// enforcement we can do.
		return nil
	}

	response, err := interceptor.NewErrorResponse(id, interceptor.CodePolicyDenied,
		"blocked by mcp-audit policy: "+decision.Reason)
	if err != nil {
		return fmt.Errorf("cannot build the policy denial response: %w", err)
	}
	if _, err := clientOut.Write(append(response, '\n')); err != nil {
		return fmt.Errorf("cannot send the policy denial to the client: %w", err)
	}
	return nil
}

// pumpToClient forwards server responses, auditing each one.
func (w *Wrapper) pumpToClient(src io.Reader, dst io.Writer, logger *log.Logger) error {
	reader := bufio.NewReaderSize(src, readBufferSize)
	for {
		line, readErr := readMessage(reader)
		if len(line) > 0 {
			// Responses are never blocked, so forward first and audit after:
			// the client sees the result with no added round trip.
			if _, err := dst.Write(line); err != nil {
				return fmt.Errorf("cannot forward response to the client: %w", err)
			}

			events := w.parse(interceptor.DirectionResponse, line, logger)
			// Responses still go through the policy engine: that is where a
			// tools/list result gets checked for rug pulls and poisoned
			// descriptions. The decision is ignored on purpose — the message
			// has already been forwarded, and the point is the flags the
			// engine records on the event.
			for i := range events {
				w.Policy.Evaluate(&events[i])
			}
			w.Dispatcher.DispatchAll(events)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

// parse runs the interceptor and turns any parse failure into a log line. A
// message we cannot understand is still forwarded — auditing must never break
// a working MCP session.
func (w *Wrapper) parse(direction string, line []byte, logger *log.Logger) []interceptor.ToolCallEvent {
	if len(line) > maxParseBytes {
		logger.Printf("skipping audit of a %d byte %s message (over the %d byte parse limit)",
			len(line), direction, maxParseBytes)
		return nil
	}
	events, err := w.Interceptor.Parse(direction, line)
	if err != nil && !errors.Is(err, interceptor.ErrEmptyMessage) {
		logger.Printf("could not audit a %s message, forwarding it unchanged: %v", direction, err)
	}
	return events
}

// readMessage reads one newline-delimited message, keeping the terminator so
// the bytes can be forwarded exactly as they arrived. A final message without
// a trailing newline is returned along with io.EOF.
func readMessage(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	return line, err
}

// syncWriter serialises writes from the response pump and the denial path.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
