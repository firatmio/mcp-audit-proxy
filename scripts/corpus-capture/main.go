// Command corpus-capture records what a real MCP server advertises, and
// optionally what its tools return, for the benign half of the corpus.
//
// Tool lists:
//
//	go run ./scripts/corpus-capture -out testdata/corpus/benign/server-memory.json \
//	    -package @modelcontextprotocol/server-memory@2.0.0 -license MIT \
//	    -repository https://github.com/modelcontextprotocol/servers \
//	    -- npx -y @modelcontextprotocol/server-memory@2.0.0
//
// Tool results: add -calls FILE, a JSON array of {"tool": ..., "arguments": {...}}
// objects. Each call is made in order and its result (or error) recorded; the
// output then holds calls instead of tools. -redact PATH replaces a local path
// with <root> everywhere in the output, and the capture refuses to write a file
// that still contains the home directory.
//
// False-positive rates are only worth reporting if they are measured on what
// servers actually produce, so the benign corpus is captured rather than
// written.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type benignSet struct {
	Server     string   `json:"server"`
	Package    string   `json:"package"`
	License    string   `json:"license"`
	Repository string   `json:"repository"`
	Captured   string   `json:"captured"`
	Command    []string `json:"command"`
	Tools      []tool   `json:"tools"`
}

type call struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

type recordedCall struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     json.RawMessage `json:"error,omitempty"`
}

// content describes the data the calls read, which usually has an owner and a
// licence of its own, separate from the server's.
type content struct {
	Description string `json:"description"`
	Source      string `json:"source"`
	License     string `json:"license"`
}

type resultSet struct {
	Server     string         `json:"server"`
	Package    string         `json:"package"`
	License    string         `json:"license"`
	Repository string         `json:"repository"`
	Captured   string         `json:"captured"`
	Command    []string       `json:"command"`
	Content    *content       `json:"content,omitempty"`
	Calls      []recordedCall `json:"calls"`
}

func main() {
	out := flag.String("out", "", "file to write (required)")
	pkg := flag.String("package", "", "package and version, for attribution (required)")
	license := flag.String("license", "", "SPDX licence of the package (required)")
	repo := flag.String("repository", "", "source repository URL")
	server := flag.String("server", "", "server name; defaults to the output file name")
	callsFile := flag.String("calls", "", "JSON file of tool calls to make and record")
	redact := flag.String("redact", "", "local path to replace with <root> in the output")
	contentDesc := flag.String("content-description", "", "what the calls read")
	contentSource := flag.String("content-source", "", "where that content comes from")
	contentLicense := flag.String("content-license", "", "licence of that content")
	timeout := flag.Duration("timeout", 3*time.Minute, "give up after this long (first runs download packages)")
	flag.Parse()

	command := flag.Args()
	if *out == "" || *pkg == "" || *license == "" || len(command) == 0 {
		fmt.Fprintln(os.Stderr, "usage: corpus-capture -out FILE -package PKG@VER -license SPDX [-repository URL] [-calls FILE] -- <server command...>")
		os.Exit(2)
	}
	if *server == "" {
		base := (*out)[strings.LastIndexAny(*out, `/\`)+1:]
		*server = strings.TrimSuffix(base, ".json")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	sess, err := start(ctx, command)
	if err != nil {
		fail(err)
	}
	defer sess.close()

	captured := time.Now().UTC().Format("2006-01-02")
	var output any
	var summary string

	if *callsFile == "" {
		tools, err := sess.listTools()
		if err != nil {
			fail(err)
		}
		sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
		output = benignSet{
			Server: *server, Package: *pkg, License: *license, Repository: *repo,
			Captured: captured, Command: command, Tools: tools,
		}
		summary = fmt.Sprintf("%d tools", len(tools))
	} else {
		raw, err := os.ReadFile(*callsFile)
		if err != nil {
			fail(err)
		}
		var calls []call
		if err := json.Unmarshal(raw, &calls); err != nil {
			fail(fmt.Errorf("%s: %w", *callsFile, err))
		}
		set := resultSet{
			Server: *server, Package: *pkg, License: *license, Repository: *repo,
			Captured: captured, Command: command,
		}
		if *contentDesc != "" || *contentSource != "" || *contentLicense != "" {
			set.Content = &content{Description: *contentDesc, Source: *contentSource, License: *contentLicense}
		}
		for _, c := range calls {
			rec, err := sess.callTool(c)
			if err != nil {
				fail(fmt.Errorf("calling %s: %w", c.Tool, err))
			}
			set.Calls = append(set.Calls, rec)
		}
		output = set
		summary = fmt.Sprintf("%d calls", len(set.Calls))
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fail(err)
	}
	text := string(encoded)
	if *redact != "" {
		text = redactPath(text, *redact)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		for _, form := range pathForms(home) {
			if strings.Contains(text, form) {
				fail(fmt.Errorf("the output still contains the home directory %s; pass -redact", home))
			}
		}
	}

	// LF line endings on every platform, so a capture made on Windows does not
	// show up as a whole-file diff on Linux.
	if err := os.WriteFile(*out, []byte(text+"\n"), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("%s: %s -> %s\n", *server, summary, *out)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "corpus-capture: %v\n", err)
	os.Exit(1)
}

// pathForms lists the spellings a path can take inside JSON output: as given,
// with forward slashes, and with JSON-escaped backslashes.
func pathForms(p string) []string {
	p = filepath.Clean(p)
	forward := strings.ReplaceAll(p, `\`, "/")
	escaped := strings.ReplaceAll(strings.ReplaceAll(p, "/", `\`), `\`, `\\`)
	forms := []string{escaped, forward, p}
	// Longest first, so a longer spelling is not half-replaced by a shorter one.
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return forms
}

func redactPath(text, p string) string {
	for _, form := range pathForms(p) {
		text = strings.ReplaceAll(text, form, "<root>")
	}
	return text
}

// session is one running server with a completed handshake.
type session struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  *bufio.Scanner
	nextID int
}

func start(ctx context.Context, command []string) (*session, error) {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start %q: %w", command[0], err)
	}

	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 0, 1<<20), 64<<20)
	s := &session{cmd: cmd, stdin: stdin, lines: lines, nextID: 1}

	if _, err := s.request("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcp-audit-corpus-capture", "version": "1"},
	}); err != nil {
		s.close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	if err := s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *session) close() {
	s.stdin.Close()
	_ = s.cmd.Process.Kill()
	_ = s.cmd.Wait()
}

func (s *session) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.stdin.Write(append(b, '\n'))
	return err
}

// rpcError is a JSON-RPC error object, kept raw for the record.
type rpcError struct{ raw json.RawMessage }

func (e *rpcError) Error() string { return "server returned an error: " + string(e.raw) }

// request sends a request and waits for its response. Servers may log or send
// notifications in between; those are skipped.
func (s *session) request(method string, params any) (json.RawMessage, error) {
	id := s.nextID
	s.nextID++
	if err := s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for s.lines.Scan() {
		var msg struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(s.lines.Bytes(), &msg) != nil || msg.ID == nil || *msg.ID != id {
			continue
		}
		if len(msg.Error) > 0 {
			return nil, &rpcError{raw: msg.Error}
		}
		return msg.Result, nil
	}
	if err := s.lines.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("the server closed its output before answering")
}

// listTools pages through tools/list.
func (s *session) listTools() ([]tool, error) {
	var all []tool
	cursor := ""
	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := s.request("tools/list", params)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		var page struct {
			Tools      []tool `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("tools/list result: %w", err)
		}
		all = append(all, page.Tools...)
		if page.NextCursor == "" {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

// callTool makes one tools/call and records its result, or its JSON-RPC
// error: an error a server really returns is as much a part of the benign
// corpus as a success.
func (s *session) callTool(c call) (recordedCall, error) {
	args := c.Arguments
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	rec := recordedCall{Tool: c.Tool, Arguments: args}
	raw, err := s.request("tools/call", map[string]any{"name": c.Tool, "arguments": args})
	var rpcErr *rpcError
	switch {
	case errors.As(err, &rpcErr):
		rec.Error = rpcErr.raw
	case err != nil:
		return rec, err
	default:
		rec.Result = raw
	}
	return rec, nil
}
