// Command corpus-capture records the tools a real MCP server advertises, for
// the benign half of the detection corpus.
//
//	go run ./scripts/corpus-capture -out testdata/corpus/benign/server-memory.json \
//	    -package @modelcontextprotocol/server-memory@2.0.0 -license MIT \
//	    -repository https://github.com/modelcontextprotocol/servers \
//	    -- npx -y @modelcontextprotocol/server-memory@2.0.0
//
// It starts the server, performs the MCP handshake over stdio, pages through
// tools/list, and writes the tool names, descriptions and input schemas. The
// false-positive rate is only worth reporting if it is measured on descriptions
// people actually ship, so the benign set is captured rather than written.
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

func main() {
	out := flag.String("out", "", "file to write (required)")
	pkg := flag.String("package", "", "package and version, for attribution (required)")
	license := flag.String("license", "", "SPDX licence of the package (required)")
	repo := flag.String("repository", "", "source repository URL")
	server := flag.String("server", "", "server name; defaults to the output file name")
	timeout := flag.Duration("timeout", 3*time.Minute, "give up after this long (first runs download packages)")
	flag.Parse()

	command := flag.Args()
	if *out == "" || *pkg == "" || *license == "" || len(command) == 0 {
		fmt.Fprintln(os.Stderr, "usage: corpus-capture -out FILE -package PKG@VER -license SPDX [-repository URL] -- <server command...>")
		os.Exit(2)
	}
	if *server == "" {
		base := (*out)[strings.LastIndexAny(*out, `/\`)+1:]
		*server = strings.TrimSuffix(base, ".json")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	tools, err := capture(ctx, command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus-capture: %v\n", err)
		os.Exit(1)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	set := benignSet{
		Server: *server, Package: *pkg, License: *license, Repository: *repo,
		Captured: time.Now().UTC().Format("2006-01-02"),
		Command:  command, Tools: tools,
	}
	encoded, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpus-capture: %v\n", err)
		os.Exit(1)
	}
	// LF line endings on every platform, so a capture made on Windows does not
	// show up as a whole-file diff on Linux.
	if err := os.WriteFile(*out, append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "corpus-capture: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s: %d tools -> %s\n", *server, len(tools), *out)
}

// capture runs the handshake and collects every page of tools/list.
func capture(ctx context.Context, command []string) ([]tool, error) {
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
	defer func() {
		stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 0, 1<<20), 64<<20)

	send := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = stdin.Write(append(b, '\n'))
		return err
	}
	// await reads until the response with the given id; servers may log or
	// send notifications in between.
	await := func(id int) (json.RawMessage, error) {
		for lines.Scan() {
			var msg struct {
				ID     *int            `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if json.Unmarshal(lines.Bytes(), &msg) != nil || msg.ID == nil || *msg.ID != id {
				continue
			}
			if len(msg.Error) > 0 {
				return nil, fmt.Errorf("request %d failed: %s", id, msg.Error)
			}
			return msg.Result, nil
		}
		if err := lines.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("the server closed its output before answering")
	}

	if err := send(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "mcp-audit-corpus-capture", "version": "1"},
		},
	}); err != nil {
		return nil, err
	}
	if _, err := await(1); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	if err := send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return nil, err
	}

	var all []tool
	cursor := ""
	for id := 2; ; id++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		if err := send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params}); err != nil {
			return nil, err
		}
		raw, err := await(id)
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
