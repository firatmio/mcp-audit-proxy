package httpproxy

import (
	"bytes"
	"io"
)

// tapMode selects how a response body is interpreted while it streams past.
type tapMode int

const (
	// tapJSON accumulates the whole body and parses it once, at EOF. Used for
	// the `application/json` replies of a plain Streamable HTTP POST.
	tapJSON tapMode = iota
	// tapSSE scans `data:` lines as they arrive. Used for `text/event-stream`,
	// where responses trickle in over a long-lived connection and must not be
	// held back until the stream closes.
	tapSSE
)

// bodyTap wraps a response body and hands each complete JSON-RPC payload to
// onMessage as the client reads it.
//
// It taps the stream inline rather than through an io.Pipe: a pipe would let a
// stalled reader on our side block the bytes going to the client, and auditing
// must never be able to stall the proxied traffic.
type bodyTap struct {
	rc        io.ReadCloser
	mode      tapMode
	limit     int
	onMessage func([]byte)

	buf       bytes.Buffer
	truncated bool
	finished  bool
}

// newBodyTap wraps rc. limit caps how much is buffered; past it the tap stops
// auditing that body but keeps streaming it untouched.
func newBodyTap(rc io.ReadCloser, mode tapMode, limit int, onMessage func([]byte)) *bodyTap {
	return &bodyTap{rc: rc, mode: mode, limit: limit, onMessage: onMessage}
}

// Read implements io.Reader, passing every byte through unchanged.
func (t *bodyTap) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.consume(p[:n])
	}
	if err == io.EOF {
		t.finish()
	}
	return n, err
}

// Close flushes whatever the tap has seen and closes the wrapped body.
func (t *bodyTap) Close() error {
	t.finish()
	return t.rc.Close()
}

// consume feeds newly read bytes into the tap's buffer.
func (t *bodyTap) consume(chunk []byte) {
	if t.truncated {
		return
	}
	if t.buf.Len()+len(chunk) > t.limit {
		t.truncated = true
		t.buf.Reset()
		return
	}
	t.buf.Write(chunk)

	if t.mode == tapSSE {
		t.drainSSELines()
	}
}

// drainSSELines emits every complete SSE data line currently buffered.
func (t *bodyTap) drainSSELines() {
	for {
		idx := bytes.IndexByte(t.buf.Bytes(), '\n')
		if idx < 0 {
			return
		}
		line := make([]byte, idx+1)
		_, _ = t.buf.Read(line)

		payload := bytes.TrimSpace(line)
		if !bytes.HasPrefix(payload, []byte("data:")) {
			continue
		}
		payload = bytes.TrimSpace(payload[len("data:"):])
		if len(payload) == 0 {
			continue
		}
		t.onMessage(payload)
	}
}

// finish emits whatever remains once the body ends. It is idempotent because
// both Read (on EOF) and Close can reach it.
func (t *bodyTap) finish() {
	if t.finished {
		return
	}
	t.finished = true
	if t.truncated || t.buf.Len() == 0 {
		return
	}

	if t.mode == tapSSE {
		// A last line without its terminating newline.
		payload := bytes.TrimSpace(t.buf.Bytes())
		if bytes.HasPrefix(payload, []byte("data:")) {
			payload = bytes.TrimSpace(payload[len("data:"):])
			if len(payload) > 0 {
				t.onMessage(payload)
			}
		}
		t.buf.Reset()
		return
	}

	t.onMessage(bytes.TrimSpace(t.buf.Bytes()))
	t.buf.Reset()
}

// Truncated reports whether the body outgrew the audit limit.
func (t *bodyTap) Truncated() bool { return t.truncated }
