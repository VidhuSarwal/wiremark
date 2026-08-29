// Package streamer assembles per-(pid,fd) byte streams from the raw Event
// stream and content-sniffs them as HTTP. It deliberately doesn't need
// accept() tracking: it buffers every fd's read/write bytes regardless of
// how the socket was established, and on close tries to parse each side as
// an HTTP request or response, keeping whichever succeeds. Trying both
// directions (not just read=request/write=response) is what lets this work
// for both a traced HTTP server (M3) and a traced Redis client (M4), where
// the roles are reversed.
package streamer

import (
	"bufio"
	"bytes"
	"io"
	"net/http"

	"github.com/vidhu/etracer/internal/collector"
)

// Exchange is a decoded HTTP request/response pair assembled from one
// connection's lifetime. Request and/or Response may be nil if only one
// side parsed as HTTP.
type Exchange struct {
	PID          uint32
	FD           int32
	Request      *http.Request
	RequestBody  []byte
	Response     *http.Response
	ResponseBody []byte
	// Truncated is set if any contributing event's payload was cut short by
	// the capture buffer cap -- the parse may have succeeded on incomplete
	// data (e.g. a short body) rather than failed outright.
	Truncated bool
}

func parseRequest(buf []byte) *http.Request {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	if err != nil {
		return nil
	}
	return req
}

func parseResponse(buf []byte, req *http.Request) *http.Response {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf)), req)
	if err != nil {
		return nil
	}
	return resp
}

func readBody(r io.Reader) []byte {
	body, _ := io.ReadAll(r) // best-effort: a short/incomplete body is kept as-is, not an error
	return body
}

// decode content-sniffs readBuf/writeBuf as HTTP, trying both possible
// role assignments and keeping whichever parses a request. Returns
// ok=false if neither side parsed as anything HTTP-shaped.
func decode(pid uint32, fd int32, readBuf, writeBuf []byte, truncated bool) (Exchange, bool) {
	ex := Exchange{PID: pid, FD: fd, Truncated: truncated}

	req, reqFromRead := parseRequest(readBuf), true
	if req == nil {
		req, reqFromRead = parseRequest(writeBuf), false
	}

	respBuf := writeBuf
	if !reqFromRead {
		respBuf = readBuf
	}
	resp := parseResponse(respBuf, req)

	if req == nil && resp == nil {
		return ex, false
	}

	if req != nil {
		ex.Request = req
		ex.RequestBody = readBody(req.Body)
	}
	if resp != nil {
		ex.Response = resp
		ex.ResponseBody = readBody(resp.Body)
	}
	return ex, true
}

// bufCap bounds memory per connection per direction; bytes beyond this are
// dropped (Exchange.Truncated reflects this via the underlying events'
// Truncated() flag, not this cap directly -- see appendCapped).
const bufCap = 64 * 1024

type key struct {
	pid uint32
	fd  int32
}

type connBufs struct {
	read, write []byte
	truncated   bool
}

func appendCapped(dst *[]byte, add []byte) {
	room := bufCap - len(*dst)
	if room <= 0 {
		return
	}
	if len(add) > room {
		add = add[:room]
	}
	*dst = append(*dst, add...)
}

// Run consumes events (becoming its sole receiver) and returns two
// channels: rawOut passes every event through unchanged, and exchanges
// emits a decoded Exchange each time a connection with HTTP-shaped traffic
// closes. Both channels close when events closes.
func Run(events <-chan collector.Event) (rawOut <-chan collector.Event, exchanges <-chan Exchange) {
	raw := make(chan collector.Event, 64)
	out := make(chan Exchange, 16)

	go func() {
		defer close(raw)
		defer close(out)

		bufs := make(map[key]*connBufs)

		get := func(k key) *connBufs {
			b := bufs[k]
			if b == nil {
				b = &connBufs{}
				bufs[k] = b
			}
			return b
		}

		for ev := range events {
			raw <- ev

			k := key{pid: ev.PID, fd: ev.FD}
			switch ev.Operation {
			case collector.OpRead:
				b := get(k)
				appendCapped(&b.read, ev.Payload())
				b.truncated = b.truncated || ev.Truncated()
			case collector.OpWrite:
				b := get(k)
				appendCapped(&b.write, ev.Payload())
				b.truncated = b.truncated || ev.Truncated()
			case collector.OpClose:
				if b, ok := bufs[k]; ok {
					if ex, ok := decode(ev.PID, ev.FD, b.read, b.write, b.truncated); ok {
						out <- ex
					}
					delete(bufs, k)
				}
			}
		}
	}()

	return raw, out
}
