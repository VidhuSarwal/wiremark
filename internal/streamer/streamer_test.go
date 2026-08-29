package streamer

import (
	"strconv"
	"strings"
	"testing"

	"github.com/vidhu/etracer/internal/collector"
)

// These are the literal byte strings captured from a live trace of
// examples/go-http-app (see the M3 capture-fidelity commit): a real
// GET /medium request and its 1533-byte JSON response. This is the gate for
// the whole milestone -- if decode() can't parse actual captured bytes,
// nothing built on top of it matters.
const capturedRequest = "GET /medium HTTP/1.1\r\nHost: 127.0.0.1:18099\r\nUser-Agent: curl/8.18.0\r\nAccept: */*\r\n\r\n"

// capturedBody mirrors examples/go-http-app's /medium handler exactly
// (bio: strings.Repeat("y", 1500)) so its length is derived, not guessed.
var capturedBody = `{"id":42,"name":"Alice","bio":"` + strings.Repeat("y", 1500) + `"}`

var capturedResponse = "HTTP/1.1 200 OK\r\nDate: Sat, 29 Aug 2026 18:25:02 GMT\r\n" +
	"Content-Length: " + strconv.Itoa(len(capturedBody)) + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
	capturedBody

func TestDecodeRealCapturedBytesServerRole(t *testing.T) {
	ex, ok := decode(42, 5, []byte(capturedRequest), []byte(capturedResponse), false)
	if !ok {
		t.Fatal("decode() failed to recognize real captured HTTP bytes")
	}
	if ex.Request == nil {
		t.Fatal("Request is nil")
	}
	if ex.Request.Method != "GET" || ex.Request.URL.Path != "/medium" {
		t.Errorf("Request = %s %s, want GET /medium", ex.Request.Method, ex.Request.URL.Path)
	}
	if ex.Response == nil {
		t.Fatal("Response is nil")
	}
	if ex.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", ex.Response.StatusCode)
	}
	if len(ex.ResponseBody) != len(capturedBody) {
		t.Errorf("ResponseBody length = %d, want %d", len(ex.ResponseBody), len(capturedBody))
	}
}

// TestDecodeClientRole is the M4-facing case: the traced process is the
// client, so it *writes* the request and *reads* the response -- the
// opposite of the server role above. decode() must try both directions.
func TestDecodeClientRole(t *testing.T) {
	ex, ok := decode(42, 5, []byte(capturedResponse), []byte(capturedRequest), false)
	if !ok {
		t.Fatal("decode() failed on the client-role byte assignment (write=request, read=response)")
	}
	if ex.Request == nil || ex.Request.Method != "GET" {
		t.Error("Request not recovered from the write-side buffer")
	}
	if ex.Response == nil || ex.Response.StatusCode != 200 {
		t.Error("Response not recovered from the read-side buffer")
	}
}

func TestDecodeNonHTTPBytesFails(t *testing.T) {
	_, ok := decode(1, 1, []byte("not http\r\n\r\n"), []byte("also not http"), false)
	if ok {
		t.Fatal("decode() should not recognize non-HTTP bytes")
	}
}

func TestAppendCappedStopsAtBufCap(t *testing.T) {
	chunk := make([]byte, 4096)
	var dst []byte
	for i := 0; i < 20; i++ { // 20*4096 = 81920 > bufCap (65536)
		appendCapped(&dst, chunk)
	}
	if len(dst) != bufCap {
		t.Fatalf("len(dst) = %d, want capped at %d", len(dst), bufCap)
	}
}

func TestAppendCappedKeepsBytesBelowCap(t *testing.T) {
	var dst []byte
	appendCapped(&dst, []byte("hello"))
	appendCapped(&dst, []byte(" world"))
	if string(dst) != "hello world" {
		t.Fatalf("dst = %q, want %q", dst, "hello world")
	}
}

// eventFor builds a collector.Event carrying payload as its captured Data,
// mirroring what the BPF program actually produces.
func eventFor(pid uint32, fd int32, op uint32, payload string) collector.Event {
	ev := collector.Event{PID: pid, FD: fd, Operation: op, DataLen: uint32(len(payload)), TotalLen: uint32(len(payload))}
	copy(ev.Data[:], payload)
	return ev
}

func TestRunEmitsExchangeOnClose(t *testing.T) {
	events := make(chan collector.Event, 8)
	events <- eventFor(1, 5, collector.OpRead, capturedRequest)
	events <- eventFor(1, 5, collector.OpWrite, capturedResponse)
	events <- eventFor(1, 5, collector.OpClose, "")
	close(events)

	rawOut, exchanges := Run(events)
	go func() {
		for range rawOut { // drain, unused by this test
		}
	}()

	ex, ok := <-exchanges
	if !ok {
		t.Fatal("no Exchange emitted on close")
	}
	if ex.Request == nil || ex.Request.URL.Path != "/medium" {
		t.Errorf("Exchange.Request = %+v, want GET /medium", ex.Request)
	}
	if ex.Response == nil || ex.Response.StatusCode != 200 {
		t.Errorf("Exchange.Response = %+v, want 200", ex.Response)
	}

	if _, ok := <-exchanges; ok {
		t.Fatal("expected exactly one Exchange")
	}
}

// TestRunFlushesOnChannelCloseWithoutOpClose guards the pooling fix: a
// connection that's never explicitly closed (e.g. go-redis pooling a
// connection) must still be decoded when the trace ends, not silently
// dropped.
func TestRunFlushesOnChannelCloseWithoutOpClose(t *testing.T) {
	events := make(chan collector.Event, 8)
	events <- eventFor(1, 5, collector.OpRead, capturedRequest)
	events <- eventFor(1, 5, collector.OpWrite, capturedResponse)
	// No OpClose -- the events channel just closes, as if the trace ended
	// while this connection was still open/pooled.
	close(events)

	rawOut, exchanges := Run(events)
	go func() {
		for range rawOut {
		}
	}()

	ex, ok := <-exchanges
	if !ok {
		t.Fatal("no Exchange emitted on trace end for a connection that never saw OpClose")
	}
	if ex.Request == nil || ex.Request.URL.Path != "/medium" {
		t.Errorf("Exchange.Request = %+v, want GET /medium", ex.Request)
	}
}

func TestRunPassesThroughEveryEvent(t *testing.T) {
	events := make(chan collector.Event, 3)
	events <- eventFor(1, 5, collector.OpRead, "x")
	events <- eventFor(1, 5, collector.OpWrite, "y")
	events <- eventFor(1, 5, collector.OpClose, "")
	close(events)

	rawOut, exchanges := Run(events)
	go func() {
		for range exchanges { // drain, unused by this test
		}
	}()

	var n int
	for range rawOut {
		n++
	}
	if n != 3 {
		t.Fatalf("rawOut passed through %d events, want 3", n)
	}
}
