package streamer

import (
	"strconv"
	"strings"
	"testing"

	"github.com/vidhu/etracer/internal/collector"
)

// Same literal captured bytes used in internal/decoder's gate tests --
// duplicated here (not imported) since these test streamer's own
// responsibility (buffering/lifecycle/flush), not decode correctness.
const capturedRequest = "GET /medium HTTP/1.1\r\nHost: 127.0.0.1:18099\r\nUser-Agent: curl/8.18.0\r\nAccept: */*\r\n\r\n"

var capturedBody = `{"id":42,"name":"Alice","bio":"` + strings.Repeat("y", 1500) + `"}`

var capturedResponse = "HTTP/1.1 200 OK\r\nDate: Sat, 29 Aug 2026 18:25:02 GMT\r\n" +
	"Content-Length: " + strconv.Itoa(len(capturedBody)) + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
	capturedBody

const capturedSetCommand = "*3\r\n$3\r\nset\r\n$7\r\nuser:42\r\n$5\r\nAlice\r\n"
const capturedOKReply = "+OK\r\n"

func TestDecodeRecognizesHTTP(t *testing.T) {
	ex, ok := decode(42, 5, []byte(capturedRequest), []byte(capturedResponse), false)
	if !ok {
		t.Fatal("decode() failed to recognize real captured HTTP bytes")
	}
	if ex.Protocol != ProtocolHTTP {
		t.Fatalf("Protocol = %v, want ProtocolHTTP", ex.Protocol)
	}
	if ex.HTTP == nil || ex.HTTP.Request == nil || ex.HTTP.Request.URL.Path != "/medium" {
		t.Errorf("HTTP = %+v, want a GET /medium request", ex.HTTP)
	}
}

func TestDecodeRecognizesRedis(t *testing.T) {
	ex, ok := decode(42, 8, []byte(capturedOKReply), []byte(capturedSetCommand), false)
	if !ok {
		t.Fatal("decode() failed to recognize real captured RESP bytes")
	}
	if ex.Protocol != ProtocolRedis {
		t.Fatalf("Protocol = %v, want ProtocolRedis", ex.Protocol)
	}
	if len(ex.Redis) != 1 || ex.Redis[0].Reply != "OK" {
		t.Errorf("Redis = %+v, want one call with reply OK", ex.Redis)
	}
}

func TestDecodeNonProtocolBytesFails(t *testing.T) {
	_, ok := decode(1, 1, []byte("not a protocol\r\n\r\n"), []byte("also not one"), false)
	if ok {
		t.Fatal("decode() should not recognize unrecognized bytes")
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
	if ex.HTTP == nil || ex.HTTP.Request == nil || ex.HTTP.Request.URL.Path != "/medium" {
		t.Errorf("Exchange.HTTP = %+v, want GET /medium", ex.HTTP)
	}

	if _, ok := <-exchanges; ok {
		t.Fatal("expected exactly one Exchange")
	}
}

// TestRunFlushesOnChannelCloseWithoutOpClose guards the M4 pooling fix: a
// connection that's never explicitly closed (e.g. go-redis pooling a
// connection) must still be decoded when the trace ends, not silently
// dropped.
func TestRunFlushesOnChannelCloseWithoutOpClose(t *testing.T) {
	events := make(chan collector.Event, 8)
	events <- eventFor(1, 8, collector.OpWrite, capturedSetCommand)
	events <- eventFor(1, 8, collector.OpRead, capturedOKReply)
	// No OpClose -- the events channel just closes, as if the trace ended
	// while this pooled connection was still open.
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
	if ex.Protocol != ProtocolRedis || len(ex.Redis) != 1 {
		t.Fatalf("Exchange = %+v, want a single decoded Redis call", ex)
	}
}

// eventForSSL mirrors eventFor for TLS-sourced events: no fd (bpf/tls.bpf.c
// always sets it to -1), an SSL* identity instead.
func eventForSSL(pid uint32, sslPtr uint64, op uint32, payload string) collector.Event {
	ev := collector.Event{PID: pid, FD: -1, SSLPtr: sslPtr, Operation: op, DataLen: uint32(len(payload)), TotalLen: uint32(len(payload))}
	copy(ev.Data[:], payload)
	return ev
}

// TestRunDecodesTLSConnectionBySSLPtr guards the TLS milestone's core
// design decision: SSL_write/SSL_read events have no fd, so the streamer
// must bucket them by ssl_ptr instead -- and since there's no SSL_shutdown/
// SSL_free probe, a TLS connection can only ever be decoded through the
// end-of-trace flush path, same as a pooled go-redis connection.
func TestRunDecodesTLSConnectionBySSLPtr(t *testing.T) {
	events := make(chan collector.Event, 8)
	events <- eventForSSL(1, 0xdeadbeef, collector.OpSSLWrite, capturedRequest)
	events <- eventForSSL(1, 0xdeadbeef, collector.OpSSLRead, capturedResponse)
	close(events)

	rawOut, exchanges := Run(events)
	go func() {
		for range rawOut {
		}
	}()

	ex, ok := <-exchanges
	if !ok {
		t.Fatal("no Exchange emitted for a TLS connection flushed at trace end")
	}
	if ex.Protocol != ProtocolHTTP || ex.HTTP == nil || ex.HTTP.Request == nil || ex.HTTP.Request.URL.Path != "/medium" {
		t.Fatalf("Exchange = %+v, want decoded HTTP from TLS-sourced plaintext", ex)
	}
}

// TestRunDoesNotAliasFDAndSSLPtrWithTheSameNumericValue guards the exact
// aliasing risk the key type's kind field exists to prevent: an fd and an
// unrelated SSL* can coincidentally share a numeric value, and they must
// not be merged into the same buffer.
func TestRunDoesNotAliasFDAndSSLPtrWithTheSameNumericValue(t *testing.T) {
	const sharedID = 5
	events := make(chan collector.Event, 8)
	events <- eventFor(1, sharedID, collector.OpWrite, capturedSetCommand)
	events <- eventFor(1, sharedID, collector.OpRead, capturedOKReply)
	events <- eventForSSL(1, sharedID, collector.OpSSLWrite, capturedRequest)
	events <- eventForSSL(1, sharedID, collector.OpSSLRead, capturedResponse)
	close(events)

	rawOut, exchanges := Run(events)
	go func() {
		for range rawOut {
		}
	}()

	var got []Exchange
	for ex := range exchanges {
		got = append(got, ex)
	}
	if len(got) != 2 {
		t.Fatalf("got %d exchanges, want 2 (one Redis via fd, one HTTP via ssl_ptr -- not merged)", len(got))
	}
	var sawRedis, sawHTTP bool
	for _, ex := range got {
		sawRedis = sawRedis || ex.Protocol == ProtocolRedis
		sawHTTP = sawHTTP || ex.Protocol == ProtocolHTTP
	}
	if !sawRedis || !sawHTTP {
		t.Fatalf("exchanges = %+v, want one Redis and one HTTP", got)
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
