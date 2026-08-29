package decoder

import (
	"strconv"
	"strings"
	"testing"
)

// These are the literal byte strings captured from a live trace of
// examples/go-http-app: a real GET /medium request and its 1533-byte JSON
// response. This is the gate for the HTTP decoder -- if it can't parse
// actual captured bytes, nothing built on top of it matters.
const capturedRequest = "GET /medium HTTP/1.1\r\nHost: 127.0.0.1:18099\r\nUser-Agent: curl/8.18.0\r\nAccept: */*\r\n\r\n"

// capturedBody mirrors examples/go-http-app's /medium handler exactly
// (bio: strings.Repeat("y", 1500)) so its length is derived, not guessed.
var capturedBody = `{"id":42,"name":"Alice","bio":"` + strings.Repeat("y", 1500) + `"}`

var capturedResponse = "HTTP/1.1 200 OK\r\nDate: Sat, 29 Aug 2026 18:25:02 GMT\r\n" +
	"Content-Length: " + strconv.Itoa(len(capturedBody)) + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
	capturedBody

func TestTryHTTPRealCapturedBytesServerRole(t *testing.T) {
	ex, ok := TryHTTP([]byte(capturedRequest), []byte(capturedResponse))
	if !ok {
		t.Fatal("TryHTTP failed to recognize real captured HTTP bytes")
	}
	if ex.Request == nil || ex.Request.Method != "GET" || ex.Request.URL.Path != "/medium" {
		t.Errorf("Request = %+v, want GET /medium", ex.Request)
	}
	if ex.Response == nil || ex.Response.StatusCode != 200 {
		t.Errorf("Response = %+v, want 200", ex.Response)
	}
	if len(ex.ResponseBody) != len(capturedBody) {
		t.Errorf("ResponseBody length = %d, want %d", len(ex.ResponseBody), len(capturedBody))
	}
}

// TestTryHTTPClientRole is the M4-facing case: the traced process is the
// client, so it *writes* the request and *reads* the response -- the
// opposite of the server role above.
func TestTryHTTPClientRole(t *testing.T) {
	ex, ok := TryHTTP([]byte(capturedResponse), []byte(capturedRequest))
	if !ok {
		t.Fatal("TryHTTP failed on the client-role byte assignment (write=request, read=response)")
	}
	if ex.Request == nil || ex.Request.Method != "GET" {
		t.Error("Request not recovered from the write-side buffer")
	}
	if ex.Response == nil || ex.Response.StatusCode != 200 {
		t.Error("Response not recovered from the read-side buffer")
	}
}

func TestTryHTTPOnNonHTTPBytesFails(t *testing.T) {
	if _, ok := TryHTTP([]byte("not http\r\n\r\n"), []byte("also not http")); ok {
		t.Fatal("TryHTTP should not recognize non-HTTP bytes")
	}
}
