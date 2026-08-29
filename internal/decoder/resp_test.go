package decoder

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
)

// These are the literal byte strings captured from a live trace of
// examples/go-http-app's /users route (go-redis, Protocol: 2 forced) doing
// a real SET against a real Redis instance. This is the gate for the whole
// RESP decoder -- if it can't parse actual captured bytes, nothing built on
// top of it matters.
const capturedSetCommand = "*3\r\n$3\r\nset\r\n$7\r\nuser:42\r\n$5\r\nAlice\r\n"
const capturedOKReply = "+OK\r\n"

// capturedHandshake is the HELLO/CLIENT SETINFO traffic go-redis sends
// before the real command -- present in every real capture, must be
// filtered as administrative rather than reported as a dependency.
const capturedHandshakeCommands = "*2\r\n$5\r\nhello\r\n$1\r\n2\r\n" +
	"*4\r\n$6\r\nclient\r\n$7\r\nsetinfo\r\n$8\r\nLIB-NAME\r\n$19\r\ngo-redis(,go1.26.0)\r\n" +
	"*4\r\n$6\r\nclient\r\n$7\r\nsetinfo\r\n$7\r\nLIB-VER\r\n$6\r\n9.22.0\r\n"
const capturedHandshakeReplies = "*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.0.5\r\n" +
	"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:7\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n" +
	"$7\r\nmodules\r\n*0\r\n" +
	"+OK\r\n+OK\r\n"

func TestParseRESPStreamSimpleCommand(t *testing.T) {
	values, ok := ParseRESPStream([]byte(capturedSetCommand))
	if !ok {
		t.Fatal("ParseRESPStream failed on real captured SET command bytes")
	}
	if len(values) != 1 || values[0].Kind != '*' {
		t.Fatalf("values = %+v, want one array value", values)
	}
	got := make([]string, len(values[0].Array))
	for i, e := range values[0].Array {
		got[i] = e.Str
	}
	want := []string{"set", "user:42", "Alice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("command = %v, want %v", got, want)
	}
}

func TestParseRESPStreamSimpleStringReply(t *testing.T) {
	values, ok := ParseRESPStream([]byte(capturedOKReply))
	if !ok || len(values) != 1 || values[0].String() != "OK" {
		t.Fatalf("ParseRESPStream(%q) = %+v, ok=%v, want a single \"OK\" value", capturedOKReply, values, ok)
	}
}

func TestParseRESPStreamMultipleValuesConcatenated(t *testing.T) {
	// Real captures show multiple RESP messages concatenated in one
	// syscall's payload (e.g. "+OK\r\n+OK\r\n" from two SETINFO replies
	// arriving in a single read()).
	values, ok := ParseRESPStream([]byte("+OK\r\n+OK\r\n"))
	if !ok || len(values) != 2 {
		t.Fatalf("got %d values, want 2", len(values))
	}
}

func TestTryRESPFiltersHandshakeKeepsRealCommand(t *testing.T) {
	cmdBuf := capturedHandshakeCommands + capturedSetCommand
	replyBuf := capturedHandshakeReplies + capturedOKReply

	calls, ok := TryRESP([]byte(cmdBuf), []byte(replyBuf))
	if !ok {
		t.Fatal("TryRESP failed to recognize a real captured command stream")
	}
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want exactly 1 (HELLO/CLIENT SETINFO should be filtered): %+v", len(calls), calls)
	}
	want := []string{"set", "user:42", "Alice"}
	if !reflect.DeepEqual(calls[0].Command, want) {
		t.Errorf("Command = %v, want %v", calls[0].Command, want)
	}
	if calls[0].Reply != "OK" {
		t.Errorf("Reply = %q, want %q", calls[0].Reply, "OK")
	}
}

func TestTryRESPOnNonRESPBytesFails(t *testing.T) {
	if _, ok := TryRESP([]byte("GET / HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\n")); ok {
		t.Fatal("TryRESP should not recognize HTTP bytes as RESP")
	}
}

// TestReadCommandReadsOneAtATime is the replay proxy's actual usage pattern:
// commands arrive back-to-back on a live connection (real captures show
// exactly this -- HELLO then two CLIENT SETINFO calls, all in one read()),
// and the proxy must consume and reply to each one without waiting for the
// connection to close.
func TestReadCommandReadsOneAtATime(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte(capturedHandshakeCommands + capturedSetCommand)))

	want := [][]string{
		{"hello", "2"},
		{"client", "setinfo", "LIB-NAME", "go-redis(,go1.26.0)"},
		{"client", "setinfo", "LIB-VER", "9.22.0"},
		{"set", "user:42", "Alice"},
	}
	for i, w := range want {
		got, err := ReadCommand(r)
		if err != nil {
			t.Fatalf("ReadCommand #%d: %v", i, err)
		}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("ReadCommand #%d = %v, want %v", i, got, w)
		}
	}

	if _, err := ReadCommand(r); !errors.Is(err, io.EOF) {
		t.Errorf("ReadCommand after last command: err = %v, want io.EOF", err)
	}
}

func TestReadCommandRejectsNonArray(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte(capturedOKReply)))
	if _, err := ReadCommand(r); err == nil {
		t.Fatal("ReadCommand should reject a non-array top-level value")
	}
}

// TestEncodeReplyRoundTrips checks EncodeReply against exactly the display
// strings RESPValue.String() produces -- it's meant to be its inverse for
// every reply shape this project actually records.
func TestEncodeReplyRoundTrips(t *testing.T) {
	cases := []struct {
		display string
		want    string
	}{
		{"OK", "+OK\r\n"},
		{"(nil)", "$-1\r\n"},
		{"(error) WRONGTYPE bad key", "-WRONGTYPE bad key\r\n"},
		{"(integer) 5", ":5\r\n"},
	}
	for _, c := range cases {
		if got := string(EncodeReply(c.display)); got != c.want {
			t.Errorf("EncodeReply(%q) = %q, want %q", c.display, got, c.want)
		}
	}
}

func TestIsAdminCommandCaseInsensitive(t *testing.T) {
	for _, name := range []string{"HELLO", "hello", "Client", "PING"} {
		if !IsAdminCommand(name) {
			t.Errorf("IsAdminCommand(%q) = false, want true", name)
		}
	}
	if IsAdminCommand("SET") {
		t.Error("IsAdminCommand(\"SET\") = true, want false")
	}
}

// TestProtocolsAreMutuallyExclusive guards against a false-positive sniff
// mislabeling a dependency as the HTTP request under test, or vice versa.
func TestProtocolsAreMutuallyExclusive(t *testing.T) {
	if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(capturedSetCommand)))); err == nil {
		t.Error("RESP command bytes should not parse as an HTTP request")
	}
	if _, ok := TryRESP([]byte("GET /medium HTTP/1.1\r\nHost: x\r\n\r\n"), nil); ok {
		t.Error("HTTP request bytes should not parse as a RESP command")
	}
}
