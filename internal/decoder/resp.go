// Package decoder implements content-sniffing parsers for the protocols
// this project decodes: HTTP (net/http) and RESP2 (Redis). Each parser is a
// pure function over a byte slice -- no channels, no state -- so streamer
// stays responsible for buffering/lifecycle and decoder for protocol
// semantics only.
package decoder

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RESPValue is a single decoded RESP2 value. Only the fields relevant to
// Kind are populated.
type RESPValue struct {
	Kind  byte // '+' simple string, '-' error, ':' integer, '$' bulk string, '*' array
	Str   string
	Array []RESPValue
	Null  bool // true for a null bulk string ($-1) or null array (*-1)
}

// String renders a RESPValue similarly to redis-cli.
func (v RESPValue) String() string {
	switch v.Kind {
	case '-':
		return "(error) " + v.Str
	case ':':
		return "(integer) " + v.Str
	case '$', '+':
		if v.Null {
			return "(nil)"
		}
		return v.Str
	case '*':
		if v.Null {
			return "(nil)"
		}
		parts := make([]string, len(v.Array))
		for i, e := range v.Array {
			parts[i] = e.String()
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return v.Str
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func parseRESPValue(r *bufio.Reader) (RESPValue, error) {
	line, err := readLine(r)
	if err != nil {
		return RESPValue{}, err
	}
	if len(line) == 0 {
		return RESPValue{}, fmt.Errorf("empty RESP line")
	}

	kind, rest := line[0], line[1:]
	switch kind {
	case '+', '-', ':':
		return RESPValue{Kind: kind, Str: rest}, nil

	case '$':
		n, err := strconv.Atoi(rest)
		if err != nil {
			return RESPValue{}, fmt.Errorf("bad bulk string length %q: %w", rest, err)
		}
		if n < 0 {
			return RESPValue{Kind: '$', Null: true}, nil
		}
		buf := make([]byte, n+2) // +2 for the trailing \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return RESPValue{}, err
		}
		return RESPValue{Kind: '$', Str: string(buf[:n])}, nil

	case '*':
		n, err := strconv.Atoi(rest)
		if err != nil {
			return RESPValue{}, fmt.Errorf("bad array length %q: %w", rest, err)
		}
		if n < 0 {
			return RESPValue{Kind: '*', Null: true}, nil
		}
		arr := make([]RESPValue, n)
		for i := 0; i < n; i++ {
			elem, err := parseRESPValue(r)
			if err != nil {
				return RESPValue{}, err
			}
			arr[i] = elem
		}
		return RESPValue{Kind: '*', Array: arr}, nil

	default:
		return RESPValue{}, fmt.Errorf("unrecognized RESP type byte %q", kind)
	}
}

// ReadCommand reads one client command (a RESP array of bulk strings) from a
// live connection. Unlike ParseRESPStream, which decodes a complete captured
// byte slice, this reads exactly one value at a time from an open
// io.Reader -- what the replay proxy needs, since it can't wait for the
// connection to close before it has anything to parse. Returns io.EOF
// (unwrapped, checkable with errors.Is) when the peer closes cleanly between
// commands.
func ReadCommand(r *bufio.Reader) ([]string, error) {
	v, err := parseRESPValue(r)
	if err != nil {
		return nil, err
	}
	if v.Kind != '*' {
		return nil, fmt.Errorf("expected RESP array command, got type %q", v.Kind)
	}
	cmd := make([]string, len(v.Array))
	for i, elem := range v.Array {
		cmd[i] = elem.Str
	}
	return cmd, nil
}

// EncodeSimpleString, EncodeError, EncodeBulkString, EncodeInteger, and
// EncodeNullBulk encode individual RESP2 reply types for the replay proxy's
// use writing responses back to a live client (the mirror image of
// parseRESPValue, which only ever needed to read them).
func EncodeSimpleString(s string) []byte { return []byte("+" + s + "\r\n") }
func EncodeError(s string) []byte        { return []byte("-" + s + "\r\n") }
func EncodeInteger(n string) []byte      { return []byte(":" + n + "\r\n") }
func EncodeNullBulk() []byte             { return []byte("$-1\r\n") }
func EncodeBulkString(s string) []byte {
	return []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(s), s))
}

// EncodeReply reverses RESPValue.String()'s rendering convention -- the form
// a recorded dependency's reply is stored in (e.g. "OK", "(integer) 5",
// "(nil)") -- back into RESP2 wire bytes, so the replay proxy can send a
// recorded reply to a real client. "(nil)"/"(error) ..."/"(integer) ..."
// round-trip exactly; anything else is encoded as a simple string, which is
// what every dependency reply this project actually records (Redis status
// replies like SET's "OK") renders as.
func EncodeReply(display string) []byte {
	switch {
	case display == "(nil)":
		return EncodeNullBulk()
	case strings.HasPrefix(display, "(error) "):
		return EncodeError(strings.TrimPrefix(display, "(error) "))
	case strings.HasPrefix(display, "(integer) "):
		return EncodeInteger(strings.TrimPrefix(display, "(integer) "))
	default:
		return EncodeSimpleString(display)
	}
}

// ParseRESPStream decodes as many complete top-level RESP values as buf
// contains. ok is false only if not even one value could be parsed (buf
// isn't RESP-shaped at all); a value cut short by truncated capture simply
// isn't included, since that's expected of a capped capture buffer rather
// than a parse failure.
func ParseRESPStream(buf []byte) (values []RESPValue, ok bool) {
	r := bufio.NewReader(bytes.NewReader(buf))
	for {
		v, err := parseRESPValue(r)
		if err != nil {
			break
		}
		values = append(values, v)
	}
	return values, len(values) > 0
}

// adminCommands are Redis connection/protocol setup commands filtered out of
// recorded dependencies -- they're the client library talking to Redis
// about itself, not the application's actual data-plane usage.
var adminCommands = map[string]bool{
	"HELLO": true, "CLIENT": true, "AUTH": true, "SELECT": true, "PING": true,
}

// IsAdminCommand reports whether name (case-insensitive) is a connection/
// protocol setup command rather than application data-plane usage. Exported
// for the replay proxy, which must answer these itself (a recording never
// captures them as dependencies -- TryRESP filters them out at record time)
// or a real client's connection handshake (HELLO, CLIENT SETINFO) will never
// get a reply and hang or fail before its first real command is even sent.
func IsAdminCommand(name string) bool {
	return adminCommands[strings.ToUpper(name)]
}

// RedisCall is one filtered, paired command/reply.
type RedisCall struct {
	Command []string
	Reply   string
}

// TryRESP decodes commands from cmdBuf and their replies from replyBuf,
// pairing them positionally -- RESP guarantees a connection's
// requests/replies are strictly ordered when not pipelined -- and filtering
// out administrative commands. ok is false if cmdBuf doesn't parse as any
// RESP command arrays at all (client requests are always arrays of bulk
// strings, so a non-array top-level value means this isn't a command
// stream).
func TryRESP(cmdBuf, replyBuf []byte) (calls []RedisCall, ok bool) {
	cmdValues, parsedAny := ParseRESPStream(cmdBuf)
	if !parsedAny {
		return nil, false
	}
	replyValues, _ := ParseRESPStream(replyBuf) // best-effort; zero replies is structurally fine

	var commands [][]string
	for _, v := range cmdValues {
		if v.Kind != '*' {
			return nil, false // a client command stream is only ever arrays
		}
		cmd := make([]string, len(v.Array))
		for i, elem := range v.Array {
			cmd[i] = elem.Str
		}
		commands = append(commands, cmd)
	}

	for i, cmd := range commands {
		if len(cmd) == 0 || IsAdminCommand(cmd[0]) {
			continue
		}
		reply := "?"
		if i < len(replyValues) {
			reply = replyValues[i].String()
		}
		calls = append(calls, RedisCall{Command: cmd, Reply: reply})
	}
	return calls, len(calls) > 0
}
