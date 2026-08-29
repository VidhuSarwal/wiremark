package decoder

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
)

// HTTPExchange is a decoded HTTP request/response pair. Request and/or
// Response may be nil if only one side parsed as HTTP.
type HTTPExchange struct {
	Request      *http.Request
	RequestBody  []byte
	Response     *http.Response
	ResponseBody []byte
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

// TryHTTP content-sniffs readBuf/writeBuf as HTTP, trying both possible role
// assignments (read=request/write=response for a traced server, the
// inverse for a traced client) and keeping whichever parses. ok is false if
// neither side parsed as anything HTTP-shaped.
func TryHTTP(readBuf, writeBuf []byte) (HTTPExchange, bool) {
	var ex HTTPExchange

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
