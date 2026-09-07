// Package recorder builds a TestCase from a trace session's decoded
// Exchanges: the one HTTP exchange is the request/response under test, and
// any Redis exchanges are its dependencies. No time-windowing is needed to
// tell them apart at this project's single-request-at-a-time scope --
// protocol type alone does the separation.
package recorder

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vidhusarwal/wiremark/internal/streamer"
)

// TestCase mirrors the build guide's YAML schema:
//
//	test: {name}
//	request: {method, path, body}
//	dependencies: [{type, request, response}]
//	response: {status, body}
type TestCase struct {
	Test         TestMeta     `yaml:"test"`
	Request      Request      `yaml:"request"`
	Dependencies []Dependency `yaml:"dependencies,omitempty"`
	Response     Response     `yaml:"response"`
}

type TestMeta struct {
	Name string `yaml:"name"`
}

type Request struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
	Body   any    `yaml:"body,omitempty"`
}

type Response struct {
	Status int `yaml:"status"`
	Body   any `yaml:"body,omitempty"`
}

type Dependency struct {
	Type     string `yaml:"type"`
	Request  string `yaml:"request"`
	Response string `yaml:"response"`
}

// Build partitions exchanges into a TestCase. Only the first HTTP exchange
// observed is recorded as the request/response under test (v1 scope is one
// request per recording); every Redis call across every Redis exchange is
// recorded as a dependency, in the order observed. Returns an error if no
// HTTP exchange was seen at all -- a recording with nothing to record is a
// caller mistake (wrong PID, no request sent) worth surfacing, not silently
// writing an empty test case.
func Build(name string, exchanges []streamer.Exchange) (TestCase, error) {
	tc := TestCase{Test: TestMeta{Name: name}}

	var foundHTTP bool
	for _, ex := range exchanges {
		switch ex.Protocol {
		case streamer.ProtocolHTTP:
			if foundHTTP || ex.HTTP == nil {
				continue
			}
			foundHTTP = true
			if ex.HTTP.Request != nil {
				tc.Request.Method = ex.HTTP.Request.Method
				tc.Request.Path = ex.HTTP.Request.URL.Path
				tc.Request.Body = decodeBody(ex.HTTP.RequestBody)
			}
			if ex.HTTP.Response != nil {
				tc.Response.Status = ex.HTTP.Response.StatusCode
				tc.Response.Body = decodeBody(ex.HTTP.ResponseBody)
			}
		case streamer.ProtocolRedis:
			for _, call := range ex.Redis {
				tc.Dependencies = append(tc.Dependencies, Dependency{
					Type:     "redis",
					Request:  strings.Join(call.Command, " "),
					Response: call.Reply,
				})
			}
		}
	}

	if !foundHTTP {
		return tc, fmt.Errorf("no HTTP request observed during the trace")
	}
	return tc, nil
}

// decodeBody renders a body as structured YAML when it's JSON (matching the
// guide's example of a nested body: {...} mapping), falling back to the raw
// string otherwise.
func decodeBody(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err == nil {
		return v
	}
	return string(b)
}
