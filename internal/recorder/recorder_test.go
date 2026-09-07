package recorder

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/vidhusarwal/wiremark/internal/decoder"
	"github.com/vidhusarwal/wiremark/internal/streamer"
)

func TestBuildPartitionsHTTPAndRedis(t *testing.T) {
	exchanges := []streamer.Exchange{
		{
			Protocol: streamer.ProtocolRedis,
			Redis: []decoder.RedisCall{
				{Command: []string{"set", "user:42", "Alice"}, Reply: "OK"},
			},
		},
		{
			Protocol: streamer.ProtocolHTTP,
			HTTP: &decoder.HTTPExchange{
				Request: &http.Request{
					Method: "POST",
					URL:    &url.URL{Path: "/users"},
				},
				RequestBody: []byte(`{"name":"Alice"}`),
				Response: &http.Response{
					StatusCode: 201,
				},
				ResponseBody: []byte(`{"id":42,"name":"Alice"}`),
			},
		},
	}

	tc, err := Build("create-user", exchanges)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if tc.Test.Name != "create-user" {
		t.Errorf("Test.Name = %q, want %q", tc.Test.Name, "create-user")
	}
	if tc.Request.Method != "POST" || tc.Request.Path != "/users" {
		t.Errorf("Request = %+v, want POST /users", tc.Request)
	}
	wantReqBody := map[string]any{"name": "Alice"}
	if got, ok := tc.Request.Body.(map[string]any); !ok || got["name"] != wantReqBody["name"] {
		t.Errorf("Request.Body = %#v, want %#v", tc.Request.Body, wantReqBody)
	}
	if tc.Response.Status != 201 {
		t.Errorf("Response.Status = %d, want 201", tc.Response.Status)
	}
	if len(tc.Dependencies) != 1 {
		t.Fatalf("got %d dependencies, want 1", len(tc.Dependencies))
	}
	dep := tc.Dependencies[0]
	if dep.Type != "redis" || dep.Request != "set user:42 Alice" || dep.Response != "OK" {
		t.Errorf("Dependency = %+v, want {redis, \"set user:42 Alice\", OK}", dep)
	}
}

func TestBuildErrorsWithoutAnyHTTPExchange(t *testing.T) {
	exchanges := []streamer.Exchange{
		{Protocol: streamer.ProtocolRedis, Redis: []decoder.RedisCall{{Command: []string{"get", "x"}, Reply: "(nil)"}}},
	}
	if _, err := Build("no-request", exchanges); err == nil {
		t.Fatal("Build should error when no HTTP exchange was observed")
	}
}

func TestBuildKeepsOnlyFirstHTTPExchange(t *testing.T) {
	first := streamer.Exchange{
		Protocol: streamer.ProtocolHTTP,
		HTTP: &decoder.HTTPExchange{
			Request: &http.Request{Method: "GET", URL: &url.URL{Path: "/first"}},
		},
	}
	second := streamer.Exchange{
		Protocol: streamer.ProtocolHTTP,
		HTTP: &decoder.HTTPExchange{
			Request: &http.Request{Method: "GET", URL: &url.URL{Path: "/second"}},
		},
	}

	tc, err := Build("t", []streamer.Exchange{first, second})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if tc.Request.Path != "/first" {
		t.Errorf("Request.Path = %q, want %q (v1 scope: only the first HTTP exchange is recorded)", tc.Request.Path, "/first")
	}
}

func TestDecodeBodyFallsBackToStringForNonJSON(t *testing.T) {
	if got := decodeBody([]byte("hello")); got != "hello" {
		t.Errorf("decodeBody(non-JSON) = %#v, want %q", got, "hello")
	}
	if got := decodeBody(nil); got != nil {
		t.Errorf("decodeBody(nil) = %#v, want nil", got)
	}
}
