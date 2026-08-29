package replay

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/vidhu/etracer/internal/recorder"
)

// TestProxyServesRecordedSET is the M5 gate: a real go-redis client must be
// able to complete its full connection handshake (HELLO, two CLIENT SETINFO
// commands -- none of which are recorded dependencies, since TryRESP filters
// them out at record time) against this proxy and then get back the exact
// recorded reply for a data command. If the proxy doesn't answer the
// handshake correctly, go-redis's connection init hangs or hard-fails before
// SET is ever sent, and this test times out or errors -- not a SET-specific
// bug, a handshake one.
func TestProxyServesRecordedSET(t *testing.T) {
	deps := []recorder.Dependency{
		{Type: "redis", Request: "set user:42 Alice", Response: "OK"},
	}
	p, err := NewProxy(deps)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	go p.Serve()
	defer p.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr:     p.Addr(),
		Protocol: 2, // matches the example app's fixture; RESP3 HELLO isn't handled
	})
	defer rdb.Close()

	ctx := context.Background()
	if err := rdb.Set(ctx, "user:42", "Alice", 0).Err(); err != nil {
		t.Fatalf("SET against replay proxy: %v (handshake likely not tolerated)", err)
	}
}

func TestProxyReturnsErrorForUnrecordedCommand(t *testing.T) {
	p, err := NewProxy(nil)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	go p.Serve()
	defer p.Close()

	rdb := redis.NewClient(&redis.Options{Addr: p.Addr(), Protocol: 2})
	defer rdb.Close()

	ctx := context.Background()
	if err := rdb.Get(ctx, "nope").Err(); err == nil {
		t.Fatal("GET for an unrecorded key should return an error, not a nil-error empty reply")
	}
}
