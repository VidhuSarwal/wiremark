// Package replay implements the userspace side of M5: a RESP2 proxy that
// stands in for a real Redis instance, serving a recorded test case's
// dependency replies instead. No eBPF and no kernel-level redirection is
// involved -- the app is simply pointed at this proxy's address instead of a
// real Redis (see cmd/wiremark's run command), matching the guide's stated v1
// scope ("no kernel redirect yet").
package replay

import (
	"bufio"
	"net"
	"strings"
	"sync"

	"github.com/vidhusarwal/wiremark/internal/decoder"
	"github.com/vidhusarwal/wiremark/internal/recorder"
)

// Proxy answers a real Redis client's connection handshake (HELLO, CLIENT
// SETINFO -- whatever admin commands a client sends before its first real
// command) and then serves the deps it was built with by exact command
// match.
type Proxy struct {
	ln   net.Listener
	deps []recorder.Dependency

	mu   sync.Mutex
	wg   sync.WaitGroup
	done bool
}

// NewProxy binds a listener on an OS-assigned localhost port. It does not
// start serving connections -- call Serve for that -- so a caller can read
// Addr() and inject it into a subprocess's environment before that
// subprocess's first connection attempt can race the listener coming up.
func NewProxy(deps []recorder.Dependency) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &Proxy{ln: ln, deps: deps}, nil
}

// Addr returns the "host:port" the proxy is listening on.
func (p *Proxy) Addr() string {
	return p.ln.Addr().String()
}

// Serve accepts connections until Close is called. It blocks; run it in its
// own goroutine.
func (p *Proxy) Serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handleConn(conn)
		}()
	}
}

// Close stops accepting new connections and waits for in-flight ones to
// finish (they exit on their own once their client disconnects).
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.done = true
	p.mu.Unlock()
	err := p.ln.Close()
	p.wg.Wait()
	return err
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		cmd, err := decoder.ReadCommand(r)
		if err != nil {
			return
		}
		if _, err := conn.Write(p.reply(cmd)); err != nil {
			return
		}
	}
}

// reply answers one command. Admin commands (HELLO, CLIENT, ...) get a
// generic RESP error -- a syntactically valid RESP2 error is required here,
// not just any bytes: go-redis's connection init treats a reply that fails
// to parse as a RESP value at all as "this isn't even a Redis server" and
// hard-fails the connection, but a proper "-ERR ...\r\n" is recognized as
// "server doesn't support this command" and gets tolerated, letting the
// client fall back to RESP2 and proceed to send its real commands. Anything
// else is matched against the recorded dependencies by exact,
// case-insensitive command text.
func (p *Proxy) reply(cmd []string) []byte {
	if len(cmd) == 0 {
		return decoder.EncodeError("ERR empty command")
	}
	if decoder.IsAdminCommand(cmd[0]) {
		return decoder.EncodeError("ERR unknown command '" + cmd[0] + "'")
	}

	want := strings.ToLower(strings.Join(cmd, " "))
	for _, dep := range p.deps {
		if strings.ToLower(dep.Request) == want {
			return decoder.EncodeReply(dep.Response)
		}
	}
	return decoder.EncodeError("ERR no recorded reply for '" + want + "'")
}
