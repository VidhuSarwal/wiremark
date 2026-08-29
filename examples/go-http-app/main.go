package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/redis/go-redis/v9"
)

func main() {
	// Protocol: 2 forces RESP2 and skips the HELLO/RESP3 handshake, which
	// keeps the wire traffic to plain commands/replies -- the guide's own
	// stated v1 scope ("just enough to decode common commands, not the
	// full RESP3 spec").
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379", Protocol: 2})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})
	http.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 10000))
	})
	http.HandleFunc("/medium", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":42,"name":"Alice","bio":"%s"}`, strings.Repeat("y", 1500))
	})
	http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		if err := rdb.Set(r.Context(), "user:42", "Alice", 0).Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"id":42,"name":"Alice"}`)
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:18099", nil))
}
