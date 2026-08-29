package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

func main() {
	// go-redis always sends HELLO to negotiate protocol version (confirmed
	// by reading its initConn source while building the M5 replay proxy,
	// which has to answer that handshake itself) -- Protocol: 2 only
	// controls *which* version HELLO requests, keeping the negotiated
	// reply types to RESP2's, which is all internal/decoder implements.
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr, Protocol: 2})

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
