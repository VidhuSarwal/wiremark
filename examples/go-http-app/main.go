package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})
	http.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 10000))
	})
	http.HandleFunc("/medium", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":42,"name":"Alice","bio":"%s"}`, strings.Repeat("y", 1500))
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:18099", nil))
}
