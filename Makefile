.PHONY: generate build test clean

generate:
	go generate ./...

build: generate
	go build -o etrace ./cmd/etrace

test:
	go test ./...

clean:
	rm -f etrace
	rm -f internal/bpfgen/*.o
