.PHONY: generate build test clean

generate:
	go generate ./...

build: generate
	go build -o wiremark ./cmd/wiremark

test:
	go test ./...

clean:
	rm -f wiremark
	rm -f internal/bpfgen/*.o
