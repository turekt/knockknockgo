GO=/usr/local/go/bin/go
GOFLAGS=
BIN_FOLDER=bin

.PHONY: all daemon client clean build-dep

all: clean test daemon client

build-dep:
	mkdir -p $(BIN_FOLDER)/

daemon: build-dep
	$(GO) build $(GOFLAGS) -o $(BIN_FOLDER)/kkd ./cmd/kkd/main.go

client: build-dep
	$(GO) build $(GOFLAGS) -o $(BIN_FOLDER)/kk ./cmd/kk/main.go

test:
	$(GO) test ./...

clean:
	rm -rf $(BIN_FOLDER)/ build/kk build/kkd