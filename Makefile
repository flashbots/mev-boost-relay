GIT_VER := $(shell git describe --tags --always --dirty="-dev")

all: clean build

v:
	@echo "Version: ${GIT_VER}"

clean:
	git clean -fdx

build:
	go build -ldflags "-X cmd.Version=${GIT_VER} -X main.Version=${GIT_VER}" -v .

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	gofmt -d -s .
	gofumpt -d .
	go vet ./...
	staticcheck ./...
	golangci-lint run

cover:
	go test -coverprofile=/tmp/boost-relay.cover.tmp ./...
	go tool cover -func /tmp/boost-relay.cover.tmp
	unlink /tmp/boost-relay.cover.tmp

cover-html:
	go test -coverprofile=/tmp/boost-relay.cover.tmp ./...
	go tool cover -html=/tmp/boost-relay.cover.tmp
	unlink /tmp/boost-relay.cover.tmp
