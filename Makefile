GIT_VER := $(shell git describe --tags --always --dirty="-dev")
# ECR_URI := flashbots/boost-relay

all: clean build

v:
	@echo "Version: ${GIT_VER}"

#clean:
#	rm -rf your-project build/

build:
	go build -ldflags "-X cmd.Version=${GIT_VER} -X main.Version=${GIT_VER}" -v .

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	gofmt -d ./
	go vet ./...
	staticcheck ./...

cover:
	go test -coverprofile=/tmp/boost-relay.cover.tmp ./...
	go tool cover -func /tmp/boost-relay.cover.tmp
	unlink /tmp/boost-relay.cover.tmp

cover-html:
	go test -coverprofile=/tmp/boost-relay.cover.tmp ./...
	go tool cover -html=/tmp/boost-relay.cover.tmp
	unlink /tmp/boost-relay.cover.tmp
