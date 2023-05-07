VERSION ?= $(shell git describe --tags --always --dirty="-dev")

all: clean build

v:
	@echo "Version: ${VERSION}"

clean:
	git clean -fdx

build:
	go build -trimpath -ldflags "-s -X cmd.Version=${VERSION} -X main.Version=${VERSION}" -v -o mev-boost-relay .

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	gofmt -d -s .
	gofumpt -d -extra .
	go vet ./...
	staticcheck ./...
	golangci-lint run

gofumpt:
	gofumpt -l -w -extra .

fmt:
	gofmt -s -w .
	gofumpt -extra -w .
	gci write .
	go mod tidy

test-coverage:
	go test -race -v -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func coverage.out

cover-html:
	go test -coverprofile=/tmp/boost-relay.cover.tmp ./...
	go tool cover -html=/tmp/boost-relay.cover.tmp
	unlink /tmp/boost-relay.cover.tmp

docker-image:
	DOCKER_BUILDKIT=1 docker build --platform linux/amd64 --build-arg VERSION=${VERSION} . -t flashbots/mev-boost-relay

lt: lint test
flt: fmt lint test