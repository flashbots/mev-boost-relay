GIT_VER := $(shell git describe --tags --always --dirty="-dev")
# ECR_URI := flashbots/boost-relay

all: clean build

v:
	@echo "Version: ${GIT_VER}"

#clean:
#	rm -rf your-project build/

build:
	go build -ldflags "-X main.version=${GIT_VER}" -v .

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

#build-for-docker:
#	GOOS=linux go build -ldflags "-X main.version=${GIT_VER}" -v -o your-project main.go

#docker-image:
#	DOCKER_BUILDKIT=1 docker build . -t your-project
# 	docker tag your-project:latest ${ECR_URI}:${GIT_VER}
# 	docker tag your-project:latest ${ECR_URI}:latest

# docker-push:
# 	docker push ${ECR_URI}:${GIT_VER}
# 	docker push ${ECR_URI}:latest

# k8s-deploy:
# 	@echo "Checking if Docker image ${ECR_URI}:${GIT_VER} exists..."
# 	@docker manifest inspect ${ECR_URI}:${GIT_VER} > /dev/null || (echo "Docker image not found" && exit 1)
# 	kubectl set image deploy/deployment-your-project app-your-project=${ECR_URI}:${GIT_VER}
# 	kubectl rollout status deploy/deployment-your-project
