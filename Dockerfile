# syntax=docker/dockerfile:1
FROM golang:1.22 AS builder
ARG VERSION
WORKDIR /build

# Cache for the modules
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build go mod download

# Now adding all the code and start building
ADD . .
RUN --mount=type=cache,target=/root/.cache/go-build GOOS=linux go build -trimpath -ldflags "-s -X cmd.Version=$VERSION -X main.Version=$VERSION -linkmode external -extldflags '-static'" -v -o mev-boost-relay .

FROM alpine
RUN apk add --no-cache libstdc++ libc6-compat
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/mev-boost-relay /app/mev-boost-relay
ENTRYPOINT ["/app/mev-boost-relay"]
