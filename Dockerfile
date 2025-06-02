# syntax=docker/dockerfile:1
FROM golang:1.24 as builder
ARG VERSION
WORKDIR /build

# Cache for the modules
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build go mod download

# Now adding all the code and start building
ADD . .
RUN --mount=type=cache,target=/root/.cache/go-build GOOS=linux go build -trimpath -ldflags "-X cmd.Version=$VERSION -X main.Version=$VERSION" -v -o mev-boost-relay .

FROM scratch
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/mev-boost-relay /app/mev-boost-relay
ENTRYPOINT ["/app/mev-boost-relay"]
