# syntax=docker/dockerfile:1
FROM golang:1.18 as builder
ARG VERSION
WORKDIR /build
ADD . /build/
RUN --mount=type=cache,target=/root/.cache/go-build GOOS=linux go build -trimpath -ldflags "-s -X cmd.Version=$VERSION -X main.Version=$VERSION" -v -o boost-relay .

FROM alpine
RUN apk add --no-cache libstdc++ libc6-compat
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/boost-relay /app/boost-relay
ENTRYPOINT ["/app/boost-relay"]
