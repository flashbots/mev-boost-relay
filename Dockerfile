# syntax=docker/dockerfile:1
FROM golang:1.18-alpine as builder
ARG GIT_VER
RUN apk add build-base
WORKDIR /build
ADD . /build/
RUN --mount=type=cache,target=/root/.cache/go-build GOOS=linux go build -ldflags "-X cmd.Version=$GIT_VER -X main.Version=$GIT_VER" -v -o boost-relay .

FROM alpine
RUN apk add --no-cache libstdc++ libc6-compat
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/boost-relay /app/boost-relay
ENTRYPOINT ["/app/boost-relay"]
