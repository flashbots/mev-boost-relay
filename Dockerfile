# syntax=docker/dockerfile:1
FROM public.ecr.aws/q0m5j4m5/golang:latest as builder
ARG VERSION
WORKDIR /build
ADD . /build/
RUN --mount=type=cache,target=/root/.cache/go-build GOOS=linux go build -trimpath -ldflags "-s -X cmd.Version=$VERSION -X main.Version=$VERSION" -v -o mev-boost-relay .

# FROM alpine
# RUN apk add --no-cache libstdc++ libc6-compat
# WORKDIR /app
# COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
FROM scratch AS export-stage
COPY --from=builder /build/boost-relay /application
# ENTRYPOINT ["/app/boost-relay"]
