# Build stage -- the Go toolchain embeds the validated FIPS module in all binaries automatically.
FROM registry.access.redhat.com/hi/go:1.26.4-fips AS builder

WORKDIR /workspace

COPY go.mod go.sum ./

ENV GOEXPERIMENT jsonv2
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY api ./api
COPY Makefile ./

ARG VERSION
RUN VERSION=${VERSION} make build

# Runtime stage -- set GODEBUG so the binary runs in FIPS mode.
FROM registry.access.redhat.com/hi/core-runtime:2.42-openssl-fips

WORKDIR /

COPY --from=builder /workspace/bin/parsec /usr/local/bin/

ENV GODEBUG=fips140=on

EXPOSE 9090
EXPOSE 8080

USER 1001
ENV PATH="$PATH:/usr/local/bin"
ENTRYPOINT ["parsec", "serve"]

LABEL name="kessel-parsec" \
      version="0.0.1" \
      summary="Kessel parsec service" \
      description="The Kessel parsec OAuth 2.0 Token Exchange and ext_authz service"
