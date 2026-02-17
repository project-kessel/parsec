FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7-1771346502 AS builder

ARG TARGETARCH
USER root
RUN microdnf install -y tar gzip make which gcc gcc-c++ cyrus-sasl-lib findutils git go-toolset

WORKDIR /workspace

COPY go.mod go.sum ./

ENV CGO_ENABLED 1
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY api ./api
COPY Makefile ./

ARG VERSION
RUN VERSION=${VERSION} make build

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7-1771346502

COPY --from=builder /workspace/bin/parsec /usr/local/bin/

EXPOSE 9090
EXPOSE 8080

USER 1001
ENV PATH="$PATH:/usr/local/bin"
ENTRYPOINT ["parsec", "serve"]

LABEL name="kessel-parsec" \
      version="0.0.1" \
      summary="Kessel parsec service" \
      description="The Kessel parsec OAuth 2.0 Token Exchange and ext_authz service"
