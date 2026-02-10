FIPS_ENABLED?=true
ifeq ($(GO),)
GO:=$(shell command -v go)
endif

GOHOSTOS:=$(shell $(GO) env GOHOSTOS)
GOPATH:=$(shell $(GO) env GOPATH)
GOOS?=$(shell $(GO) env GOOS)
GOARCH?=$(shell $(GO) env GOARCH)
GOBIN?=$(shell $(GO) env GOBIN)
GOFLAGS_MOD ?=

GOENV=GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=1 GOFLAGS="${GOFLAGS_MOD}"
GOBUILDFLAGS=-gcflags="all=-trimpath=${GOPATH}" -asmflags="all=-trimpath=${GOPATH}"

ifeq (${FIPS_ENABLED}, true)
GOFLAGS_MOD+=-tags=fips_enabled
GOFLAGS_MOD:=$(strip ${GOFLAGS_MOD})
GOENV+=GOEXPERIMENT=strictfipsruntime,boringcrypto
GOENV:=$(strip ${GOENV})
endif

IMAGE ?="quay.io/cloudservices/kessel-parsec"
IMAGE_TAG=$(git rev-parse --short=7 HEAD)
GIT_COMMIT=$(git rev-parse --short HEAD)

ifeq ($(DOCKER),)
DOCKER:=$(shell command -v podman || command -v docker)
endif

API_PROTO_FILES:=$(shell find api -name *.proto)

TITLE:="Kessel Parsec Service"
ifeq ($(VERSION),)
VERSION:=$(shell git describe --tags --always)
endif

.PHONY: init
# init env
init:
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) get google.golang.org/grpc/cmd/protoc-gen-go-grpc
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc
	$(GO) install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
	$(GO) install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest

.PHONY: api
# generate api proto
api:
	@echo "Generating api protos"
	buf generate
	buf lint

.PHONY: build
# build
build:
	$(warning Setting GOEXPERIMENT=strictfipsruntime,boringcrypto - this generally causes builds to fail unless building inside the provided Dockerfile. If building locally, run `make local-build`)
	mkdir -p bin/ && ${GOENV} GOOS=${GOOS} ${GO} build ${GOBUILDFLAGS} -ldflags "-X cmd.Version=$(VERSION)" -o ./bin/ ./cmd/parsec

.PHONY: local-build
# local-build to ensure FIPS is not enabled which would likely result in a failed build locally
local-build:
	mkdir -p bin/ && $(GO) build -ldflags "-X cmd.Version=$(VERSION)" -o ./bin/ ./cmd/parsec

.PHONY: docker-build-push
docker-build-push:
	./build_deploy.sh

.PHONY: clean
# removes all binaries and build artifacts
clean:
	rm -rf bin/ coverage.txt coverage.html

.PHONY: test
# run all tests
test:
	@echo ""
	@echo "Running tests."
	@$(GO) test ./... -count=1 -race -short -covermode=atomic -coverprofile=coverage.txt
	@echo "Overall test coverage:"
	@$(GO) tool cover -func=coverage.txt | grep total: | awk '{print $$3}'

test-coverage: test
	@$(GO) tool cover -html=coverage.txt -o coverage.html
	@echo "coverage report written to coverage.html"

.PHONY: generate
# generate
generate:
	$(GO) mod tidy
	$(GO) generate ./...

.PHONY: all
# generate all
all:
	make api;
	make generate;

.PHONY: lint
# run go linter with the repositories lint config
lint:
	@echo "Running golangci-lint"
	@$(DOCKER) run -t --rm -v $(PWD):/app:rw,z -w /app golangci/golangci-lint:v2.6.2 golangci-lint run -v

lint-fix:
	@echo "Running golangci-lint run --fix"
	@$(DOCKER) run -t --rm -v $(PWD):/app:rw,z -w /app golangci/golangci-lint:v2.6.2 golangci-lint run --fix -v

.PHONY: pr-check
# generate pr-check
pr-check:
	make generate;
	make test;
	make lint;
	make local-build;

.PHONY: run
# run parsec locally
run: local-build
	./bin/parsec serve

run-help: local-build
	./bin/parsec serve --help

help:
# show help
	@echo ''
	@echo 'Usage:'
	@echo ' make [target]'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z\-_0-9/]+:/ { \
	helpMessage = match(lastLine, /^# (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")); \
			helpMessage = substr(lastLine, RSTART + 2, RLENGTH); \
			printf "\033[36m%-22s\033[0m %s\n", helpCommand,helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
