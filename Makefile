ifeq ($(GO),)
GO:=$(shell command -v go)
endif

GOHOSTOS:=$(shell $(GO) env GOHOSTOS)
GOPATH:=$(shell $(GO) env GOPATH)
GOOS?=$(shell $(GO) env GOOS)
GOARCH?=$(shell $(GO) env GOARCH)
GOBIN?=$(shell $(GO) env GOBIN)

GOENV=GOOS=${GOOS} GOARCH=${GOARCH} GOEXPERIMENT=jsonv2
GOTESTENV=GOEXPERIMENT=jsonv2
GOBUILDFLAGS=-gcflags="all=-trimpath=${GOPATH}" -asmflags="all=-trimpath=${GOPATH}"

IMAGE_TAG := $(shell git rev-parse --short=7 HEAD)
GIT_COMMIT := $(shell git rev-parse --short HEAD)

ifeq ($(DOCKER),)
DOCKER := $(shell command -v podman || command -v docker)
endif

PLATFORM_FLAGS :=
ifeq ($(shell uname -s),Darwin)
PLATFORM_FLAGS := --platform linux/amd64 --build-arg TARGETARCH=amd64
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
	mkdir -p bin/ && ${GOENV} ${GO} build ${GOBUILDFLAGS} -ldflags "-X cmd.Version=$(VERSION)" -o ./bin/ ./cmd/parsec

.PHONY: docker-build-push
# build and push container image to a registry
docker-build-push:
	@[ -n "$(DOCKER)" ] || { echo "Error: neither podman nor docker found. Please install one to continue."; exit 1; }
	@if [ -z "$(IMAGE)" ]; then \
		echo "IMAGE is required. Example: make docker-build-push IMAGE=quay.io/youruser/parsec"; \
		exit 1; \
	fi
	@printf '%s\n' "$(IMAGE)" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$$' || { echo "IMAGE contains invalid characters. Use format: quay.io/your-org/image-name"; exit 1; }
	@"$(DOCKER)" build $(PLATFORM_FLAGS) --build-arg GIT_COMMIT="$(GIT_COMMIT)" -t "$(IMAGE):$(IMAGE_TAG)" -f ./Dockerfile . || \
		(echo "Build failed. If due to authentication, check your registry credentials and try again." && exit 1)
	@"$(DOCKER)" push "$(IMAGE):$(IMAGE_TAG)" || \
		(echo "Push failed. If due to authentication, run: $(DOCKER) login quay.io" && exit 1)
	@"$(DOCKER)" tag "$(IMAGE):$(IMAGE_TAG)" "$(IMAGE):latest"
	@"$(DOCKER)" push "$(IMAGE):latest" || \
		(echo "Push failed. If due to authentication, run: $(DOCKER) login quay.io" && exit 1)

.PHONY: clean
# removes all binaries and build artifacts
clean:
	rm -rf bin/ coverage.txt coverage.html

.PHONY: test
# run all tests
test:
	@echo ""
	@echo "Running tests."
	@${GOTESTENV} $(GO) test ./... -count=1 -race -short -covermode=atomic -coverprofile=coverage.txt
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
	@$(DOCKER) run -t --rm -e ${GOTESTENV} -v $(PWD):/app:rw,z -w /app golangci/golangci-lint:v2.12.2 golangci-lint run -v

lint-fix:
	@echo "Running golangci-lint run --fix"
	@$(DOCKER) run -t --rm -e ${GOTESTENV} -v $(PWD):/app:rw,z -w /app golangci/golangci-lint:v2.12.2 golangci-lint run --fix -v

.PHONY: pr-check
# generate pr-check
pr-check:
	make generate;
	make test;
	make lint;
	make build;

.PHONY: run
# run parsec locally
run: build
	./bin/parsec serve --config ./configs/parsec.yaml

run-help: build
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
