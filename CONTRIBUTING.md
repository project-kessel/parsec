# Contributing

## Pull Requests
All pull requests should be made against the `main` branch from your own fork of the repository. Please ensure that your pull request includes a clear description of the changes made and all CI checks pass.

## Linting & Formatting

[golangci-lint](https://github.com/golangci/golangci-lint) should be used to lint this project. CI will automatically run this, but you can run linting locally by running:

```bash
make lint # requires docker/podman to be installed
```

### IDE Formatting

It is recommended to have `goimports` installed locally and have your IDE set to auto-format on save. You can install it by running:

```bash
go install golang.org/x/tools/cmd/goimports@latest
```

For vscode users, you can set up your editor to use `goimports` for auto-formatting by adding the following to your workspace or user settings:

```json
{
  ...
  "go.formatTool": "goimports"
}
```

For jetbrains users see https://www.jetbrains.com/help/go/integration-with-go-tools.html#goimports

## Proto / API Changes

Parsec uses [buf](https://buf.build/) to manage protobuf definitions. Proto files live under `api/proto/`. When making changes:

1. Edit the `.proto` files under `api/proto/parsec/`
2. Regenerate the Go code and lint:
   ```bash
   make api
   ```
3. Verify generated code compiles:
   ```bash
   make local-build
   ```

## Running Tests

Run the full test suite with race detection and coverage:

```bash
make test
```

To generate an HTML coverage report:

```bash
make test-coverage
```

## Building

For local development builds (no FIPS):

```bash
make local-build
```

For production FIPS-enabled builds (typically done inside the Dockerfile):

```bash
make build
```

## PR Checklist

Before submitting a PR, run the full pre-check suite:

```bash
make pr-check
```

This runs `generate`, `test`, `lint`, and `local-build` to ensure everything passes.
