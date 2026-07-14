# Testing

Tests are done deterministically and [hermetically](https://testing.googleblog.com/2018/11/testing-on-toilet-exercise-service-call.html).

## No I/O

By default, there is NO external I/O in tests. This often includes syscalls (e.g. time, randomization). This means you often need to design main code to support testability:

* Instead of using time directly, inject a Clock abstraction, OR use [synctest](https://go.dev/blog/testing-time)  
* Instead of databases or queues, use in memory fakes  
* Instead of using the filesystem directly, inject a filesystem abstraction (either [io/fs](https://pkg.go.dev/io/fs) or something more full featured like [afero](https://github.com/spf13/afero))  
* Instead of using randomness directly, inject an abstract source of randomness and use a deterministic version for tests

Never use time.Sleep in a test. Use a clock abstraction to advance the time, or [deterministic concurrency](#deterministic-concurrency).

The only exception is when the code under test itself is necessarily coupled to external I/O. If you have a PostgresRepository, you obviously have to test it by connecting to a postgres instance. But if you aren't specifically testing the implementation of something dependent on I/O, avoiding it will improve your tests and your designs.

## Observability

Observability is often untested or awkward to test. Take advantage of the [Domain Oriented Observability](https://martinfowler.com/articles/domain-oriented-observability.html) pattern. We don't need excessive coverage of observability concerns, as these are often tested automatically by virtue of alert rules on metrics. Testing observability is therefore a judgement call on the importance, complexity, and how likely and how quickly a regression is to be caught in production under normal operation. When it is warranted though, this pattern makes it much simpler to do so.

For real world examples in a Go codebase, see [this](https://github.com/project-kessel/parsec/blob/main/internal/service/observer.go) and [this](https://github.com/alechenninger/falcon/blob/main/internal/domain/observer.go).

## Benchmarks

Benchmarks live alongside tests in `*_bench_test.go` files and use the standard `testing.B` API with `b.ReportAllocs()`.

### Running benchmarks

```bash
# Run all benchmarks in a package
go test ./internal/probe/otel/ -bench=. -benchmem

# Run a specific benchmark by name (regex)
go test ./internal/probe/otel/ -bench=BenchmarkProbeRecord_StatusOnly -benchmem

# Run with multiple iterations for stability
go test ./internal/probe/otel/ -bench=. -benchmem -count=5
```

Benchmarks do NOT run with a plain `go test` — the `-bench` flag is required.

### OTel metric probe benchmarks

`internal/probe/otel/observer_bench_test.go` verifies that the `WithAttributeSet` attribute strategy keeps per-recording allocations minimal. The benchmarks cover all three strategies:

| Benchmark | Strategy | Expected behavior |
|-----------|----------|-------------------|
| `BenchmarkProbeRecord_StatusOnly` | Package-level pre-built attribute set | Zero attribute allocs at `End()` |
| `BenchmarkProbeRecord_StatusOnly_Error` | Same, error path | Zero attribute allocs at `End()` |
| `BenchmarkProbeRecord_KnownAtStartAttrs` | Attribute set built in `*Started` | Zero attribute allocs at `End()` (cost amortized in probe creation) |
| `BenchmarkProbeRecord_KnownAtStartAttrs_Error` | Same, error path | Zero attribute allocs at `End()` |
| `BenchmarkProbeRecord_MidFlightAttrs` | `attribute.NewSet` built in `End()` | One set construction (unavoidable for dynamic values) |
| `BenchmarkProbeRecord_ServeFailedStatic` | Package-level static set, counter only | Near-zero overhead |

Any remaining allocations (typically 1–4 per op) originate from the OTel SDK's internal recording pipeline, not from attribute construction.

## Deterministic concurrency

Coordinating threads / goroutines is sometimes necessary in tests. To do this deterministically and cleanly, take advantage of the [Domain Oriented Observability](https://martinfowler.com/articles/domain-oriented-observability.html) pattern. The main code is coupled on to an interface with certain probe points. Then, an implementation of this injected at test time uses these probes to block, or signal waiting code.

For an example of how to do this, see [this](https://github.com/alechenninger/falcon/blob/ae638df2a195b903a76e414db00d3aa32078a09a/internal/domain/observer.go#L252).

## No Mocks (and RARELY stubs!)

No "method verifying" mocks, ever.

Prefer simply using a real instance. If an object is not coupled to external I/O, there is no reason not to reuse it. It is the least work and the best coverage.

If it is, prefer using a Fake. In memory fakes are a useful feature of an application ("Kessel in a box"), so the investment pays for itself quickly. When implementing fakes (or any second implementation of an interface), first define a set of "contract tests" at the interface layer.

Stubs or dummies can be used judiciously when the interaction is completely trivial, but this is rare. There is usually no point if the in memory version is just as fast.

## Hermetic

When external dependencies are needed, leverage testcontainers to download and run them locally. This should only be for when this is essential. For example, we can't test a PostgresStore without a Postgres. Writing a "fake" postgres is absurd 🙂. But, if you need to test business logic that involves a repository, using a real postgres is overkill. Just use the in memory fake (e.g. a custom in memory implementation, or sqlite with an in memory database, etc.).

## E2E Tests

E2E tests live in `test/e2e/` and have additional rules beyond general testing guidelines. See [test/e2e/README.md](../test/e2e/README.md) for the full specification.

Key rule: test actions and assertions must go through the external gRPC API (`Check()` or `Exchange()`). Using internal packages to set up hermetic fixtures and wire the server is expected, but the system under test must only be exercised via its public API.