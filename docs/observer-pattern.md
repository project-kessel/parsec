# Observer Pattern

Use when adding observability to domain or application components. Inspired by [Domain-Oriented Observability](https://martinfowler.com/articles/domain-oriented-observability.html).

## Structure

1. **Observer interface** — Entry point, returns Probes for operations
2. **Probe interface** — Tracks a single operation lifecycle
3. **NoOp implementations** — For forward compatibility and testing

## Naming

- Observer: `{Component}Observer` (e.g., `WidgetObserver`)
- Probe: `{Operation}Probe` (e.g., `WidgetUpdateProbe`)
- NoOp: `NoOp{Component}Observer`, `NoOp{Operation}Probe`

## Interface Pattern

```go
// {Component}Observer is called at key points during {Component} operations.
// Implementations should embed NoOp{Component}Observer for forward compatibility
// with new methods added to this interface.
type {Component}Observer interface {
    // {Op}Started is called when {Op} begins.
    // Returns a potentially modified context and a probe to track the operation.
    {Op}Started(ctx context.Context, ...) (context.Context, {Op}Probe)
}

// {Op}Probe tracks a single {Op} invocation.
// Implementations should embed NoOp{Op}Probe for forward compatibility.
type {Op}Probe interface {
    // Result is called with the operation result.
    Result(...)

    // Error is called when an error occurs.
    Error(err error)

    // End signals the operation is complete (for timing). Called via defer.
    End()
}
```

## NoOp Implementation

Always provide NoOp implementations in the same package as the interface:

```go
type NoOp{Component}Observer struct{}

func (NoOp{Component}Observer) {Op}Started(ctx context.Context, ...) (context.Context, {Op}Probe) {
    return ctx, NoOp{Op}Probe{}
}

type NoOp{Op}Probe struct{}

func (NoOp{Op}Probe) Result(...) {}
func (NoOp{Op}Probe) Error(error) {}
func (NoOp{Op}Probe) End() {}
```

## Observer Hierarchy

Observer interfaces mirror the exact component hierarchy of each domain package. There are at least two levels:

1. **Leaf observer** — Named after a specific component (e.g. `DualSlotRotatingSignerObserver`, `AWSKMSProviderObserver`, `JWTValidatorObserver`). Declares the `{Op}Started(ctx, ...) (ctx, {Op}Probe)` methods that component actually calls (see Interface Pattern above).
2. **Package aggregate** — One per domain package (e.g. `KeysObserver`, `TrustObserver`). Embeds all intermediates for that package.

Beyond that, there can be one or more **Intermediate observers**, depending on the depth of the interface hierarchy. If there are any at all, usually there is just one. They are named after the interface a component implements (e.g. `RotatingSignerObserver`, `KeyProviderObserver`, `ValidatorObserver`). Embeds one or more leaf observers, corresponding to the implementations of these interfaces.

The central `observer.Observer` in `internal/observer/` embeds all package aggregates and adds infrastructure methods: `Shutdown(context.Context) error` for resource lifecycle and `ConfigureHTTPMux(*http.ServeMux)` for HTTP endpoint registration (e.g. /metrics). These are **not** on the per-package aggregates (that would create ambiguous methods via embedding); they live only on the central interface and cascade through the composite tree.

Example from the `keys` package:

```
KeysObserver                         (package aggregate)
├── RotatingSignerObserver           (intermediate)
│   └── DualSlotRotatingSignerObserver   (leaf)
└── KeyProviderObserver              (intermediate)
    ├── AWSKMSProviderObserver           (leaf)
    ├── DiskProviderObserver             (leaf)
    └── InMemoryProviderObserver         (leaf)
```

Each level has a corresponding NoOp type. Intermediate and aggregate NoOps compose the NoOps below them:

```go
type NoOpRotatingSignerObserver struct {
    NoOpDualSlotRotatingSignerObserver
}

type NoOpKeyProviderObserver struct {
    NoOpAWSKMSProviderObserver
    NoOpDiskProviderObserver
    NoOpInMemoryProviderObserver
}

type NoOpKeysObserver struct {
    NoOpRotatingSignerObserver
    NoOpKeyProviderObserver
}
```

### Injection convention

**Constructors accept the most specific (leaf) observer they need.** A `DualSlotRotatingSigner` takes a `DualSlotRotatingSignerObserver`; an `AWSKMSKeyProvider` takes an `AWSKMSProviderObserver`. This keeps each component decoupled from siblings it knows nothing about.

**Config/wiring layers pass the package aggregate.** The config layer holds a `KeysObserver` and passes it to each constructor. This works because Go structural typing lets a wider interface satisfy a narrower one.

```go
// Config layer: passes the package aggregate
func buildSignerRegistry(..., keysObs keys.KeysObserver) { ... }

// Constructor: accepts only what it needs
type DualSlotRotatingSignerConfig struct {
    Observer DualSlotRotatingSignerObserver
}
```

## Example: Logging Implementation (probe package)

```go
type {Component}Observer struct {
    domain.NoOp{Component}Observer  // Embed for forward compatibility
    logger zerolog.Logger
}

func New{Component}Observer(logger zerolog.Logger) *{Component}Observer {
    return &{Component}Observer{logger: logger.With().Str("component", "{component}").Logger()}
}

func (o *{Component}Observer) {Op}Started(ctx context.Context, ...) (context.Context, domain.{Op}Probe) {
    return ctx, &{op}Probe{
        logger:    o.logger,
        ctx:       ctx,
        startTime: time.Now(),
        // capture input params...
    }
}

type {op}Probe struct {
    domain.NoOp{Op}Probe  // Embed for forward compatibility
    logger    zerolog.Logger
    ctx       context.Context
    startTime time.Time
    // state fields...
}

func (p *{op}Probe) End() {
    if p.err != nil {
        p.logger.Error().Err(p.err).Dur("duration", time.Since(p.startTime)).Msg("{op} failed")
        return
    }
    p.logger.Info().Dur("duration", time.Since(p.startTime)).Msg("{op} completed")
}
```

## Usage in Domain Code

```go
func (s *Service) DoOperation(ctx context.Context, ...) error {
    ctx, p := s.observer.DoOperationStarted(ctx, ...)
    defer p.End()

    // ... operation logic ...

    if err != nil {
        p.Error(err)
        return err
    }

    p.Result(...)
    return nil
}
```

## Lifecycle

The central `observer.Observer` has two infrastructure methods beyond domain observation:

- `Shutdown(ctx context.Context) error` — flushes and releases resources (e.g. an OTel MeterProvider).
- `ConfigureHTTPMux(mux *http.ServeMux)` — registers HTTP endpoints the observer needs (e.g. `/metrics` for Prometheus).

`observer.Compose` accepts `WithShutdown(fn)` and `WithHTTPMux(fn)` options to attach these behaviors. `CompositeAll` cascades both to all children. NoOp observers are no-ops.

Neither method is on per-package aggregate interfaces to avoid Go embedding ambiguity.

## Package Layout

- Observer and probe interfaces live in their domain package (e.g. `keys/observer.go`, `trust/observer.go`)
- Logging implementations live in `internal/probe/`
- The central composite and composition logic lives in `internal/observer/`
- Observer construction dispatch lives in `internal/config.Provider`, not in standalone constructors

## OTel Metrics: Implementation

When implementing metric probes (`internal/probe/otel/`), use `metric.WithAttributeSet` with pre-built `attribute.Set` values — never `metric.WithAttributes` with variadic key-values. The latter allocates and sorts on every `Record` call.

### Instrument convention

Each timed probe records a single `Float64Histogram` with unit `"s"`. Histograms provide count, sum, and distribution via Prometheus's `_count`, `_sum`, and `_bucket` suffixes, making separate counters redundant. The only standalone counter is `serveFailedTotal` (fire-and-forget events with no meaningful duration).

### Probe structure

Each probe holds a pointer to its parent observer (to access instruments), a `context.Context`, a `time.Time`, and `attribute.KeyValue` fields for every attribute it records. Probes do not embed a shared base type — each `End()` method is self-contained and records directly to the observer's instrument.

### Attribute fields

All probes follow a single, uniform pattern: store attribute values as `attribute.KeyValue` fields, build one `attribute.NewSet` at `End()`.

**`status`** — Every probe has a `status attribute.KeyValue` field, initialized to `successStatusAttr`. Failure methods assign `errorStatusAttr` directly — no branching at `End()`.

**`result`** — High-value probes with multiple distinct outcomes also carry a `result attribute.KeyValue` field. Success is the default; lifecycle methods assign specific failure reasons from package-level constants. Since `result` and `status` are perfectly correlated (every result value implies exactly one status value), adding both does not increase time series cardinality.

**Other attributes** — Domain attributes like `issuer`, `key_name`, or `datasource` are stored as `attribute.KeyValue` fields, set at probe creation. Enum-like values (cache `result`, rotation `result`) use pre-allocated package-level constants to avoid per-call allocations.

At `End()`, all fields are combined into a single `attribute.NewSet` and passed via `metric.WithAttributeSet`:

```go
func (p *jwtValidateProbe) End() {
    attrs := metric.WithAttributeSet(attribute.NewSet(p.validatorType, p.validator, p.result, p.status))
    p.obs.validateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}
```

## Key Principles

- Always use `defer p.End()` for timing accuracy
- Probes either emit signals throughout method calls, or may collect state via methods and only emit upon `End()`. It depends on signal best practices and what minimizes overhead. Logs usually emit at the end, unless the probe runs long.
- Include `request_id` from context in logs
- Check log level before constructing log messages

## Method Parameters

- **Cheap to obtain**: Parameters should already be available at the call site. Avoid requiring expensive computation, allocations, or I/O just to call an observer method.
- **Informative**: Parameters should provide enough context for useful logs, metrics, or traces (e.g., IDs, counts, interesting details, error details). Optimize for minimum runtime cost while maximizing information available to probes.
- **Domain-oriented**: Use domain types rather than primitives where practical. Speak in the language of the model.
