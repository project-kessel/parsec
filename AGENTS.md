For how to...
- implement instrumentation (observability: tracing, logging, metrics, ...), see docs/observer-pattern.md
- write tests, see docs/testing.md
- run tests, don't be afraid to run the whole suite even if some tests require containers.
- write constructors: required parameters are positional (so new required fields break call sites at compile time); use the functional "Option" pattern only for optional parameters, with exported `With…` functions against a package-private config struct.