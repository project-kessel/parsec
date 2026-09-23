# parsec

An experiment in [transaction tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) and generalizable trust architecture.

parsec is an implementation of [ext_authz](https://pkg.go.dev/github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3) and [token exchange](https://datatracker.ietf.org/doc/rfc8693/). It is intended to be used by the perimeter of a trust domain in order to:

- abstract away validating credentials from external trust domains (removing those credentials for services within the trust domain)
- issue trusted authorization context for a call chain (transaction token)

It is intended to be used as part of a general federated trust architecture that defines a (1) workload trust domain (expected to be abstracted in the network e.g. through a service mesh) and (2) a [potentially wider] transaction trust domain, established by this service as a transction token issuer.

## Security & Deployment Model

**TLS Termination**: parsec is designed to run within a service mesh (Envoy/Istio) or behind a TLS-terminating ingress controller. The gRPC and HTTP servers bind to plaintext listeners and rely on the mesh/sidecar for TLS termination, mTLS between services, and network-level authentication.

- **In-mesh deployment (production)**: TLS is handled by the Envoy sidecar or mesh proxy. Parsec exposes plaintext gRPC (port 9090) and HTTP (port 8080) endpoints that are only accessible within the mesh.
- **Standalone/non-mesh deployment**: Not recommended for production. If parsec must run outside a service mesh, implement external TLS termination (e.g., via Nginx, HAProxy, or cloud load balancer) before deploying to production.

For vulnerability reporting and security policy, see [SECURITY.md](SECURITY.md).

## Building and Pushing the Container Image

Log in to the required registries, then run the `docker-build-push` target with your image destination. The base image is pulled from `registry.access.redhat.com` during the build, so both logins are required.

    podman login quay.io                     # or: docker login quay.io
    podman login registry.access.redhat.com  # or: docker login registry.access.redhat.com

    make docker-build-push IMAGE=quay.io/your-org/parsec

If the build fails with an authentication error mentioning `registry.access.redhat.com`, ensure you are logged in using your Red Hat Customer Portal credentials. See the [Red Hat Registry Authentication guide](https://access.redhat.com/RegistryAuthentication) for details.

`podman` is used automatically if available, otherwise `docker` is used. Override with `DOCKER=docker make docker-build-push IMAGE=quay.io/your-org/parsec`.