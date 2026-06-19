# parsec Flow Diagrams (Excalidraw)

Open these `.excalidraw` files in:

- [excalidraw.com](https://excalidraw.com) (File → Open)
- VS Code [Excalidraw extension](https://marketplace.visualstudio.com/items?itemName=pomdtr.excalidraw-editor)
- Obsidian Excalidraw plugin

## Diagrams

- [Entry point overview (main → serve → services)](./01-entry-point-overview.excalidraw)
- [`parsec serve` bootstrap sequence](./02-bootstrap-flow.excalidraw)
- [Dual protocol stack (gRPC + HTTP/grpc-gateway)](./03-server-architecture.excalidraw)
- [Envoy ext_authz `AuthzServer.Check` flow](./04-ext-authz-flow.excalidraw)
- [RFC 8693 `ExchangeServer.Exchange` flow](./05-token-exchange-flow.excalidraw)
- [JWKS discovery flow](./06-jwks-flow.excalidraw)
- [Actor vs subject identity model](./07-dual-identity-model.excalidraw)
- [Token issuance pipeline](./08-token-issuance-pipeline.excalidraw)
- [Perimeter sequence (Envoy)](./09-perimeter-envoy-sequence.excalidraw)
- [Direct token exchange sequence](./10-token-exchange-sequence.excalidraw)

Regenerate with:

```bash
python3 scripts/generate_excalidraw_diagrams.py
```
