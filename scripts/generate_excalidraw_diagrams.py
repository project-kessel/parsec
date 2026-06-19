#!/usr/bin/env python3
"""Generate Excalidraw diagrams for parsec entry points and flows."""

from __future__ import annotations

import json
import random
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "diagrams"

_rng = random.Random(42)


def _id() -> str:
    return "".join(_rng.choices(string.ascii_letters + string.digits, k=16))


def _seed() -> int:
    return _rng.randint(1, 2**31 - 1)


@dataclass
class Scene:
    title: str
    elements: list[dict[str, Any]] = field(default_factory=list)
    _counter: int = 0

    def _next_y(self, gap: int = 20) -> int:
        if not self.elements:
            return 40
        max_y = max(e.get("y", 0) + e.get("height", 0) for e in self.elements)
        return int(max_y + gap)

    def box(
        self,
        text: str,
        *,
        x: float,
        y: float,
        width: float,
        height: float,
        bg: str = "#a5d8ff",
        stroke: str = "#1e1e1e",
        font_size: int = 16,
        align: str = "center",
    ) -> str:
        box_id = _id()
        text_id = _id()
        self.elements.append(
            {
                "id": box_id,
                "type": "rectangle",
                "x": x,
                "y": y,
                "width": width,
                "height": height,
                "angle": 0,
                "strokeColor": stroke,
                "backgroundColor": bg,
                "fillStyle": "solid",
                "strokeWidth": 2,
                "strokeStyle": "solid",
                "roughness": 1,
                "opacity": 100,
                "groupIds": [],
                "frameId": None,
                "roundness": {"type": 3},
                "seed": _seed(),
                "version": 1,
                "versionNonce": _seed(),
                "isDeleted": False,
                "boundElements": [{"type": "text", "id": text_id}],
                "updated": 1,
                "link": None,
                "locked": False,
            }
        )
        self.elements.append(
            {
                "id": text_id,
                "type": "text",
                "x": x + 8,
                "y": y + height / 2 - font_size / 2,
                "width": width - 16,
                "height": font_size + 8,
                "angle": 0,
                "strokeColor": stroke,
                "backgroundColor": "transparent",
                "fillStyle": "solid",
                "strokeWidth": 1,
                "strokeStyle": "solid",
                "roughness": 1,
                "opacity": 100,
                "groupIds": [],
                "frameId": None,
                "roundness": None,
                "seed": _seed(),
                "version": 1,
                "versionNonce": _seed(),
                "isDeleted": False,
                "boundElements": None,
                "updated": 1,
                "link": None,
                "locked": False,
                "text": text,
                "fontSize": font_size,
                "fontFamily": 1,
                "textAlign": align,
                "verticalAlign": "middle",
                "containerId": box_id,
                "originalText": text,
                "autoResize": True,
                "lineHeight": 1.25,
            }
        )
        return box_id

    def label(self, text: str, *, x: float, y: float, width: float = 400, font_size: int = 20) -> None:
        text_id = _id()
        lines = text.count("\n") + 1
        height = lines * (font_size + 6)
        self.elements.append(
            {
                "id": text_id,
                "type": "text",
                "x": x,
                "y": y,
                "width": width,
                "height": height,
                "angle": 0,
                "strokeColor": "#1e1e1e",
                "backgroundColor": "transparent",
                "fillStyle": "solid",
                "strokeWidth": 1,
                "strokeStyle": "solid",
                "roughness": 1,
                "opacity": 100,
                "groupIds": [],
                "frameId": None,
                "roundness": None,
                "seed": _seed(),
                "version": 1,
                "versionNonce": _seed(),
                "isDeleted": False,
                "boundElements": None,
                "updated": 1,
                "link": None,
                "locked": False,
                "text": text,
                "fontSize": font_size,
                "fontFamily": 1,
                "textAlign": "left",
                "verticalAlign": "top",
                "containerId": None,
                "originalText": text,
                "autoResize": True,
                "lineHeight": 1.25,
            }
        )

    def arrow(
        self,
        from_id: str,
        to_id: str,
        *,
        label: str | None = None,
        color: str = "#1e1e1e",
    ) -> None:
        from_el = next((e for e in self.elements if e["id"] == from_id), None)
        to_el = next((e for e in self.elements if e["id"] == to_id), None)
        if not from_el:
            raise ValueError(f"Arrow source element not found: {from_id}")
        if not to_el:
            raise ValueError(f"Arrow target element not found: {to_id}")

        x1 = from_el["x"] + from_el["width"] / 2
        y1 = from_el["y"] + from_el["height"]
        x2 = to_el["x"] + to_el["width"] / 2
        y2 = to_el["y"]

        arrow_id = _id()
        self.elements.append(
            {
                "id": arrow_id,
                "type": "arrow",
                "x": x1,
                "y": y1,
                "width": x2 - x1,
                "height": y2 - y1,
                "angle": 0,
                "strokeColor": color,
                "backgroundColor": "transparent",
                "fillStyle": "solid",
                "strokeWidth": 2,
                "strokeStyle": "solid",
                "roughness": 1,
                "opacity": 100,
                "groupIds": [],
                "frameId": None,
                "roundness": {"type": 2},
                "seed": _seed(),
                "version": 1,
                "versionNonce": _seed(),
                "isDeleted": False,
                "boundElements": None,
                "updated": 1,
                "link": None,
                "locked": False,
                "points": [[0, 0], [x2 - x1, y2 - y1]],
                "lastCommittedPoint": None,
                "startBinding": {"elementId": from_id, "focus": 0, "gap": 4},
                "endBinding": {"elementId": to_id, "focus": 0, "gap": 4},
                "startArrowhead": None,
                "endArrowhead": "arrow",
                "elbowed": False,
            }
        )
        if label:
            self.label(label, x=(x1 + x2) / 2 + 10, y=(y1 + y2) / 2 - 10, width=200, font_size=14)

    def flow_steps(self, steps: list[str], *, x: float = 80, width: float = 520, step_h: float = 56) -> None:
        self.label(self.title, x=x, y=20, width=width + 120, font_size=24)
        prev: str | None = None
        y = 70
        for step in steps:
            box_id = self.box(step, x=x, y=y, width=width, height=step_h, bg="#d0ebff")
            if prev:
                self.arrow(prev, box_id)
            prev = box_id
            y += step_h + 30

    def sequence(
        self,
        participants: list[str],
        messages: list[tuple[str, str, str]],
        *,
        x_start: float = 60,
        y_start: float = 80,
        col_w: float = 140,
        row_h: float = 70,
    ) -> None:
        self.label(self.title, x=x_start, y=20, width=900, font_size=24)
        p_ids: dict[str, str] = {}
        for i, name in enumerate(participants):
            x = x_start + i * col_w
            p_ids[name] = self.box(name, x=x, y=y_start, width=col_w - 20, height=50, bg="#ffd8a8")

        lifeline_y = y_start + 70
        for i in range(len(participants)):
            x = x_start + i * col_w + (col_w - 20) / 2
            line_id = _id()
            self.elements.append(
                {
                    "id": line_id,
                    "type": "line",
                    "x": x,
                    "y": lifeline_y,
                    "width": 0,
                    "height": row_h * len(messages) + 40,
                    "angle": 0,
                    "strokeColor": "#868e96",
                    "backgroundColor": "transparent",
                    "fillStyle": "solid",
                    "strokeWidth": 1,
                    "strokeStyle": "dashed",
                    "roughness": 0,
                    "opacity": 100,
                    "groupIds": [],
                    "frameId": None,
                    "roundness": None,
                    "seed": _seed(),
                    "version": 1,
                    "versionNonce": _seed(),
                    "isDeleted": False,
                    "boundElements": None,
                    "updated": 1,
                    "link": None,
                    "locked": False,
                    "points": [[0, 0], [0, row_h * len(messages) + 40]],
                    "lastCommittedPoint": None,
                    "startBinding": None,
                    "endBinding": None,
                    "startArrowhead": None,
                    "endArrowhead": None,
                }
            )

        y = lifeline_y + 20
        for src, dst, msg in messages:
            if src not in participants:
                raise ValueError(f"Unknown participant '{src}' in message '{msg}'")
            if dst not in participants:
                raise ValueError(f"Unknown participant '{dst}' in message '{msg}'")
            src_idx = participants.index(src)
            dst_idx = participants.index(dst)
            x1 = x_start + src_idx * col_w + (col_w - 20) / 2
            x2 = x_start + dst_idx * col_w + (col_w - 20) / 2
            arrow_id = _id()
            self.elements.append(
                {
                    "id": arrow_id,
                    "type": "arrow",
                    "x": min(x1, x2),
                    "y": y,
                    "width": abs(x2 - x1),
                    "height": 0,
                    "angle": 0,
                    "strokeColor": "#1e1e1e",
                    "backgroundColor": "transparent",
                    "fillStyle": "solid",
                    "strokeWidth": 2,
                    "strokeStyle": "solid",
                    "roughness": 1,
                    "opacity": 100,
                    "groupIds": [],
                    "frameId": None,
                    "roundness": {"type": 2},
                    "seed": _seed(),
                    "version": 1,
                    "versionNonce": _seed(),
                    "isDeleted": False,
                    "boundElements": None,
                    "updated": 1,
                    "link": None,
                    "locked": False,
                    "points": [[0, 0], [x2 - x1, 0]],
                    "lastCommittedPoint": None,
                    "startBinding": None,
                    "endBinding": None,
                    "startArrowhead": src_idx < dst_idx and "arrow" or None,
                    "endArrowhead": dst_idx < src_idx and "arrow" or None,
                    "elbowed": False,
                }
            )
            self.label(msg, x=min(x1, x2) + 8, y=y - 18, width=abs(x2 - x1) - 16, font_size=12)
            y += row_h

    def save(self, filename: str) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        path = OUTPUT_DIR / filename
        doc = {
            "type": "excalidraw",
            "version": 2,
            "source": "https://excalidraw.com",
            "elements": self.elements,
            "appState": {
                "gridSize": 20,
                "viewBackgroundColor": "#ffffff",
            },
            "files": {},
        }
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return path


def bootstrap_flow() -> Scene:
    s = Scene("parsec serve — Bootstrap Flow")
    s.flow_steps(
        [
            "1. Load config\n(file → PARSEC_* env → CLI flags)",
            "2. config.Provider builds components\n(Observer, TrustStore, TokenService, registries)",
            "3. Create handlers\n(AuthzServer, ExchangeServer, JWKSServer)",
            "4. Start JWKS background cache refresh",
            "5. Bind TCP listeners\n(gRPC :9090, HTTP :8080)",
            "6. server.Start()\nRegister gRPC services + grpc-gateway",
            "7. srv.SetReady()\nHealth → SERVING",
            "8. Wait SIGINT/SIGTERM → graceful shutdown",
        ]
    )
    return s


def server_architecture() -> Scene:
    s = Scene("Server Architecture — Dual Protocol Stack")
    grpc = s.box(
        "gRPC Server :9090\n\n• ext_authz (Authorization)\n• TokenExchangeService\n• JWKSService\n• grpc.health.v1.Health\n• reflection",
        x=200,
        y=70,
        width=360,
        height=200,
        bg="#d0ebff",
    )
    gw = s.box(
        "grpc-gateway\n(passthrough dial)",
        x=290,
        y=310,
        width=180,
        height=60,
        bg="#e9ecef",
    )
    http = s.box(
        "HTTP Server :8080\n\nGET  /healthz/live | /healthz/ready\nPOST /v1/token\nGET  /v1/jwks.json\nGET  /.well-known/jwks.json\n(+ /metrics via observer)",
        x=200,
        y=410,
        width=360,
        height=180,
        bg="#b2f2bb",
    )
    envoy = s.box("Envoy / gRPC clients", x=40, y=120, width=140, height=50, bg="#ffd8a8")
    http_clients = s.box("HTTP clients", x=40, y=480, width=140, height=50, bg="#ffd8a8")

    s.arrow(envoy, grpc, label="gRPC")
    s.arrow(http_clients, http, label="HTTP")
    s.arrow(grpc, gw)
    s.arrow(gw, http)
    return s


def authz_flow() -> Scene:
    s = Scene("ext_authz — AuthzServer.Check")
    s.flow_steps(
        [
            "Envoy CheckRequest",
            "buildRequestAttributes()\n(method, path, headers, IP, extensions)",
            "extractActorCredential()\n(mTLS cert or Bearer in gRPC metadata)",
            "trustStore.Validate(actor) → actor Result (or anonymous)",
            "trustStore.ForActor(actor) → filtered validator set",
            "extractCredential()\n(Bearer from Authorization header)",
            "filteredStore.Validate(subject)",
            "tokenService.IssueTokens()",
            "CheckResponse OK\n+ Transaction-Token header\n− strip external credential headers",
        ],
        width=560,
        step_h=62,
    )
    return s


def exchange_flow() -> Scene:
    s = Scene("Token Exchange — ExchangeServer.Exchange")
    s.flow_steps(
        [
            "ExchangeRequest\n(grant_type, subject_token, audience, scope, request_context)",
            "Validate grant_type = token-exchange",
            "extractActorCredential() + validate actor",
            "Parse/filter request_context\n(base64 JSON → claims filter by actor)",
            "trustStore.ForActor(actor)",
            "Validate subject_token as BearerCredential",
            "Determine token type (default: transaction token)",
            "Validate audience matches trust domain",
            "tokenService.IssueTokens()",
            "ExchangeResponse\n(access_token, issued_token_type, expires_in)",
        ],
        width=560,
        step_h=62,
    )
    return s


def jwks_flow() -> Scene:
    s = Scene("JWKS Discovery — JWKSServer.GetJWKS")
    s.flow_steps(
        [
            "Client request\nGET /v1/jwks.json or /.well-known/jwks.json\n(or gRPC GetJWKS)",
            "HTTP → grpc-gateway → gRPC GetJWKS",
            "Check in-memory cache",
            "Cache hit → return cached JWKS",
            "Cache miss → refreshCache()\n(collect public keys from IssuerRegistry)",
            "Background ticker refreshes cache every 1 min",
            "Return GetJWKSResponse\n(public keys for token verification)",
        ],
        width=560,
        step_h=58,
    )
    return s


def dual_identity() -> Scene:
    s = Scene("Dual Identity Model")
    actor = s.box(
        "Actor\n\nSource: mTLS cert or Bearer\nin gRPC metadata\n\nRole: Who calls parsec\n(gateway, service)",
        x=80,
        y=80,
        width=280,
        height=160,
        bg="#ffd8a8",
    )
    subject = s.box(
        "Subject\n\nSource: Bearer in HTTP headers\n(authz) or subject_token\n(exchange)\n\nRole: End user / principal",
        x=420,
        y=80,
        width=280,
        height=160,
        bg="#d0ebff",
    )
    core = s.box(
        "Shared pipeline\n\nForActor() filters validators\nIssueTokens(subject + actor)",
        x=200,
        y=300,
        width=380,
        height=100,
        bg="#b2f2bb",
    )
    s.arrow(actor, core)
    s.arrow(subject, core)
    s.label(
        "Enables: service X acting on behalf of user Y",
        x=200,
        y=430,
        width=400,
        font_size=16,
    )
    return s


def token_issuance() -> Scene:
    s = Scene("Token Issuance Pipeline")
    s.flow_steps(
        [
            "IssueRequest\n{ Subject, Actor, RequestAttributes, TokenTypes, Scope }",
            "issuerRegistry.GetIssuer(tokenType)",
            "Claim mappers (CEL)\nbuild tctx + req_ctx claims",
            "DataSources (Lua/HTTP)\nenrich lazily during mapping",
            "Sign JWT (TransactionTokenIssuer)\nor unsigned token",
            "Return Token { Value, IssuedAt, ExpiresAt }",
        ],
        width=540,
        step_h=62,
    )
    return s


def perimeter_sequence() -> Scene:
    s = Scene("Perimeter Flow (Envoy)")
    s.sequence(
        ["Client", "Envoy", "parsec\n(ext_authz)", "Backend"],
        [
            ("Client", "Envoy", "HTTP + external Bearer token"),
            ("Envoy", "parsec\n(ext_authz)", "gRPC Check (headers, path, actor mTLS)"),
            ("parsec\n(ext_authz)", "parsec\n(ext_authz)", "validate actor + subject"),
            ("parsec\n(ext_authz)", "parsec\n(ext_authz)", "issue transaction token"),
            ("parsec\n(ext_authz)", "Envoy", "OK + Transaction-Token\nstrip Authorization"),
            ("Envoy", "Backend", "forwarded request\n(no external creds)"),
        ],
        col_w=180,
        row_h=65,
    )
    return s


def token_exchange_sequence() -> Scene:
    s = Scene("Direct Token Exchange Flow")
    s.sequence(
        ["Client", "HTTP\n:8080", "grpc-gateway", "gRPC\n:9090"],
        [
            ("Client", "HTTP\n:8080", "POST /v1/token (form or JSON)"),
            ("HTTP\n:8080", "grpc-gateway", "route to gateway"),
            ("grpc-gateway", "gRPC\n:9090", "Exchange RPC"),
            ("gRPC\n:9090", "gRPC\n:9090", "validate + issue token"),
            ("gRPC\n:9090", "grpc-gateway", "ExchangeResponse"),
            ("grpc-gateway", "HTTP\n:8080", "JSON OAuth token response"),
            ("HTTP\n:8080", "Client", "access_token (transaction token)"),
        ],
        col_w=160,
        row_h=60,
    )
    return s


def entry_point_overview() -> Scene:
    s = Scene("parsec Entry Point Overview")
    main = s.box("cmd/parsec/main.go\nmain() → cli.Execute()", x=260, y=60, width=280, height=60, bg="#e9ecef")
    cli = s.box("parsec serve\n(internal/cli/serve.go)", x=260, y=160, width=280, height=60, bg="#d0ebff")
    provider = s.box(
        "config.Provider\nTrustStore · TokenService · Observer",
        x=260,
        y=260,
        width=280,
        height=70,
        bg="#d0ebff",
    )
    authz = s.box("AuthzServer\next_authz gRPC", x=60, y=390, width=200, height=70, bg="#ffd8a8")
    exchange = s.box("ExchangeServer\nPOST /v1/token", x=300, y=390, width=200, height=70, bg="#b2f2bb")
    jwks = s.box("JWKSServer\nGET /v1/jwks.json", x=540, y=390, width=200, height=70, bg="#b2f2bb")
    token = s.box("TokenService.IssueTokens()", x=260, y=510, width=280, height=60, bg="#ffc9c9")

    s.arrow(main, cli)
    s.arrow(cli, provider)
    s.arrow(provider, authz)
    s.arrow(provider, exchange)
    s.arrow(provider, jwks)
    s.arrow(authz, token)
    s.arrow(exchange, token)
    return s


DIAGRAMS = [
    ("01-entry-point-overview.excalidraw", entry_point_overview),
    ("02-bootstrap-flow.excalidraw", bootstrap_flow),
    ("03-server-architecture.excalidraw", server_architecture),
    ("04-ext-authz-flow.excalidraw", authz_flow),
    ("05-token-exchange-flow.excalidraw", exchange_flow),
    ("06-jwks-flow.excalidraw", jwks_flow),
    ("07-dual-identity-model.excalidraw", dual_identity),
    ("08-token-issuance-pipeline.excalidraw", token_issuance),
    ("09-perimeter-envoy-sequence.excalidraw", perimeter_sequence),
    ("10-token-exchange-sequence.excalidraw", token_exchange_sequence),
]


def main() -> None:
    paths: list[Path] = []
    for filename, builder in DIAGRAMS:
        path = builder().save(filename)
        paths.append(path)
        print(f"Wrote {path}")

    readme = OUTPUT_DIR / "README.md"
    lines = [
        "# parsec Flow Diagrams (Excalidraw)",
        "",
        "Open these `.excalidraw` files in:",
        "",
        "- [excalidraw.com](https://excalidraw.com) (File → Open)",
        "- VS Code [Excalidraw extension](https://marketplace.visualstudio.com/items?itemName=pomdtr.excalidraw-editor)",
        "- Obsidian Excalidraw plugin",
        "",
        "## Diagrams",
        "",
    ]
    titles = {
        "01-entry-point-overview.excalidraw": "Entry point overview (main → serve → services)",
        "02-bootstrap-flow.excalidraw": "`parsec serve` bootstrap sequence",
        "03-server-architecture.excalidraw": "Dual protocol stack (gRPC + HTTP/grpc-gateway)",
        "04-ext-authz-flow.excalidraw": "Envoy ext_authz `AuthzServer.Check` flow",
        "05-token-exchange-flow.excalidraw": "RFC 8693 `ExchangeServer.Exchange` flow",
        "06-jwks-flow.excalidraw": "JWKS discovery flow",
        "07-dual-identity-model.excalidraw": "Actor vs subject identity model",
        "08-token-issuance-pipeline.excalidraw": "Token issuance pipeline",
        "09-perimeter-envoy-sequence.excalidraw": "Perimeter sequence (Envoy)",
        "10-token-exchange-sequence.excalidraw": "Direct token exchange sequence",
    }
    for filename, _ in DIAGRAMS:
        lines.append(f"- [{titles[filename]}](./{filename})")
    lines.extend(["", "Regenerate with:", "", "```bash", "python3 scripts/generate_excalidraw_diagrams.py", "```", ""])
    readme.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {readme}")


if __name__ == "__main__":
    main()
