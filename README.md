# zap-rns

> **Docs:** [Resource Name Service over ZAP](https://zap-proto.dev/docs/protocols/rns) · part of the [ZAP Protocol](https://zap-proto.io)


Resource Name Service over ZAP — service naming bound to KEM keypair.

[**zap-proto.io**](https://zap-proto.io) · [Spec](https://github.com/zap-proto/spec) · [Paper](https://github.com/zap-proto/papers/tree/main/rns-identity-binding) · [Discord](https://zap-proto.io/discord)

`zap-rns` layers service discovery semantics over the [ZAP transport](https://github.com/zap-proto/spec). Post-quantum confidentiality, mutual authentication, and zero-copy parse come from the wire; this repo only adds the service discovery message shape.

## Status

**v0.1 — schema-first.** This repo currently ships:

- [`schema/zap_rns.zap`](schema/zap_rns.zap) — wire format spec in ZAP schema language

Reference implementations (Go, Rust, TS) land in v0.2 once `zap-proto/spec` provides cross-language codegen for the schema.

## Why

| Property | DNS / mDNS / SPIFFE | `zap-rns` |
|---|---|---|
| Confidentiality | TLS (classical) | X-Wing hybrid PQ (default) |
| Authentication | bearer / TLS cert | KEM keypair at transport |
| Wire encoding | text or per-protocol binary | ZAP wire, zero-copy |
| Identity binding | DNS / cert chain | [zap-rns](https://github.com/zap-proto/rns) keypair |
| Future-quantum | classical only | hybrid by construction |

By the [composability theorem](https://github.com/zap-proto/papers/tree/main/composability), `zap-rns` inherits ZAP-base's PQ confidentiality and mutual auth automatically — no rns-specific PQ analysis required.

## Sub-protocol family

- [`zap-http`](https://github.com/zap-proto/http) — HTTP request/response over ZAP
- [`zap-ws`](https://github.com/zap-proto/ws) — multi-stream pubsub
- [`zap-fix`](https://github.com/zap-proto/fix) — FIX 4.4 / 5.0 trading channel
- [`zap-rns`](https://github.com/zap-proto/rns) — KEM-bound service naming
- [`zap-mcp`](https://github.com/zap-proto/mcp) — Model Context Protocol over ZAP
- [`zap-acp`](https://github.com/zap-proto/acp) — Agent Communication Protocol
- [`zap-a2a`](https://github.com/zap-proto/a2a) — Google Agent2Agent over ZAP

## License

MIT OR Apache-2.0