# zap-proto/rns

> **Docs:** [PQ-RNS](https://zap-proto.dev/docs/protocols/rns) · part of the [ZAP Protocol](https://zap-proto.io)

PQ-RNS — Resource Name Service over ZAP. Resolves human-readable names to post-quantum identity records (`kemPubKey + sigPubKey`) signed by the issuing registry. No CA, no DNS provider in the trust path.

## What's here

| | |
|---|---|
| `schema/zap_rns.zap` | Wire schema — `Record`, `Query`, `Response` |
| `did.go` | Canonical DID computation (`did:zap:<base32(SHA3-256(kemPk‖sigPk))>`) |
| `did_test.go` | Go conformance test using the KAT fixture |
| `testdata/pqrns_kat.json` | Cross-language KAT fixture — every SDK must reproduce |
| `examples/` | Four runnable end-to-end examples (see below) |

## Runnable examples

```bash
go run ./examples/01_compute_did              # derive a did:zap from a keypair
go run ./examples/02_dual_identity_collision  # show rotation surfaces in the DID
go run ./examples/03_signed_record_roundtrip  # registry signs → client verifies
go run ./examples/04_capability_mailbox       # PostCap vs ReadCap + revocation
```

Each builds in <1s from a clean checkout. Walkthroughs at [zap-proto.dev/docs/examples](https://zap-proto.dev/docs/examples).

## Cross-language KAT

The canonical DID for fixed inputs (1216 × `0x01` for KEM, 1984 × `0x02` for sig) is:

```
did:zap:ok7klbkh4p3udjjeo4n7hkevssfyhswx6zygqif3tiemjmbgz7fa
```

Every PQ-RNS implementation must reproduce this exactly. Conformance tests live in each SDK:

- **Go**: `go test ./...` (this repo)
- **TypeScript**: [zap-proto/ts](https://github.com/zap-proto/ts) `test/pqrns_did.test.ts`
- **Python**: [zap-proto/py](https://github.com/zap-proto/py) `tests/test_pqrns_did.py`
- **Rust**: [zap-proto/rust](https://github.com/zap-proto/rust) `tests/pqrns_did.rs`

Drop the same `testdata/pqrns_kat.json` into a new language port and write the local equivalent of the test — that's the floor of conformance.

## License

MIT
