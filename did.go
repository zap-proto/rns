// Package rns implements the canonical DID computation for the Resource Name
// Service. The DID is the lowercase RFC 4648 base32 encoding of the SHA3-256
// of (kemPubKey || sigPubKey), prefixed with "did:zap:".
//
// Every language SDK MUST reproduce the same DID for the same inputs.
// The KAT vector in testdata/pqrns_kat.json is the conformance fixture.
package rns

import (
	"encoding/base32"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ComputeDID returns the canonical did:zap identifier for an identity
// composed of a KEM public key and a signature public key.
//
//   - kemPubKey: X-Wing static public key (1216 bytes)
//   - sigPubKey: hybrid Ed25519 + ML-DSA-65 verification key (1984 bytes)
//
// DID = "did:zap:" + base32(SHA3-256(kemPubKey || sigPubKey)) lowercase, no padding.
func ComputeDID(kemPubKey, sigPubKey []byte) string {
	h := sha3.Sum256(append(append([]byte{}, kemPubKey...), sigPubKey...))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:])
	return "did:zap:" + strings.ToLower(enc)
}
