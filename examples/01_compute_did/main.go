// Example 01 — compute a did:zap identifier from a PQ keypair.
//
//	go run ./examples/01_compute_did
//
// You can change the inputs and see how the DID derives from the keys.
// Any other SDK reading the same (kemPubKey, sigPubKey) gets the same DID.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	rns "github.com/zap-proto/rns"
)

func main() {
	// Fake an X-Wing pk (1216 bytes) and a hybrid sig pk (1984 bytes).
	// In a real deployment these come from `zwing.GenerateIdentity()`.
	kemPK := derive("kem-pubkey-for-acme.payments", 1216)
	sigPK := derive("sig-pubkey-for-acme.payments", 1984)

	did := rns.ComputeDID(kemPK, sigPK)

	fmt.Println("== PQ-RNS DID derivation ==")
	fmt.Printf("kem pk (first 16 bytes): %s ...\n", hex.EncodeToString(kemPK[:16]))
	fmt.Printf("sig pk (first 16 bytes): %s ...\n", hex.EncodeToString(sigPK[:16]))
	fmt.Println()
	fmt.Println(did)
}

// derive expands a seed into n bytes via repeated SHA-256.
// Stand-in for real PQ key generation in this example only.
func derive(seed string, n int) []byte {
	out := make([]byte, 0, n)
	var prev [32]byte = sha256.Sum256([]byte(seed))
	for len(out) < n {
		out = append(out, prev[:]...)
		prev = sha256.Sum256(prev[:])
	}
	return out[:n]
}
