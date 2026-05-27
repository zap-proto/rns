// Example 02 — show why both keys are bound into the DID.
//
//	go run ./examples/02_dual_identity_collision
//
// Two services share the same KEM public key but rotate their signature
// key (e.g. an emergency hybrid-sig rotation). They produce DIFFERENT
// DIDs even though the encryption key is identical. That's by design:
// a peer who learns the DID has already pinned both keys.
//
// Conversely, rotating just the KEM key (keeping the sig key) ALSO yields
// a different DID. Either rotation is a new identity. To preserve
// identity across rotations, use RNS Records — the registry's signature
// migrates the binding, not the DID.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	rns "github.com/zap-proto/rns"
)

func main() {
	kemA := derive("acme.kem.v1", 1216)
	sigA := derive("acme.sig.v1", 1984)
	sigB := derive("acme.sig.v2", 1984) // emergency rotation
	kemB := derive("acme.kem.v2", 1216) // rotated KEM only

	did_v1 := rns.ComputeDID(kemA, sigA)
	did_v2_sig_rotated := rns.ComputeDID(kemA, sigB)
	did_v3_kem_rotated := rns.ComputeDID(kemB, sigA)

	fmt.Println("== Identity rotation surfaces in the DID ==")
	fmt.Printf("kem v1 first16: %s\n", hex.EncodeToString(kemA[:16]))
	fmt.Printf("sig v1 first16: %s\n", hex.EncodeToString(sigA[:16]))
	fmt.Printf("sig v2 first16: %s\n", hex.EncodeToString(sigB[:16]))
	fmt.Printf("kem v2 first16: %s\n", hex.EncodeToString(kemB[:16]))
	fmt.Println()
	fmt.Printf("did v1 (kemA + sigA): %s\n", did_v1)
	fmt.Printf("did sig-rotated     : %s\n", did_v2_sig_rotated)
	fmt.Printf("did kem-rotated     : %s\n", did_v3_kem_rotated)
	fmt.Println()
	if did_v1 == did_v2_sig_rotated || did_v1 == did_v3_kem_rotated {
		fmt.Println("FAILURE: rotation collided with original DID")
		return
	}
	fmt.Println("OK: every rotation produces a fresh identity. Use RNS")
	fmt.Println("Records, not DID equality, to track 'same service' across")
	fmt.Println("rotations.")
}

func derive(seed string, n int) []byte {
	out := make([]byte, 0, n)
	var prev [32]byte = sha256.Sum256([]byte(seed))
	for len(out) < n {
		out = append(out, prev[:]...)
		prev = sha256.Sum256(prev[:])
	}
	return out[:n]
}
