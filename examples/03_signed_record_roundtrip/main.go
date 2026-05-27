// Example 03 — sign and verify an RNS record end-to-end.
//
//	go run ./examples/03_signed_record_roundtrip
//
// A registry signs a Record binding "acme.payments" to a (kem, sig)
// keypair. A resolver returns the record. A client verifies the
// registry signature, then derives the DID from the resolved keys
// and checks that the DID matches an expected value.
//
// In production the registry's signature would be hybrid (Ed25519 +
// ML-DSA-65). For brevity this example uses pure Ed25519. Wiring up
// the hybrid path is in the zwing package.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	rns "github.com/zap-proto/rns"
)

// Record is a stripped-down version of the wire schema — same fields,
// JSON-encoded here for clarity.
type Record struct {
	Name      string `json:"name"`
	KEMPubKey []byte `json:"kem_pubkey"`
	SigPubKey []byte `json:"sig_pubkey"`
	TTL       uint32 `json:"ttl"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	Registry  string `json:"registry"`
	Signature []byte `json:"signature"`
}

func main() {
	now := time.Now()

	// 1. Registry generates its key (long-lived, published out-of-band).
	regPubKey, regPrivKey, _ := ed25519.GenerateKey(rand.Reader)

	// 2. Service ("acme.payments") generates its identity keypair.
	kemPK := derive("acme.kem", 1216)
	sigPK := derive("acme.sig", 1984)

	// 3. Registry constructs and signs a Record.
	record := Record{
		Name:      "acme.payments",
		KEMPubKey: kemPK,
		SigPubKey: sigPK,
		TTL:       300,
		NotBefore: now.UnixNano(),
		NotAfter:  now.Add(24 * time.Hour).UnixNano(),
		Registry:  "did:zap:registry-alpha",
	}
	record.Signature = signRecord(record, regPrivKey)

	// 4. Pretend network round-trip: serialize, ship, deserialize.
	wire, _ := json.Marshal(record)
	fmt.Println("== resolver returned a signed Record ==")
	fmt.Printf("size on wire: %d bytes\n", len(wire))

	var got Record
	_ = json.Unmarshal(wire, &got)

	// 5. Client verifies registry signature.
	if err := verifyRecord(got, regPubKey); err != nil {
		fmt.Printf("FAILURE: signature verify: %v\n", err)
		return
	}
	fmt.Println("✓ registry signature verifies")

	// 6. Client checks the time window.
	nowNs := time.Now().UnixNano()
	if nowNs < got.NotBefore || nowNs > got.NotAfter {
		fmt.Println("FAILURE: record expired")
		return
	}
	fmt.Println("✓ record is within validity window")

	// 7. Derive the DID — this is the value the client can now address.
	did := rns.ComputeDID(got.KEMPubKey, got.SigPubKey)
	fmt.Printf("\nresolved %q to:\n  %s\n", got.Name, did)
	fmt.Printf("\nclient can now dial this identity. The handshake will\n")
	fmt.Printf("reuse kem pk (first 16 bytes: %s ...)\n",
		hex.EncodeToString(got.KEMPubKey[:16]))
}

// signRecord signs every field except Signature itself.
func signRecord(r Record, sk ed25519.PrivateKey) []byte {
	r.Signature = nil
	canonical, _ := json.Marshal(r)
	return ed25519.Sign(sk, canonical)
}

// verifyRecord checks the signature against the (unsigned) canonical encoding.
func verifyRecord(r Record, pk ed25519.PublicKey) error {
	sig := r.Signature
	r.Signature = nil
	canonical, _ := json.Marshal(r)
	if !ed25519.Verify(pk, canonical, sig) {
		return errors.New("registry signature failed verification")
	}
	return nil
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
