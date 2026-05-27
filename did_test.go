package rns

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestDIDKAT verifies ComputeDID against the canonical KAT in
// testdata/pqrns_kat.json. Every language SDK that ships a PQ-RNS
// implementation MUST pass this same fixture; a divergence on the
// hash, byte order, base32 alphabet, or casing fails the test.
func TestDIDKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/pqrns_kat.json")
	if err != nil {
		t.Fatalf("read KAT fixture: %v", err)
	}

	var kat struct {
		DIDCanonical struct {
			Inputs struct {
				KEMHex string `json:"kem_pubkey_hex"`
				SigHex string `json:"sig_pubkey_hex"`
			} `json:"inputs"`
			Outputs struct {
				Sha3Hex string `json:"sha3_256_hex"`
				DID     string `json:"did"`
			} `json:"outputs"`
		} `json:"did_canonical"`
	}
	if err := json.Unmarshal(raw, &kat); err != nil {
		t.Fatalf("parse KAT: %v", err)
	}

	kemPK, err := hex.DecodeString(kat.DIDCanonical.Inputs.KEMHex)
	if err != nil {
		t.Fatalf("decode kem hex: %v", err)
	}
	sigPK, err := hex.DecodeString(kat.DIDCanonical.Inputs.SigHex)
	if err != nil {
		t.Fatalf("decode sig hex: %v", err)
	}

	if want, got := 1216, len(kemPK); got != want {
		t.Fatalf("kem pk size: got %d, want %d", got, want)
	}
	if want, got := 1984, len(sigPK); got != want {
		t.Fatalf("sig pk size: got %d, want %d", got, want)
	}

	got := ComputeDID(kemPK, sigPK)
	if got != kat.DIDCanonical.Outputs.DID {
		t.Fatalf("DID diverged:\n  got  %s\n  want %s", got, kat.DIDCanonical.Outputs.DID)
	}
}
