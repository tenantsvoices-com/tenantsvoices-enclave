package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// encryptPayload mints a JWE for an arbitrary payload under the given key,
// stamping its kid in the header exactly like generateJWE. Tests use it to forge
// edge-case claims (expired, wrong issuer, unknown key) that the normal issue
// path would never produce.
func encryptPayload(t *testing.T, k jweKeyEntry, p tokenPayload) string {
	t.Helper()
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256GCMKW, Key: k.key, KeyID: k.kid},
		nil,
	)
	if err != nil {
		t.Fatalf("new encrypter: %v", err)
	}
	raw, _ := json.Marshal(p)
	obj, err := enc.Encrypt(raw)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return tok
}

func TestTokenRoundTrip(t *testing.T) {
	initSecrets()
	tok, err := generateJWE("rev-hash-abc")
	if err != nil {
		t.Fatalf("generateJWE: %v", err)
	}
	got, err := verifyJWE(tok)
	if err != nil {
		t.Fatalf("verifyJWE: %v", err)
	}
	if got != "rev-hash-abc" {
		t.Fatalf("reviewer hash = %q, want rev-hash-abc", got)
	}
}

func TestVerifyRejectsClaims(t *testing.T) {
	initSecrets()
	now := time.Now()
	good := tokenPayload{ReviewerHash: "rev", Iss: tokenIssuer, Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix()}

	cases := map[string]tokenPayload{
		"expired":       {ReviewerHash: "rev", Iss: tokenIssuer, Nbf: now.Add(-2 * time.Hour).Unix(), Exp: now.Add(-time.Hour).Unix()},
		"not yet valid": {ReviewerHash: "rev", Iss: tokenIssuer, Nbf: now.Add(time.Hour).Unix(), Exp: now.Add(2 * time.Hour).Unix()},
		"wrong issuer":  {ReviewerHash: "rev", Iss: "someone-else", Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix()},
		"no exp":        {ReviewerHash: "rev", Iss: tokenIssuer, Nbf: now.Unix()},
		"no subject":    {Iss: tokenIssuer, Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix()},
	}
	for name, p := range cases {
		tok := encryptPayload(t, jwePrimary, p)
		if _, err := verifyJWE(tok); err == nil {
			t.Errorf("%s: expected verify to fail, got nil", name)
		}
	}

	// Sanity: the "good" control must still pass under the same key.
	if _, err := verifyJWE(encryptPayload(t, jwePrimary, good)); err != nil {
		t.Fatalf("control token rejected: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	initSecrets()
	now := time.Now()
	claims := tokenPayload{ReviewerHash: "rev", Iss: tokenIssuer, Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix()}

	// A token minted under an old key still verifies while that key remains in
	// the ring (the decrypt-only overlap window after a rotation).
	retired := addKey([]byte("FEDCBA9876543210FEDCBA9876543210"))
	tok := encryptPayload(t, retired, claims)
	if _, err := verifyJWE(tok); err != nil {
		t.Fatalf("retired-key token should verify while in ring: %v", err)
	}

	// Once the key is dropped from the ring, its tokens no longer verify.
	delete(jweKeyring, retired.kid)
	if _, err := verifyJWE(tok); err == nil {
		t.Fatal("token should fail once its key leaves the ring")
	}
}
