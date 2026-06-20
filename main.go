package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/argon2"
)

const tokenTTL = 30 * 24 * time.Hour

// defaultIssuer is the `iss` claim stamped into every token and required on
// verify. Override with TOKEN_ISS if the enclave is deployed under another name.
const defaultIssuer = "tenantsvoices-enclave"

// clockSkew is the leeway allowed when checking the time-based claims (nbf/exp)
// so small clock drift between the enclave and a verifier doesn't reject
// otherwise-valid tokens.
const clockSkew = 60 * time.Second

// argon2id parameters, shared by email_key and password hashing.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// fixedEmailSalt makes the email_key deterministic (so the same email always
// maps to the same row). It is not a secret — the secrecy comes from emailPepper.
var fixedEmailSalt = []byte("tv-email-key-salt-v1")

// tokenPayload is the JWE plaintext. Claims follow JWT naming so their meaning
// is conventional: sub = reviewer hash, iss = issuer, and iat/nbf/exp are the
// issued-at / not-before / expiry times in Unix seconds.
type tokenPayload struct {
	ReviewerHash string `json:"sub"`
	Iss          string `json:"iss"`
	Iat          int64  `json:"iat"`
	Nbf          int64  `json:"nbf"`
	Exp          int64  `json:"exp"`
}

// Secrets the enclave guards. jweKey encrypts tokens; emailPepper is mixed into
// the deterministic email_key so a leaked accounts table can't be enumerated by
// guessing emails. Both are set-once. The reviewer-identity hash uses no pepper:
// its strength comes from the user's password plus a per-user salt.
// jweKeyEntry is a JWE key plus its short identifier. The kid is published in
// each token's header so verify can pick the exact key that encrypted it —
// which is what makes rotation possible without a flag day.
type jweKeyEntry struct {
	kid string
	key []byte
}

var (
	// jwePrimary encrypts new tokens (and can also decrypt). After a rotation
	// the previous primary is demoted into jweKeyring as decrypt-only, so tokens
	// minted before the rotation keep verifying until they expire.
	jwePrimary  jweKeyEntry
	jweKeyring  map[string]jweKeyEntry // kid -> key; every key we can decrypt with
	tokenIssuer string

	emailPepper []byte
)

// keyID derives a short, stable identifier for a key (first 8 hex of its
// SHA-256). It isn't secret — it only needs to be collision-resistant enough to
// name keys in a small keyring.
func keyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

// addKey registers a key in the keyring under its kid and returns the entry.
func addKey(key []byte) jweKeyEntry {
	k := jweKeyEntry{kid: keyID(key), key: key}
	jweKeyring[k.kid] = k
	return k
}

// fetchJWEKeyProd loads the AES-256 key that encrypts session tokens.
//
// MVP: there is no real enclave yet, so the key is supplied via the JWE_KEY env
// var and we refuse to boot without a valid 32-byte value — no hardcoded
// fallback, so a misconfigured deploy fails loudly instead of silently signing
// tokens with a publicly known key.
//
// Production (Nitro Enclave) path: replace the env read with a KMS Decrypt call
// (or read from sealed enclave memory) gated on a successful attestation
// document, so the key is released only to a verified enclave image and never
// transits an env var, disk, or the host.
func fetchJWEKeyProd() ([]byte, error) {
	v := os.Getenv("JWE_KEY")
	if v == "" {
		return nil, fmt.Errorf("JWE_KEY is required in production mode")
	}
	if len(v) != 32 {
		return nil, fmt.Errorf("JWE_KEY must be a 32-byte AES-256 key, got %d bytes", len(v))
	}
	return []byte(v), nil
}

// fetchEmailPepperProd loads the pepper mixed into the deterministic email_key.
// Same contract as fetchJWEKeyProd: required via EMAIL_PEPPER for the MVP, no
// fallback, and intended to be fetched from KMS / sealed enclave memory under
// attestation in the production deployment.
func fetchEmailPepperProd() ([]byte, error) {
	v := os.Getenv("EMAIL_PEPPER")
	if v == "" {
		return nil, fmt.Errorf("EMAIL_PEPPER is required in production mode")
	}
	return []byte(v), nil
}

// fetchRetiredJWEKeysProd loads zero or more decrypt-only keys from
// JWE_KEYS_RETIRED (comma-separated, each a 32-byte AES-256 key). These are the
// previous primaries kept alive so tokens minted under them survive a rotation;
// once every token signed under a retired key has expired it can be dropped from
// the var.
func fetchRetiredJWEKeysProd() [][]byte {
	v := strings.TrimSpace(os.Getenv("JWE_KEYS_RETIRED"))
	if v == "" {
		return nil
	}
	var out [][]byte
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if len(part) != 32 {
			log.Fatalf("enclave secret: each JWE_KEYS_RETIRED entry must be a 32-byte AES-256 key, got %d bytes", len(part))
		}
		out = append(out, []byte(part))
	}
	return out
}

func initSecrets() {
	jweKeyring = make(map[string]jweKeyEntry)
	tokenIssuer = os.Getenv("TOKEN_ISS")
	if tokenIssuer == "" {
		tokenIssuer = defaultIssuer
	}

	env := os.Getenv("ENV")
	if env == "dev" || env == "" {
		log.Println("Running enclave in LOCAL DEV mode")
		jwePrimary = addKey([]byte("0123456789ABCDEF0123456789ABCDEF"))
		emailPepper = []byte("dev-email-pepper")
		return
	}

	log.Println("Running enclave in PRODUCTION mode")
	primary, err := fetchJWEKeyProd()
	if err != nil {
		log.Fatalf("enclave secret: %v", err)
	}
	jwePrimary = addKey(primary)

	// Retired keys are decrypt-only: registering them in the keyring lets tokens
	// minted under a previous JWE_KEY keep verifying through the overlap window
	// after a rotation. They are never selected to encrypt new tokens.
	for _, k := range fetchRetiredJWEKeysProd() {
		retired := addKey(k)
		log.Printf("loaded retired JWE key %s (decrypt-only)", retired.kid)
	}

	if emailPepper, err = fetchEmailPepperProd(); err != nil {
		log.Fatalf("enclave secret: %v", err)
	}
	log.Printf("primary JWE key %s; issuer %q", jwePrimary.kid, tokenIssuer)
}

// normalizeEmail lower-cases and trims so "Alice@X.com " and "alice@x.com"
// resolve to the same account.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// hashFields hashes a tagged, length-prefixed concatenation of its parts. The
// length prefixes make the encoding unambiguous (so "ab"+"c" can't collide with
// "a"+"bc"), and the leading tag domain-separates hash kinds.
func hashFields(tag string, parts ...string) string {
	h := sha256.New()
	write := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	write(tag)
	for _, p := range parts {
		write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func generateJWE(reviewerHash string) (string, error) {
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256GCMKW, Key: jwePrimary.key, KeyID: jwePrimary.kid},
		nil,
	)
	if err != nil {
		return "", err
	}
	now := time.Now()
	payload, err := json.Marshal(tokenPayload{
		ReviewerHash: reviewerHash,
		Iss:          tokenIssuer,
		Iat:          now.Unix(),
		Nbf:          now.Unix(),
		Exp:          now.Add(tokenTTL).Unix(),
	})
	if err != nil {
		return "", err
	}
	obj, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// verifyJWE decrypts a token, validates its claims, and returns the embedded
// reviewer_hash. It selects the decryption key by the `kid` header (falling back
// to trying every known key) so tokens issued under a rotated-out key still
// verify. Any decrypt or claim failure yields an error so callers can return 401
// without leaking which step failed.
func verifyJWE(token string) (string, error) {
	obj, err := jose.ParseEncrypted(
		token,
		[]jose.KeyAlgorithm{jose.A256GCMKW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	if err != nil {
		return "", err
	}

	plaintext, err := decryptWithKeyring(obj)
	if err != nil {
		return "", err
	}

	var p tokenPayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return "", err
	}
	if p.ReviewerHash == "" {
		return "", fmt.Errorf("missing reviewer_hash")
	}
	if p.Iss != tokenIssuer {
		return "", fmt.Errorf("unexpected issuer")
	}
	now := time.Now()
	if p.Exp == 0 || now.Add(-clockSkew).Unix() >= p.Exp {
		return "", fmt.Errorf("token expired")
	}
	if p.Nbf != 0 && now.Add(clockSkew).Unix() < p.Nbf {
		return "", fmt.Errorf("token not yet valid")
	}
	return p.ReviewerHash, nil
}

// decryptWithKeyring tries the key named by the token's kid header first, then
// falls back to every key in the ring. The fallback keeps verification working
// for tokens whose kid we don't recognise and is cheap because the ring holds at
// most a handful of keys.
func decryptWithKeyring(obj *jose.JSONWebEncryption) ([]byte, error) {
	if kid := obj.Header.KeyID; kid != "" {
		if k, ok := jweKeyring[kid]; ok {
			return obj.Decrypt(k.key)
		}
	}
	for _, k := range jweKeyring {
		if pt, err := obj.Decrypt(k.key); err == nil {
			return pt, nil
		}
	}
	return nil, fmt.Errorf("no key could decrypt token")
}

// computeEmailKey derives the deterministic, peppered account lookup key. The
// email is HMAC'd with the pepper first (argon2 has no secret parameter), then
// stretched with argon2id against a fixed salt so the output is reproducible.
func computeEmailKey(email string) string {
	mac := hmac.New(sha256.New, emailPepper)
	mac.Write([]byte(normalizeEmail(email)))
	key := argon2.IDKey(mac.Sum(nil), fixedEmailSalt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return hex.EncodeToString(key)
}

// hashPassword produces a verifier with a fresh random salt, encoded as
// "saltHex:hashHex". The salt lives with the hash (it is not secret); it only
// needs to be unique so identical passwords don't collide.
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(h), nil
}

// verifyPassword re-derives the hash with the stored salt and compares in
// constant time.
func verifyPassword(password, encoded string) bool {
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func decode(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// emailKeyHandler derives the peppered account lookup key from an email.
func emailKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Email == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"email_key": computeEmailKey(req.Email)})
}

// hashPasswordHandler returns a fresh argon2id verifier for a password.
func hashPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Password == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	enc, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "hash failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"password_hash": enc})
}

// verifyPasswordHandler checks a password against a stored verifier.
func verifyPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password     string `json:"password"`
		PasswordHash string `json:"password_hash"`
	}
	if !decode(w, r, &req) {
		return
	}
	writeJSON(w, map[string]bool{"ok": verifyPassword(req.Password, req.PasswordHash)})
}

// tokenHandler derives the salted reviewer_hash H(email, password, salt) and
// wraps it in a JWE. Rotating the salt (done by the API) yields a fresh hash.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Salt     string `json:"salt"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Email == "" || req.Password == "" || req.Salt == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	rh := hashFields("rev", normalizeEmail(req.Email), req.Password, req.Salt)
	tok, err := generateJWE(rh)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"reviewer_hash": rh, "token": tok})
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Token == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	rh, err := verifyJWE(req.Token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]string{"reviewer_hash": rh})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func main() {
	initSecrets()

	addr := os.Getenv("ENCLAVE_ADDR")
	if addr == "" {
		addr = ":5001"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/email-key", emailKeyHandler)
	mux.HandleFunc("/hash-password", hashPasswordHandler)
	mux.HandleFunc("/verify-password", verifyPasswordHandler)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/verify", verifyHandler)
	mux.HandleFunc("/health", healthHandler)

	log.Printf("Enclave HTTP service listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
