package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-jose/go-jose/v4"
)

var (
	secretPepper []byte
	jweKey       []byte
)

func fetchSecretPepperProd() []byte {
	// TODO: Fetch REVIEW_PEPPER from KMS or enclave memory
	if v := os.Getenv("REVIEW_PEPPER"); v != "" {
		return []byte(v)
	}
	return []byte("prod-pepper-secret-placeholder")
}

func fetchJWEKeyProd() []byte {
	// TODO: Fetch JWE_KEY from KMS or enclave memory
	if v := os.Getenv("JWE_KEY"); v != "" && len(v) == 32 {
		return []byte(v)
	}
	return []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256
}

func initSecrets() {
	env := os.Getenv("ENV")
	if env == "dev" || env == "" {
		log.Println("Running enclave in LOCAL DEV mode")
		secretPepper = []byte("dev-pepper-secret")
		jweKey = []byte("0123456789ABCDEF0123456789ABCDEF")
	} else {
		log.Println("Running enclave in PRODUCTION mode")
		secretPepper = fetchSecretPepperProd()
		jweKey = fetchJWEKeyProd()
	}
}

func computeReviewerHash(email string) string {
	h := hmac.New(sha256.New, secretPepper)
	h.Write([]byte(email))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func generateJWE(reviewerHash string) (string, error) {
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256GCMKW, Key: jweKey},
		nil,
	)
	if err != nil {
		return "", err
	}
	obj, err := encrypter.Encrypt([]byte(reviewerHash))
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

type hashRequest struct {
	Email string `json:"email"`
}

type hashResponse struct {
	ReviewerHash string `json:"reviewer_hash"`
	Token        string `json:"token"`
}

func hashHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req hashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	rh := computeReviewerHash(req.Email)
	tok, err := generateJWE(rh)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hashResponse{ReviewerHash: rh, Token: tok})
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
	mux.HandleFunc("/hash", hashHandler)
	mux.HandleFunc("/health", healthHandler)

	log.Printf("Enclave HTTP service listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
