package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net"
	"os"

	"github.com/go-jose/go-jose/v4"
)

// Secrets (will be initialized based on environment)
var (
	secretPepper []byte
	jweKey       []byte
)

// Placeholder functions for prod secret retrieval
func fetchSecretPepperProd() []byte {
	// TODO: Fetch REVIEW_PEPPER from KMS or enclave memory
	return []byte("prod-pepper-secret-placeholder")
}

func fetchJWEKeyProd() []byte {
	// TODO: Fetch JWE_KEY from KMS or enclave memory
	return []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256
}

func initSecrets() {
	env := os.Getenv("ENV")
	if env == "dev" {
		fmt.Println("Running enclave in LOCAL DEV mode")
		secretPepper = []byte("dev-pepper-secret")
		jweKey = []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes
	} else {
		fmt.Println("Running enclave in PRODUCTION mode")
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
	key := jose.JSONWebKey{Key: jweKey, Algorithm: string(jose.A256GCMKW), Use: "enc"}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.A256GCMKW, Key: key.Key}, nil)
	if err != nil {
		return "", err
	}
	obj, err := encrypter.Encrypt([]byte(reviewerHash))
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func main() {
	initSecrets()

	// Simulate vsock with TCP
	l, err := net.Listen("tcp", "localhost:5001")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	fmt.Println("Listening on localhost:5001 (simulated enclave)")

	for {
		conn, _ := l.Accept()
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 1024)
			n, _ := c.Read(buf)
			email := string(buf[:n])
			fmt.Printf("Received email: %s\n", email)

			reviewerHash := computeReviewerHash(email)
			token, err := generateJWE(reviewerHash)
			if err != nil {
				fmt.Println("Error generating JWE:", err)
				return
			}

			c.Write([]byte(token))
			fmt.Printf("Sent JWE token: %s\n", token)
		}(conn)
	}
}

