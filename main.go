package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
	Expiry     time.Time
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

var (
	validKey   *KeyPair
	expiredKey *KeyPair
)

func init() {
	// Generate valid key (expires in 1 hour)
	validKey = generateKeyPair("valid-key", time.Now().Add(time.Hour))

	// Generate expired key (expired 1 hour ago)
	expiredKey = generateKeyPair("expired-key", time.Now().Add(-time.Hour))
}

func generateKeyPair(kid string, expiry time.Time) *KeyPair {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Kid:        kid,
		Expiry:     expiry,
	}
}

func (kp *KeyPair) toJWK() JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kp.Kid,
		N:   base64.RawURLEncoding.EncodeToString(kp.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(kp.PublicKey.E)).Bytes()),
	}
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var keys []JWK

	// Only include non-expired keys
	if time.Now().Before(validKey.Expiry) {
		keys = append(keys, validKey.toJWK())
	}

	jwks := JWKS{Keys: keys}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if expired parameter is present
	expired := r.URL.Query().Get("expired") != ""

	var keyToUse *KeyPair
	var exp time.Time

	if expired {
		keyToUse = expiredKey
		exp = expiredKey.Expiry
	} else {
		keyToUse = validKey
		exp = time.Now().Add(time.Hour)
	}

	// Create JWT claims
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "jwks-server",
		"aud": "test-client",
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}

	// Create token with kid in header
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyToUse.Kid

	// Sign token
	tokenString, err := token.SignedString(keyToUse.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	// Return JWT as plain text
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(tokenString))
}

func main() {
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("JWKS Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
