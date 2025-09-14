package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKSHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	jwksHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var jwks JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Errorf("Failed to parse JWKS: %v", err)
	}

	// Should contain only valid (non-expired) keys
	if len(jwks.Keys) == 0 {
		t.Error("Expected at least one key in JWKS")
	}

	// Verify key properties
	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("Expected kty=RSA, got %s", key.Kty)
	}
	if key.Use != "sig" {
		t.Errorf("Expected use=sig, got %s", key.Use)
	}
	if key.Kid == "" {
		t.Error("Expected kid to be set")
	}
}

func TestJWKSHandlerMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	jwksHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestAuthHandler(t *testing.T) {
	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	tokenString := strings.TrimSpace(w.Body.String())
	if tokenString == "" {
		t.Error("Expected JWT token, got empty response")
	}

	// Parse and verify token structure
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Errorf("Failed to parse JWT: %v", err)
	}

	// Check kid in header
	if kid, ok := token.Header["kid"]; !ok || kid == "" {
		t.Error("Expected kid in JWT header")
	}
}

func TestAuthHandlerExpired(t *testing.T) {
	req := httptest.NewRequest("POST", "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	tokenString := strings.TrimSpace(w.Body.String())
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Errorf("Failed to parse JWT: %v", err)
	}

	// Check that kid matches expired key
	if kid := token.Header["kid"]; kid != expiredKey.Kid {
		t.Errorf("Expected kid=%s, got %s", expiredKey.Kid, kid)
	}
}

func TestAuthHandlerMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestKeyPairGeneration(t *testing.T) {
	kp := generateKeyPair("test-kid", time.Now().Add(time.Hour))

	if kp.Kid != "test-kid" {
		t.Errorf("Expected kid=test-kid, got %s", kp.Kid)
	}

	if kp.PrivateKey == nil {
		t.Error("Expected private key to be generated")
	}

	if kp.PublicKey == nil {
		t.Error("Expected public key to be generated")
	}
}

func TestJWKConversion(t *testing.T) {
	kp := generateKeyPair("test-kid", time.Now().Add(time.Hour))
	jwk := kp.toJWK()

	if jwk.Kty != "RSA" {
		t.Errorf("Expected kty=RSA, got %s", jwk.Kty)
	}

	if jwk.Use != "sig" {
		t.Errorf("Expected use=sig, got %s", jwk.Use)
	}

	if jwk.Kid != "test-kid" {
		t.Errorf("Expected kid=test-kid, got %s", jwk.Kid)
	}

	if jwk.N == "" {
		t.Error("Expected N parameter to be set")
	}

	if jwk.E == "" {
		t.Error("Expected E parameter to be set")
	}
}

func TestExpiredKeyNotInJWKS(t *testing.T) {
	// Create a key that's already expired
	expiredTestKey := generateKeyPair("expired-test", time.Now().Add(-time.Hour))

	// Temporarily replace the global expired key
	originalExpired := expiredKey
	expiredKey = expiredTestKey
	defer func() { expiredKey = originalExpired }()

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	jwksHandler(w, req)

	var jwks JWKS
	json.Unmarshal(w.Body.Bytes(), &jwks)

	// Verify expired key is not in JWKS
	for _, key := range jwks.Keys {
		if key.Kid == "expired-test" {
			t.Error("Expired key should not be in JWKS")
		}
	}
}
