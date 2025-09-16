package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT_Succeeds(t *testing.T) {
	t.Parallel()

	secret := "super-secret"
	userID := uuid.New()

	token, err := MakeJWT(userID, secret, 1*time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT error: %v", err)
	}

	gotID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT error: %v", err)
	}
	if gotID != userID {
		t.Fatalf("userID mismatch: got %s, want %s", gotID, userID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	t.Parallel()

	secret := "super-secret"
	userID := uuid.New()

	// Create a token that already expired
	token, err := MakeJWT(userID, secret, -1*time.Minute)
	if err != nil {
		t.Fatalf("MakeJWT error: %v", err)
	}

	if _, err := ValidateJWT(token, secret); err == nil {
		t.Fatalf("expected error for expired token, got nil")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	t.Parallel()

	secret := "right-secret"
	userID := uuid.New()

	token, err := MakeJWT(userID, secret, 1*time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT error: %v", err)
	}

	// Validate with the wrong secret
	if _, err := ValidateJWT(token, "wrong-secret"); err == nil {
		t.Fatalf("expected error with wrong secret, got nil")
	}
}
