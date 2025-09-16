package auth

import (
	"net/http"
	"testing"
)

func TestGetBearerToken_Success(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer abc.def.ghi")

	got, err := GetBearerToken(h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abc.def.ghi" {
		t.Fatalf("got %q, want %q", got, "abc.def.ghi")
	}
}

func TestGetBearerToken_ExtraSpaces(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer   abc.def.ghi  ")

	got, err := GetBearerToken(h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abc.def.ghi" {
		t.Fatalf("got %q, want %q", got, "abc.def.ghi")
	}
}

func TestGetBearerToken_MissingHeader(t *testing.T) {
	h := http.Header{}

	_, err := GetBearerToken(h)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err != ErrNoAuthHeader {
		t.Fatalf("got %v, want %v", err, ErrNoAuthHeader)
	}
}

func TestGetBearerToken_WrongScheme(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Basic abcdef")

	_, err := GetBearerToken(h)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err != ErrInvalidAuthHeader {
		t.Fatalf("got %v, want %v", err, ErrInvalidAuthHeader)
	}
}

func TestGetBearerToken_EmptyToken(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer   ")

	_, err := GetBearerToken(h)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err != ErrInvalidAuthHeader {
		t.Fatalf("got %v, want %v", err, ErrInvalidAuthHeader)
	}
}
