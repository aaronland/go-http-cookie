package cookie

import (
	"context"
	"testing"
)

func TestRegisterCookie(t *testing.T) {

	ctx := context.Background()

	err := RegisterCookie(ctx, "encrypted", NewEncryptedCookie)

	if err == nil {
		t.Fatalf("Expected NewEncryptedCookie to be registered already")
	}
}

func TestNewCookie(t *testing.T) {

	ctx := context.Background()

	uri, err := NewRandomEncryptedCookieURI("test")

	if err != nil {
		t.Fatalf("Failed to create new cookie URI, %v", err)
	}

	_, err = NewCookie(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create new cookie for '%s', %v", uri, err)
	}
}
