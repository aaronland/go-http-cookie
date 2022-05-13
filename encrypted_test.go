package cookie

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// Copied from https://cs.opensource.google/go/go/+/master:src/net/http/cookie_test.go

type headerOnlyResponseWriter http.Header

func (ho headerOnlyResponseWriter) Header() http.Header {
	return http.Header(ho)
}

func (ho headerOnlyResponseWriter) Write([]byte) (int, error) {
	panic("NOIMPL")
}

func (ho headerOnlyResponseWriter) WriteHeader(int) {
	panic("NOIMPL")
}

func TestRandomEncryptedCookieURI(t *testing.T) {

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

func TestEncryptedCookie(t *testing.T) {

	ctx := context.Background()

	name := "test"

	secret, err := NewRandomEncryptedCookieSecret()

	if err != nil {
		t.Fatalf("Failed to generate secret, %v", err)
	}

	salt, err := NewRandomEncryptedCookieSalt()

	if err != nil {
		t.Fatalf("Failed to generate salt, %v", err)
	}

	uri := fmt.Sprintf("encrypted://?name=%s&secret=%s&salt=%s", name, secret, salt)

	c, err := NewCookie(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create cookie for '%s', %v", uri, err)
	}

	headers := make(http.Header)
	rsp := headerOnlyResponseWriter(headers)

	err = c.SetString(rsp, "encrypted")

	if err != nil {
		t.Fatalf("Failed to set string, %v", err)
	}

	// To do: Finish up tests to GET cookie
}
