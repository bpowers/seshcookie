// Copyright 2025 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package seshcookie

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bpowers/seshcookie/internal/pb"
)

const testCookieName = "testcookiepleaseignore"

func createKey() []byte {
	encHash := sha256.New()
	encHash.Write([]byte(time.Now().UTC().String()))
	encHash.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	encHash.Write([]byte("-enc"))
	return encHash.Sum(nil)[:blockSize]
}

func createKeyString() string {
	return string(createKey())
}

// TestRoundtrip tests encoding and decoding a session
func TestRoundtrip(t *testing.T) {
	encKey := createKey()

	orig := &pb.TestSession{
		Count: 1,
		User:  "test",
		Value: 1.2,
	}

	maxAge := 24 * time.Hour

	encoded, encodedHash, err := encodeCookie(orig, encKey, maxAge, nil)
	if err != nil {
		t.Errorf("encodeCookie: %s", err)
		return
	}

	decoded, decodedHash, _, err := decodeCookie[*pb.TestSession](encoded, encKey, maxAge)
	if err != nil {
		t.Errorf("decodeCookie: %s", err)
		return
	}

	if decoded == nil {
		t.Errorf("decoded message is null")
		return
	}

	if !bytes.Equal(encodedHash, decodedHash) {
		t.Errorf("encoded & decoded proto hash mismatches")
	}

	if decoded.Count != orig.Count {
		t.Errorf("expected decoded.Count (%d) == %d", decoded.Count, orig.Count)
	}

	if decoded.User != orig.User {
		t.Errorf("expected decoded.User (%s) == %s", decoded.User, orig.User)
	}

	if decoded.Value != orig.Value {
		t.Errorf("expected decoded.Value (%f) == %f", decoded.Value, orig.Value)
	}
}

// TestExpiryValidation tests that expired sessions are rejected
func TestExpiryValidation(t *testing.T) {
	encKey := createKey()

	session := &pb.TestSession{
		Count: 42,
		User:  "expired",
	}

	// Encode with very short expiry
	maxAge := 1 * time.Millisecond

	encoded, _, err := encodeCookie(session, encKey, maxAge, nil)
	if err != nil {
		t.Fatalf("encodeCookie: %s", err)
	}

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	// Try to decode - should fail with expiry error
	decoded, _, _, err := decodeCookie[*pb.TestSession](encoded, encKey, maxAge)
	if err == nil {
		t.Errorf("expected expiry error, got nil")
	}

	if err != nil && !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expiry error, got: %s", err)
	}

	if decoded != nil && decoded.Count != 0 {
		t.Errorf("expected zero value for expired session")
	}
}

// TestHandler tests the full HTTP handler flow
func TestHandler(t *testing.T) {
	key := createKeyString()
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	// Create a test handler that increments a counter
	visitHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			return
		}

		session, err := GetSession[*pb.TestSession](req.Context())
		if err != nil {
			// No session yet, create a new one
			session = &pb.TestSession{Count: 0}
		}

		session.Count++
		if err := SetSession(req.Context(), session); err != nil {
			t.Errorf("SetSession failed: %s", err)
		}

		// for testing cookie deletion
		if session.Count >= 2 {
			if err := ClearSession[*pb.TestSession](req.Context()); err != nil {
				t.Errorf("ClearSession failed: %s", err)
			}
		}

		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(200)
		if session.Count == 1 {
			rw.Write([]byte("this is your first visit, welcome!"))
		} else {
			rw.Write([]byte(fmt.Sprintf("page view #%d", session.Count)))
		}
	})

	handler, err := NewHandler[*pb.TestSession](visitHandler, key, config)
	if err != nil {
		t.Fatalf("NewHandler: %s", err)
	}

	// First request - no cookie
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if 200 > resp.StatusCode || resp.StatusCode >= 300 {
		t.Fatalf("bad status code: %d", resp.StatusCode)
	}

	if !strings.Contains(string(body), "first visit") {
		t.Fatalf("bad response for uncookied request")
	}

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected a single cookie to be set")
	}

	cookie := cookies[0]
	if cookie.Name != testCookieName {
		t.Fatalf("expected cookie to have name %s not %s", testCookieName, cookie.Name)
	}

	if cookie.HttpOnly != true {
		t.Fatalf("expected HTTP only")
	}

	if cookie.Secure != false {
		t.Fatalf("expected not secure")
	}

	// Second request - with cookie
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()

	// create a new handler to ensure decoding the cookie isn't
	// dependent on local state
	handler, err = NewHandler[*pb.TestSession](visitHandler, key, config)
	if err != nil {
		t.Fatalf("NewHandler: %s", err)
	}

	handler.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)

	if 200 > resp.StatusCode || resp.StatusCode >= 300 {
		t.Fatalf("bad status code: %d", resp.StatusCode)
	}

	if string(body) != "page view #2" {
		t.Fatalf("bad response for cookied request: '%s'", string(body))
	}

	if len(resp.Cookies()) != 1 {
		t.Fatalf("expected a single cookie to be set")
	}

	// expect the cookie value to be empty (cleared)
	clearedCookie := resp.Cookies()[0]
	if clearedCookie.Expires.After(time.Now().Add(-24 * time.Hour)) {
		t.Fatalf("expected expiration to be in the past")
	}

	// Third request - tamper with cookie
	cookie.Value = "tampered" + cookie.Value[8:]
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)

	if 200 > resp.StatusCode || resp.StatusCode >= 300 {
		t.Fatalf("bad status code: %d", resp.StatusCode)
	}

	if !strings.Contains(string(body), "first visit") {
		t.Fatalf("bad response for tampered request")
	}

	if len(resp.Cookies()) != 1 {
		t.Fatalf("expected a single cookie to be set")
	}
}

// TestEmptyKeyReturnsError tests that NewHandler returns an error for empty key
func TestEmptyKeyReturnsError(t *testing.T) {
	_, err := NewHandler[*pb.TestSession](http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), "", nil)

	if err == nil {
		t.Errorf("expected error for empty key")
	}

	if err != nil && !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty key error, got: %s", err)
	}
}

// TestNoHijack tests that hijacking is not supported
func TestNoHijack(t *testing.T) {
	key := createKeyString()
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	hijackFailed := false
	hijacker := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		hj, ok := rw.(http.Hijacker)
		if !ok {
			panic("expected hijack support")
		}

		_, _, err := hj.Hijack()
		if err != nil {
			hijackFailed = true
		}
	})

	handler, err := NewHandler[*pb.TestSession](hijacker, key, config)
	if err != nil {
		t.Fatalf("NewHandler: %s", err)
	}

	handler.ServeHTTP(w, req)

	if !hijackFailed {
		t.Fatalf("expected Hijack to fail")
	}
}

// TestGetSessionError tests error handling when session is not in context
func TestGetSessionError(t *testing.T) {
	ctx := context.Background()

	_, err := GetSession[*pb.TestSession](ctx)
	if err == nil {
		t.Errorf("expected error when getting session from empty context")
	}

	if err != ErrNoSession {
		t.Errorf("expected ErrNoSession, got: %v", err)
	}
}

// TestSetSessionError tests error handling when setting session on empty context
func TestSetSessionError(t *testing.T) {
	ctx := context.Background()

	err := SetSession(ctx, &pb.TestSession{Count: 1})
	if err == nil {
		t.Errorf("expected error when setting session on empty context")
	}

	if err != ErrNoSession {
		t.Errorf("expected ErrNoSession, got: %v", err)
	}
}

// TestClearSessionError tests error handling when clearing session on empty context
func TestClearSessionError(t *testing.T) {
	ctx := context.Background()

	err := ClearSession[*pb.TestSession](ctx)
	if err == nil {
		t.Errorf("expected error when clearing session on empty context")
	}

	if err != ErrNoSession {
		t.Errorf("expected ErrNoSession, got: %v", err)
	}
}

// TestSessionChangeDetection tests that unchanged sessions aren't re-written
func TestSessionChangeDetection(t *testing.T) {
	key := createKeyString()
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	visitCount := 0
	testHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		visitCount++
		session, err := GetSession[*pb.TestSession](req.Context())
		if err != nil {
			t.Errorf("GetSession failed: %s", err)
			rw.WriteHeader(500)
			return
		}
		// On first visit, set some data
		if visitCount == 1 {
			session.Count = 1
			SetSession(req.Context(), session)
		}
		// Don't modify session on second visit
		rw.WriteHeader(200)
	})

	handler, err := NewHandler[*pb.TestSession](testHandler, key, config)
	if err != nil {
		t.Fatalf("NewHandler: %s", err)
	}

	// First request
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected cookie on first request")
	}
	cookie := cookies[0]

	// Second request with same cookie - should not get new cookie since unchanged
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp = w.Result()
	cookies = resp.Cookies()
	if len(cookies) != 0 {
		t.Fatalf("expected no cookie on unchanged session")
	}
}
