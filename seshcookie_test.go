// Copyright 2025 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package seshcookie

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bpowers/seshcookie/v3/internal/pb"
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

// TestDeriveKey tests the Argon2id key derivation function
func TestDeriveKey(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		key := "test-key-12345"
		k1, err := deriveKey(key)
		if err != nil {
			t.Fatalf("deriveKey: %v", err)
		}
		k2, err := deriveKey(key)
		if err != nil {
			t.Fatalf("deriveKey: %v", err)
		}
		if !bytes.Equal(k1, k2) {
			t.Error("deriveKey not deterministic: same input produced different outputs")
		}
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := deriveKey("")
		if err == nil {
			t.Error("expected error for empty key, got nil")
		}
	})

	t.Run("different keys produce different outputs", func(t *testing.T) {
		k1, err := deriveKey("key1")
		if err != nil {
			t.Fatalf("deriveKey(key1): %v", err)
		}
		k2, err := deriveKey("key2")
		if err != nil {
			t.Fatalf("deriveKey(key2): %v", err)
		}
		if bytes.Equal(k1, k2) {
			t.Error("different keys produced same derived key")
		}
	})

	t.Run("correct length", func(t *testing.T) {
		k, err := deriveKey("test-key")
		if err != nil {
			t.Fatalf("deriveKey: %v", err)
		}
		if len(k) != blockSize {
			t.Errorf("expected key length %d, got %d", blockSize, len(k))
		}
	})

	t.Run("high entropy key", func(t *testing.T) {
		// Test with a high-entropy key
		k, err := deriveKey("39f8b2c7e4d1a9f0e3b7c8d2a6f5e1b9c8d7e4f3a2b1c9d8e7f6a5b4c3d2e1f0")
		if err != nil {
			t.Fatalf("deriveKey with high-entropy key: %v", err)
		}
		if len(k) != blockSize {
			t.Errorf("expected key length %d, got %d", blockSize, len(k))
		}
	})
}

// BenchmarkDeriveKey benchmarks the Argon2id key derivation performance
func BenchmarkDeriveKey(b *testing.B) {
	key := "benchmark-key-32-bytes-long-test-key-value"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deriveKey(key)
		if err != nil {
			b.Fatal(err)
		}
	}
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

	mw, err := NewMiddleware[*pb.TestSession](key, config)
	if err != nil {
		t.Fatalf("NewMiddleware: %s", err)
	}
	handler := mw(visitHandler)

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
	mw, err = NewMiddleware[*pb.TestSession](key, config)
	if err != nil {
		t.Fatalf("NewMiddleware: %s", err)
	}
	handler = mw(visitHandler)

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

// TestEmptyKeyReturnsError tests that NewMiddleware returns an error for empty key
func TestEmptyKeyReturnsError(t *testing.T) {
	_, err := NewMiddleware[*pb.TestSession]("", nil)

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

	mw, err := NewMiddleware[*pb.TestSession](key, config)
	if err != nil {
		t.Fatalf("NewMiddleware: %s", err)
	}

	mw(hijacker).ServeHTTP(w, req)

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

// mockHijackableResponseWriter implements http.ResponseWriter and http.Hijacker
type mockHijackableResponseWriter struct {
	http.ResponseWriter
	hijacked bool
}

func (m *mockHijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.hijacked = true
	// Return a mock connection for testing
	server, client := net.Pipe()
	client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

// mockFlushableResponseWriter implements http.ResponseWriter and http.Flusher
type mockFlushableResponseWriter struct {
	http.ResponseWriter
	flushed bool
}

func (m *mockFlushableResponseWriter) Flush() {
	m.flushed = true
}

// mockReaderFromResponseWriter implements http.ResponseWriter and io.ReaderFrom
type mockReaderFromResponseWriter struct {
	http.ResponseWriter
	readFromCalled bool
	bytesRead      int64
}

func (m *mockReaderFromResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	m.readFromCalled = true
	n, err := io.Copy(m.ResponseWriter, r)
	m.bytesRead = n
	return n, err
}

// TestHijackerProxying tests that Hijacker is properly proxied to underlying ResponseWriter
func TestHijackerProxying(t *testing.T) {
	key := createKeyString()
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	t.Run("proxies to hijackable underlying writer", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		mock := &mockHijackableResponseWriter{ResponseWriter: httptest.NewRecorder()}

		hijackHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			hj, ok := rw.(http.Hijacker)
			if !ok {
				t.Fatal("expected responseWriter to implement http.Hijacker")
			}

			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("Hijack failed: %v", err)
			}
			if conn != nil {
				conn.Close()
			}
		})

		mw, err := NewMiddleware[*pb.TestSession](key, config)
		if err != nil {
			t.Fatalf("NewMiddleware: %s", err)
		}

		mw(hijackHandler).ServeHTTP(mock, req)

		if !mock.hijacked {
			t.Fatal("expected underlying ResponseWriter's Hijack to be called")
		}
	})

	t.Run("returns error when underlying writer does not support hijacking", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		hijackHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			hj, ok := rw.(http.Hijacker)
			if !ok {
				t.Fatal("expected responseWriter to implement http.Hijacker")
			}

			_, _, err := hj.Hijack()
			if err == nil {
				t.Fatal("expected error when underlying writer doesn't support hijacking")
			}
		})

		mw, err := NewMiddleware[*pb.TestSession](key, config)
		if err != nil {
			t.Fatalf("NewMiddleware: %s", err)
		}

		mw(hijackHandler).ServeHTTP(w, req)
	})
}

// TestFlusherProxying tests that Flusher is properly proxied to underlying ResponseWriter
func TestFlusherProxying(t *testing.T) {
	key := createKeyString()
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	t.Run("proxies to flushable underlying writer", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		mock := &mockFlushableResponseWriter{ResponseWriter: httptest.NewRecorder()}

		flushHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			f, ok := rw.(http.Flusher)
			if !ok {
				t.Fatal("expected responseWriter to implement http.Flusher")
			}

			f.Flush()
		})

		mw, err := NewMiddleware[*pb.TestSession](key, config)
		if err != nil {
			t.Fatalf("NewMiddleware: %s", err)
		}

		mw(flushHandler).ServeHTTP(mock, req)

		if !mock.flushed {
			t.Fatal("expected underlying ResponseWriter's Flush to be called")
		}
	})

	t.Run("does not panic when underlying writer does not support flushing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		flushHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			f, ok := rw.(http.Flusher)
			if !ok {
				t.Fatal("expected responseWriter to implement http.Flusher")
			}

			// Should not panic even if underlying writer doesn't support Flush
			f.Flush()
		})

		mw, err := NewMiddleware[*pb.TestSession](key, config)
		if err != nil {
			t.Fatalf("NewMiddleware: %s", err)
		}

		mw(flushHandler).ServeHTTP(w, req)
	})
}

// TestReaderFromProxying tests that io.ReaderFrom is properly proxied to underlying ResponseWriter
func TestReaderFromProxying(t *testing.T) {
	key := createKeyString()
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	t.Run("proxies to ReaderFrom-supporting underlying writer", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		mock := &mockReaderFromResponseWriter{ResponseWriter: httptest.NewRecorder()}

		rfHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rf, ok := rw.(io.ReaderFrom)
			if !ok {
				t.Fatal("expected responseWriter to implement io.ReaderFrom")
			}

			data := strings.NewReader("test data for ReadFrom")
			n, err := rf.ReadFrom(data)
			if err != nil {
				t.Fatalf("ReadFrom failed: %v", err)
			}
			if n != 22 {
				t.Fatalf("expected 22 bytes, got %d", n)
			}
		})

		mw, err := NewMiddleware[*pb.TestSession](key, config)
		if err != nil {
			t.Fatalf("NewMiddleware: %s", err)
		}

		mw(rfHandler).ServeHTTP(mock, req)

		if !mock.readFromCalled {
			t.Fatal("expected underlying ResponseWriter's ReadFrom to be called")
		}
		if mock.bytesRead != 22 {
			t.Fatalf("expected 22 bytes read, got %d", mock.bytesRead)
		}
	})

	t.Run("falls back to io.Copy when underlying writer does not support ReaderFrom", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		rfHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rf, ok := rw.(io.ReaderFrom)
			if !ok {
				t.Fatal("expected responseWriter to implement io.ReaderFrom")
			}

			data := strings.NewReader("test data")
			n, err := rf.ReadFrom(data)
			if err != nil {
				t.Fatalf("ReadFrom failed: %v", err)
			}
			if n != 9 {
				t.Fatalf("expected 9 bytes, got %d", n)
			}
		})

		mw, err := NewMiddleware[*pb.TestSession](key, config)
		if err != nil {
			t.Fatalf("NewMiddleware: %s", err)
		}

		mw(rfHandler).ServeHTTP(w, req)

		if w.Body.String() != "test data" {
			t.Fatalf("expected 'test data', got %q", w.Body.String())
		}
	})
}

// TestVersionPrefix tests that encoded cookies have the sc1_ prefix and roundtrip correctly
func TestVersionPrefix(t *testing.T) {
	encKey := createKey()
	maxAge := 24 * time.Hour

	orig := &pb.TestSession{
		Count: 7,
		User:  "prefix-test",
	}

	encoded, _, err := encodeCookie(orig, encKey, maxAge, nil)
	if err != nil {
		t.Fatalf("encodeCookie: %v", err)
	}

	if !strings.HasPrefix(encoded, versionPrefix) {
		t.Errorf("encoded cookie %q does not start with %q", encoded, versionPrefix)
	}

	decoded, _, _, err := decodeCookie[*pb.TestSession](encoded, encKey, maxAge)
	if err != nil {
		t.Fatalf("decodeCookie: %v", err)
	}

	if decoded.Count != orig.Count || decoded.User != orig.User {
		t.Errorf("roundtrip mismatch: got {%d, %s}, want {%d, %s}",
			decoded.Count, decoded.User, orig.Count, orig.User)
	}
}

// TestLegacyGoCookieWithoutPrefix tests that cookies encoded by
// pre-sc1_ versions of seshcookie are still readable after upgrade.
func TestLegacyGoCookieWithoutPrefix(t *testing.T) {
	key := createKeyString()
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	// Create a handler, set a session, capture the Go cookie
	mw, err := NewMiddleware[*pb.TestSession](key, config)
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	setHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session, _ := GetSession[*pb.TestSession](req.Context())
		session.Count = 99
		session.User = "legacy"
		SetSession(req.Context(), session)
		rw.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mw(setHandler).ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	goCookie := cookies[0]
	if !strings.HasPrefix(goCookie.Value, versionPrefix) {
		t.Fatalf("expected sc1_ prefix on cookie")
	}

	// Simulate a legacy cookie by stripping the sc1_ prefix
	legacyCookie := &http.Cookie{
		Name:  testCookieName,
		Value: strings.TrimPrefix(goCookie.Value, versionPrefix),
	}

	// Send it to a fresh handler without migration - should still decode
	readHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session, err := GetSession[*pb.TestSession](req.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.WriteHeader(200)
		fmt.Fprintf(rw, "count=%d user=%s", session.Count, session.User)
	})

	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(legacyCookie)
	w = httptest.NewRecorder()

	mw, err = NewMiddleware[*pb.TestSession](key, config)
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}
	mw(readHandler).ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if string(body) != "count=99 user=legacy" {
		t.Fatalf("body = %q, want %q", string(body), "count=99 user=legacy")
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

	mw, err := NewMiddleware[*pb.TestSession](key, config)
	if err != nil {
		t.Fatalf("NewMiddleware: %s", err)
	}
	handler := mw(testHandler)

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
