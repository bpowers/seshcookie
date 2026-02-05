// Copyright 2025 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package seshcookie

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bpowers/seshcookie/v3/internal/pb"
)

type jsVector struct {
	Description   string `json:"description"`
	Key           string `json:"key"`
	DerivedKeyHex string `json:"derived_key_hex"`
	SessionJSON   string `json:"session_json"`
	CookieValue   string `json:"cookie_value"`
}

type jsVectors struct {
	Vectors []jsVector `json:"vectors"`
}

func loadVectors(t *testing.T) []jsVector {
	t.Helper()
	data, err := os.ReadFile("testdata/js_vectors.json")
	if err != nil {
		t.Fatalf("read test vectors: %v", err)
	}
	var vecs jsVectors
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("unmarshal test vectors: %v", err)
	}
	return vecs.Vectors
}

func TestDeriveJSKey(t *testing.T) {
	vectors := loadVectors(t)
	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			got := deriveJSKey(v.Key)
			gotHex := hex.EncodeToString(got)
			if gotHex != v.DerivedKeyHex {
				t.Errorf("deriveJSKey(%q) = %s, want %s", v.Key, gotHex, v.DerivedKeyHex)
			}
		})
	}
}

func TestDecodeJSCookie(t *testing.T) {
	vectors := loadVectors(t)
	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			encKey := deriveJSKey(v.Key)
			plaintext, err := decodeJSCookie(v.CookieValue, encKey)
			if err != nil {
				t.Fatalf("decodeJSCookie: %v", err)
			}
			if string(plaintext) != v.SessionJSON {
				t.Errorf("plaintext = %q, want %q", string(plaintext), v.SessionJSON)
			}
		})
	}
}

func TestDecodeJSCookieMalformed(t *testing.T) {
	validKey := deriveJSKey("test-secret-key")

	t.Run("wrong part count - too few", func(t *testing.T) {
		_, err := decodeJSCookie("abc-def", validKey)
		if err == nil {
			t.Error("expected error for 2-part cookie")
		}
	})

	t.Run("wrong part count - too many", func(t *testing.T) {
		_, err := decodeJSCookie("a-b-c-d", validKey)
		if err == nil {
			t.Error("expected error for 4-part cookie")
		}
	})

	t.Run("bad base64 nonce", func(t *testing.T) {
		_, err := decodeJSCookie("!!!-AAAA-AAAA", validKey)
		if err == nil {
			t.Error("expected error for bad base64 nonce")
		}
	})

	t.Run("bad base64 ciphertext", func(t *testing.T) {
		_, err := decodeJSCookie("AAAAAAAAAAAAAAAA-!!!-AAAA", validKey)
		if err == nil {
			t.Error("expected error for bad base64 ciphertext")
		}
	})

	t.Run("bad base64 tag", func(t *testing.T) {
		_, err := decodeJSCookie("AAAAAAAAAAAAAAAA-AAAA-!!!", validKey)
		if err == nil {
			t.Error("expected error for bad base64 tag")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		vectors := loadVectors(t)
		wrongKey := deriveJSKey("wrong-key")
		_, err := decodeJSCookie(vectors[0].CookieValue, wrongKey)
		if err == nil {
			t.Error("expected error decrypting with wrong key")
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		vectors := loadVectors(t)
		parts := strings.Split(vectors[0].CookieValue, "-")
		// flip a byte in the ciphertext
		ct := []byte(parts[1])
		ct[0] ^= 0xff
		parts[1] = string(ct)
		tampered := strings.Join(parts, "-")

		_, err := decodeJSCookie(tampered, validKey)
		if err == nil {
			t.Error("expected error for tampered ciphertext")
		}
	})

	t.Run("tampered tag", func(t *testing.T) {
		vectors := loadVectors(t)
		parts := strings.Split(vectors[0].CookieValue, "-")
		// flip a byte in the tag
		tag := []byte(parts[2])
		tag[0] ^= 0xff
		parts[2] = string(tag)
		tampered := strings.Join(parts, "-")

		_, err := decodeJSCookie(tampered, validKey)
		if err == nil {
			t.Error("expected error for tampered tag")
		}
	})
}

func TestMigrationEndToEnd(t *testing.T) {
	vectors := loadVectors(t)
	vec := vectors[0] // simple session: {count: 42, user: "alice"}

	goKey := createKeyString()
	jsKey := vec.Key

	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	convert := func(jsonData []byte) (*pb.TestSession, error) {
		var raw map[string]any
		if err := json.Unmarshal(jsonData, &raw); err != nil {
			return nil, err
		}
		session := &pb.TestSession{}
		if v, ok := raw["count"].(float64); ok {
			session.Count = int32(v)
		}
		if v, ok := raw["user"].(string); ok {
			session.User = v
		}
		return session, nil
	}

	mw, err := NewMiddleware[*pb.TestSession](goKey, config,
		WithMigration[*pb.TestSession](jsKey, convert))
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	// Handler that reads and reports the session
	readHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session, err := GetSession[*pb.TestSession](req.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.WriteHeader(200)
		fmt.Fprintf(rw, "count=%d user=%s", session.Count, session.User)
	})

	handler := mw(readHandler)

	// First request: send JS cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: vec.CookieValue})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if string(body) != "count=42 user=alice" {
		t.Fatalf("body = %q, want %q", string(body), "count=42 user=alice")
	}

	// Should have a Set-Cookie with sc1_ prefix (Go format)
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	goCookie := cookies[0]
	if !strings.HasPrefix(goCookie.Value, versionPrefix) {
		t.Fatalf("cookie value %q does not have sc1_ prefix", goCookie.Value)
	}

	// Second request: send Go cookie back
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(goCookie)
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if string(body) != "count=42 user=alice" {
		t.Fatalf("body = %q after re-read, want %q", string(body), "count=42 user=alice")
	}

	// Session unchanged, no new cookie should be set
	if len(resp.Cookies()) != 0 {
		t.Fatalf("expected no cookie on unchanged re-read, got %d", len(resp.Cookies()))
	}
}

func TestMigrationWithDifferentKeys(t *testing.T) {
	vectors := loadVectors(t)
	vec := vectors[1] // single string field with "another-key-here"

	// Go key is different from JS key
	goKey := createKeyString()
	jsKey := vec.Key

	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	convert := func(jsonData []byte) (*pb.TestSession, error) {
		var raw map[string]any
		if err := json.Unmarshal(jsonData, &raw); err != nil {
			return nil, err
		}
		session := &pb.TestSession{}
		if v, ok := raw["name"].(string); ok {
			session.User = v
		}
		return session, nil
	}

	mw, err := NewMiddleware[*pb.TestSession](goKey, config,
		WithMigration[*pb.TestSession](jsKey, convert))
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	handler := mw(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session, err := GetSession[*pb.TestSession](req.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.WriteHeader(200)
		fmt.Fprintf(rw, "user=%s", session.User)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: vec.CookieValue})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if string(body) != "user=bob" {
		t.Fatalf("body = %q, want %q", string(body), "user=bob")
	}

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	if !strings.HasPrefix(cookies[0].Value, versionPrefix) {
		t.Fatalf("cookie %q missing sc1_ prefix", cookies[0].Value)
	}
}

func TestMigrationConvertError(t *testing.T) {
	vectors := loadVectors(t)
	vec := vectors[0]

	goKey := createKeyString()

	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	convert := func(jsonData []byte) (*pb.TestSession, error) {
		return nil, fmt.Errorf("conversion failed")
	}

	mw, err := NewMiddleware[*pb.TestSession](goKey, config,
		WithMigration[*pb.TestSession](vec.Key, convert))
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	handler := mw(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session, err := GetSession[*pb.TestSession](req.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.WriteHeader(200)
		fmt.Fprintf(rw, "count=%d", session.Count)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: vec.CookieValue})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Should get empty session since convert failed
	if string(body) != "count=0" {
		t.Fatalf("body = %q, want %q (empty session)", string(body), "count=0")
	}
}

func TestMigrationGarbageInput(t *testing.T) {
	goKey := createKeyString()

	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	convert := func(jsonData []byte) (*pb.TestSession, error) {
		return &pb.TestSession{Count: 1}, nil
	}

	mw, err := NewMiddleware[*pb.TestSession](goKey, config,
		WithMigration[*pb.TestSession]("some-js-key", convert))
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	handler := mw(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session, err := GetSession[*pb.TestSession](req.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.WriteHeader(200)
		fmt.Fprintf(rw, "count=%d", session.Count)
	}))

	// Cookie that looks like JS format (3 hyphen-separated parts) but is garbage
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: "AAAA-BBBB-CCCC"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Should get empty session since decryption fails on garbage
	if string(body) != "count=0" {
		t.Fatalf("body = %q, want %q (empty session for garbage input)", string(body), "count=0")
	}
}

// TestMigrationWithLegacyGoCookie verifies that when migration is enabled,
// a legacy Go cookie (no sc1_ prefix, not JS format) is still decodable.
func TestMigrationWithLegacyGoCookie(t *testing.T) {
	goKey := createKeyString()

	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	convert := func(jsonData []byte) (*pb.TestSession, error) {
		return nil, fmt.Errorf("should not be called for Go cookies")
	}

	// First, create a Go cookie (with sc1_ prefix) using a handler without migration
	mwNoMigrate, err := NewMiddleware[*pb.TestSession](goKey, config)
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	setHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session, _ := GetSession[*pb.TestSession](req.Context())
		session.Count = 77
		session.User = "legacy-with-migration"
		SetSession(req.Context(), session)
		rw.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mwNoMigrate(setHandler).ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	// Strip sc1_ prefix to simulate a legacy Go cookie
	legacyCookie := &http.Cookie{
		Name:  testCookieName,
		Value: strings.TrimPrefix(cookies[0].Value, versionPrefix),
	}

	// Now create a handler WITH migration enabled and send the legacy Go cookie
	mwWithMigrate, err := NewMiddleware[*pb.TestSession](goKey, config,
		WithMigration[*pb.TestSession]("some-js-key", convert))
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

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
	mwWithMigrate(readHandler).ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if string(body) != "count=77 user=legacy-with-migration" {
		t.Fatalf("body = %q, want %q", string(body), "count=77 user=legacy-with-migration")
	}
}

func TestNoMigrationIgnoresJSCookies(t *testing.T) {
	vectors := loadVectors(t)
	vec := vectors[0]

	goKey := createKeyString()

	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
		MaxAge:     24 * time.Hour,
	}

	// No WithMigration option
	mw, err := NewMiddleware[*pb.TestSession](goKey, config)
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	handler := mw(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		session, err := GetSession[*pb.TestSession](req.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.WriteHeader(200)
		fmt.Fprintf(rw, "count=%d", session.Count)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: vec.CookieValue})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Should get empty session since no migration configured
	if string(body) != "count=0" {
		t.Fatalf("body = %q, want %q (empty session)", string(body), "count=0")
	}
}
