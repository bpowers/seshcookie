// Copyright 2017 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package seshcookie

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testCookieName = "testcookiepleaseignore"

func createKey() (encKey []byte) {
	encSha1 := sha1.New()
	encSha1.Write([]byte(time.Now().UTC().String()))
	encSha1.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	encSha1.Write([]byte("-enc"))
	encKey = encSha1.Sum(nil)[:blockSize]

	return
}

func TestRoundtrip(t *testing.T) {
	encKey := createKey()

	orig := map[string]interface{}{"a": 1, "b": "c", "d": 1.2}

	encoded, encodedHash, err := encodeCookie(orig, encKey)
	if err != nil {
		t.Errorf("encodeCookie: %s", err)
		return
	}
	decoded, decodedHash, err := decodeCookie(encoded, encKey)
	if err != nil {
		t.Errorf("decodeCookie: %s", err)
		return
	}

	if decoded == nil {
		t.Errorf("decoded map is null")
		return
	}

	if len(decoded) != 3 {
		t.Errorf("len was %d, expected 3", len(decoded))
		return
	}

	if !bytes.Equal(encodedHash, decodedHash) {
		t.Errorf("encoded & decoded gob hash mismatches: %s, %s",
			string(encodedHash), string(decodedHash))
	}

	for k, v := range orig {
		if decoded[k] != v {
			t.Errorf("expected decoded[%s] (%#v) == %#v", k,
				decoded[k], v)
		}
	}
}

type VisitedHandler struct{}

func (h *VisitedHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		return
	}

	session := GetSession(req.Context())

	count, _ := session["count"].(int)
	count++
	session["count"] = count

	// for testing cookie deletion
	if count >= 2 {
		delete(session, "count")
		if len(session) != 0 {
			panic("expected empty session")
		}
	}

	rw.Header().Set("Content-Type", "text/plain")
	rw.WriteHeader(200)
	if count == 1 {
		rw.Write([]byte("this is your first visit, welcome!"))
	} else {
		rw.Write([]byte(fmt.Sprintf("page view #%d", count)))
	}
}

func TestHandler(t *testing.T) {
	key := string(createKey())
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler := NewHandler(
		&VisitedHandler{},
		key,
		config)

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

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

	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()

	// create a new handler to ensure decoding the cookie isn't
	// dependent on local state
	handler = NewHandler(
		&VisitedHandler{},
		key,
		config)

	handler.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = ioutil.ReadAll(resp.Body)

	if 200 > resp.StatusCode || resp.StatusCode >= 300 {
		t.Fatalf("bad status code: %d", resp.StatusCode)
	}

	if string(body) != "page view #2" {
		t.Fatalf("bad response for cookied request: '%s'", string(body))
	}

	if len(resp.Cookies()) != 1 {
		t.Fatalf("expected a single cookie to be set")
	}

	// expect the cookie value to be empty
	clearedCookie := resp.Cookies()[0]
	if clearedCookie.Expires.After(time.Now().Add(-24 * time.Hour)) {
		t.Fatalf("expected expiration to be in the past")
	}
	if len(clearedCookie.Value) != 0 {
		//t.Fatalf("expected cookie value to be empty, not '%s'", clearedCookie.Value)
	}

	// now try messing with the cookie data and ensuring the page loads ok
	if cookie.Value[0] == 'a' {
		cookie.Value = "A" + cookie.Value[1:]
	} else {
		cookie.Value = "a" + cookie.Value[1:]
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = ioutil.ReadAll(resp.Body)

	if 200 > resp.StatusCode || resp.StatusCode >= 300 {
		t.Fatalf("bad status code: %d", resp.StatusCode)
	}

	if !strings.Contains(string(body), "first visit") {
		t.Fatalf("bad response for uncookied request")
	}

	if len(resp.Cookies()) != 1 {
		t.Fatalf("expected a single cookie to be set")
	}
}

func TestEmptyKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	_ = NewHandler(
		&VisitedHandler{},
		"",
		nil)
}

func TestNoHijack(t *testing.T) {
	key := string(createKey())
	config := &Config{
		CookieName: testCookieName,
		HTTPOnly:   true,
		Secure:     false,
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

	handler := NewHandler(
		hijacker,
		key,
		config)

	handler.ServeHTTP(w, req)

	if !hijackFailed {
		t.Fatalf("expected Hijack to fail")
	}
}
