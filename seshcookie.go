// Copyright 2017 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package seshcookie

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

type contextKey int

const (
	sessionKey contextKey = 0
	gobHashKey contextKey = 1

	// we want 16 byte blocks, for AES-128
	blockSize    = 16
	gcmNonceSize = 12
)

var (
	// DefaultConfig is used as the configuration if a nil config
	// is passed to NewHandler
	DefaultConfig = &Config{
		HTTPOnly: true,
		Secure:   true,
	}
)

// Session is simply a map of keys to arbitrary values, with the
// restriction that the value must be GOB-encodable.
type Session map[string]interface{}

type responseWriter struct {
	http.ResponseWriter
	h   *Handler
	req *http.Request
	// int32 so we can use the sync/atomic functions on it
	wroteHeader int32
}

// Config provides directives to a seshcookie instance on cookie
// attributes, like if they are accessible from JavaScript and/or only
// set on HTTPS connections.
type Config struct {
	HTTPOnly bool // don't allow JavaScript to access cookie
	Secure   bool // only send session over HTTPS
}

// Handler is the seshcookie HTTP handler that provides a Session
// object to child handlers.
type Handler struct {
	http.Handler
	CookieName string // name of the cookie to store our session in
	CookiePath string // resource path the cookie is valid for
	config     Config
	encKey     []byte
}

// GetSession is a wrapper to grab the seshcookie Session out of a Context.
//
// By only providing a 'Get' API, we ensure that clients can't
// mistakenly set something unexpected on the given context in place
// of the session.
func GetSession(ctx context.Context) Session {
	return ctx.Value(sessionKey).(Session)
}

func encodeGob(obj interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(obj)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeGob(encoded []byte) (Session, error) {
	buf := bytes.NewBuffer(encoded)
	dec := gob.NewDecoder(buf)
	var out Session
	err := dec.Decode(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// encodeCookie encodes a gob-encodable piece of content into a base64
// encoded string, using AES-GCM mode for authenticated encryption.
//
// Go documentation suggests to never encode more than 2^32 cookies,
// due to the risk of nonce-collision.
func encodeCookie(content interface{}, encKey []byte) (string, []byte, error) {
	plaintext, err := encodeGob(content)
	if err != nil {
		return "", nil, err
	}

	// we want to record a hash of the serialized session to know
	// if the contents of the cookie changed.  As we use a unique
	// nonce per encryption, we need to hash the plaintext as it
	// is before being passed through AES-GCM
	gobHash := sha256.New()
	gobHash.Write(plaintext)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", nil, fmt.Errorf("aes.NewCipher: %s", err)
	}

	if block.BlockSize() != blockSize {
		return "", nil, fmt.Errorf("block size assumption mismatch")
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, fmt.Errorf("io.ReadFull(rand.Reader): %s", err)
	}

	aeadCipher, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("cipher.NewGCM: %s", err)
	}

	ciphertext := aeadCipher.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), gobHash.Sum(nil), nil
}

// decodeCookie decrypts a base64-encoded cookie using AES-GCM for
// authenticated decryption.
func decodeCookie(encoded string, encKey []byte) (Session, []byte, error) {
	cookie, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, fmt.Errorf("aes.NewCipher: %s", err)
	}

	if len(cookie) < block.BlockSize() {
		return nil, nil, fmt.Errorf("expected ciphertext(%d) to be bigger than blockSize", len(cookie))
	}

	// split the cookie data
	nonce, ciphertext := cookie[:gcmNonceSize], cookie[gcmNonceSize:]

	aeadCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewGCM: %s", err)
	}

	plaintext, err := aeadCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("aeadCipher.Open: %s", err)
	}

	gobHash := sha256.New()
	gobHash.Write(plaintext)

	session, err := decodeGob(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("decodeGob: %s", err)
	}
	return session, gobHash.Sum(nil), nil
}

func (s *responseWriter) Write(data []byte) (int, error) {
	if atomic.LoadInt32(&s.wroteHeader) == 0 {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(data)
}

func (s *responseWriter) writeCookie() {
	origCookieVal := ""
	if origCookie, err := s.req.Cookie(s.h.CookieName); err == nil {
		origCookieVal = origCookie.Value
	}

	session := s.req.Context().Value(sessionKey).(Session)
	if len(session) == 0 {
		// if we have an empty session, but the user's cookie
		// was non-empty, we need to clear out the users
		// cookie.
		if origCookieVal != "" {
			//log.Println("clearing cookie")
			var cookie http.Cookie
			cookie.Name = s.h.CookieName
			cookie.Value = ""
			cookie.Path = "/"
			// a cookie is expired by setting it
			// with an expiration time in the past
			cookie.Expires = time.Unix(0, 0).UTC()
			http.SetCookie(s, &cookie)
		}
		return
	}

	encoded, gobHash, err := encodeCookie(session, s.h.encKey)
	if err != nil {
		log.Printf("encodeCookie: %s\n", err)
		return
	}

	if bytes.Equal(gobHash, s.req.Context().Value(gobHashKey).([]byte)) {
		// log.Println("not re-setting identical cookie")
		return
	}

	var cookie http.Cookie
	cookie.Name = s.h.CookieName
	cookie.Value = encoded
	cookie.Path = s.h.CookiePath
	cookie.HttpOnly = s.h.config.HTTPOnly
	cookie.Secure = s.h.config.Secure
	http.SetCookie(s, &cookie)
}

func (s *responseWriter) WriteHeader(code int) {
	// TODO: this is racey if WriteHeader is called from 2
	// different goroutines.  I think so is the underlying
	// ResponseWriter from net.http, but it is worth checking.
	if atomic.AddInt32(&s.wroteHeader, 1) == 1 {
		s.writeCookie()
	}

	s.ResponseWriter.WriteHeader(code)
}

func (s *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, _ := s.ResponseWriter.(http.Hijacker)
	return hijacker.Hijack()
}

func (h *Handler) getCookieSession(req *http.Request) (Session, []byte) {
	cookie, err := req.Cookie(h.CookieName)
	if err != nil {
		//log.Printf("getCookieSesh: '%#v' not found\n",
		//	h.CookieName)
		return Session{}, nil
	}
	session, gobHash, err := decodeCookie(cookie.Value, h.encKey)
	if err != nil {
		// this almost always just means that the user doesn't
		// have a valid login.
		//log.Printf("decodeCookie: %s\n", err)
		return Session{}, nil
	}

	return session, gobHash
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// get our session a little early, so that we can add our
	// authentication information to it if we get some
	session, gobHash := h.getCookieSession(req)

	// store both the session and gobHash on this request's context
	ctx := req.Context()
	ctx = context.WithValue(ctx, sessionKey, session)
	ctx = context.WithValue(ctx, gobHashKey, gobHash)

	req = req.WithContext(ctx)

	sessionWriter := &responseWriter{rw, h, req, 0}
	h.Handler.ServeHTTP(sessionWriter, req)
}

// NewHandler creates a new seshcookie Handler with a given encryption
// key and configuration.
func NewHandler(handler http.Handler, key string, config *Config) *Handler {
	if key == "" {
		panic("don't use an empty key")
	}

	// sha256 sums are 32 bytes long.  we use the first 16 bytes as
	// the aes key.
	encHash := sha256.New()
	encHash.Write([]byte(key))
	encHash.Write([]byte("-seshcookie-encryption"))

	// if the user hasn't specified a config, use the package's
	// default one
	if config == nil {
		config = DefaultConfig
	}

	return &Handler{
		Handler:    handler,
		CookieName: "session",
		CookiePath: "/",
		config:     *config,
		encKey:     encHash.Sum(nil)[:blockSize],
	}
}
