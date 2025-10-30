// Copyright 2025 Bobby Powers. All rights reserved.
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
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// we want 16 byte blocks, for AES-128
	blockSize    = 16
	gcmNonceSize = 12
)

const defaultCookieName = "session"

var (
	// DefaultConfig is used as the configuration if a nil config
	// is passed to NewHandler
	DefaultConfig = &Config{
		CookieName: defaultCookieName, // "session"
		CookiePath: "/",
		HTTPOnly:   true,
		Secure:     true,
		MaxAge:     24 * time.Hour, // 24 hour default expiry
	}

	// ErrSessionExpired is returned when a session has expired
	ErrSessionExpired = errors.New("session expired")

	// ErrNoSession is returned when no session is present in the context
	ErrNoSession = errors.New("no session in context")

	// ErrTypeMismatch is returned when the session type doesn't match expected type
	ErrTypeMismatch = errors.New("session type mismatch")
)

// contextKey is used for storing session data in context.
// We use a generic struct to ensure each Handler[T] has a unique key type.
type contextKey[T proto.Message] struct{}

// sessionData holds both the session and a hash for change detection
type sessionData[T proto.Message] struct {
	session  T
	hash     []byte
	changed  bool // tracks if SetSession was called
	issuedAt *timestamppb.Timestamp // preserve original issue time
}

// responseWriter wraps http.ResponseWriter to intercept header writes
// and manage session cookies.
type responseWriter[T proto.Message] struct {
	http.ResponseWriter
	h   *Handler[T]
	req *http.Request
	// int32 so we can use the sync/atomic functions on it
	wroteHeader int32
}

// Config provides directives to a seshcookie instance on cookie
// attributes, like if they are accessible from JavaScript and/or only
// set on HTTPS connections.
type Config struct {
	CookieName string        // name of the cookie to store our session in
	CookiePath string        // resource path the cookie is valid for
	HTTPOnly   bool          // don't allow JavaScript to access cookie
	Secure     bool          // only send session over HTTPS
	MaxAge     time.Duration // server-side session expiry duration
}

// Handler is the seshcookie HTTP handler that provides a Session
// object to child handlers. It uses Go generics to provide type-safe
// session access.
type Handler[T proto.Message] struct {
	http.Handler
	Config Config
	encKey []byte
}

// GetSession retrieves the session from the context.
// Returns ErrNoSession if no session context is present.
// If the session is empty (no cookie was present), returns a new zero instance.
// The returned session is always a valid proto.Message that can be modified.
func GetSession[T proto.Message](ctx context.Context) (T, error) {
	var zero T
	data, ok := ctx.Value(contextKey[T]{}).(*sessionData[T])
	if !ok || data == nil {
		return zero, ErrNoSession
	}

	session := data.session
	// If session is zero/nil, create and store a new instance
	// This happens on first request when there's no cookie
	if !session.ProtoReflect().IsValid() {
		session = zero.ProtoReflect().New().Interface().(T)
		// Store it so subsequent operations see the same instance
		data.session = session
		// Mark as changed only if SetSession is explicitly called
	}

	return session, nil
}

// SetSession updates the session in the context.
// This marks the session as changed so it will be written back to the cookie.
func SetSession[T proto.Message](ctx context.Context, session T) error {
	data, ok := ctx.Value(contextKey[T]{}).(*sessionData[T])
	if !ok || data == nil {
		return ErrNoSession
	}
	data.session = session
	data.changed = true
	return nil
}

// ClearSession clears the session from the context.
// This will cause the cookie to be deleted on the next response.
func ClearSession[T proto.Message](ctx context.Context) error {
	data, ok := ctx.Value(contextKey[T]{}).(*sessionData[T])
	if !ok || data == nil {
		return ErrNoSession
	}
	var zero T
	data.session = zero
	data.changed = true
	return nil
}

// encodeProto creates a SessionEnvelope with the given payload and timestamp.
// If issuedAt is nil, uses current time.
func encodeProto[T proto.Message](session T, issuedAt *timestamppb.Timestamp) ([]byte, error) {
	// Handle zero value (cleared session)
	// Check if session is nil using reflection
	if !session.ProtoReflect().IsValid() {
		return nil, nil
	}

	// Check if it's the zero value
	if proto.Equal(session, session.ProtoReflect().New().Interface()) {
		return nil, nil
	}

	// Pack the user's proto message into an Any
	anyMsg, err := anypb.New(session)
	if err != nil {
		return nil, fmt.Errorf("anypb.New: %w", err)
	}

	// Use provided timestamp or create new one
	if issuedAt == nil {
		issuedAt = timestamppb.Now()
	}

	// Create the envelope with issued timestamp
	envelope := &SessionEnvelope{
		IssuedAt: issuedAt,
		Payload:  anyMsg,
	}

	// Marshal to protobuf bytes
	plaintext, err := proto.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("proto.Marshal: %w", err)
	}

	return plaintext, nil
}

// decodeProto unmarshals a SessionEnvelope and validates expiry.
// Returns the session and the original issuedAt timestamp.
func decodeProto[T proto.Message](encoded []byte, maxAge time.Duration) (T, *timestamppb.Timestamp, error) {
	var zero T

	if len(encoded) == 0 {
		return zero, nil, nil
	}

	// Unmarshal the envelope
	var envelope SessionEnvelope
	if err := proto.Unmarshal(encoded, &envelope); err != nil {
		return zero, nil, fmt.Errorf("proto.Unmarshal: %w", err)
	}

	// Validate expiry
	if envelope.IssuedAt != nil {
		issuedAt := envelope.IssuedAt.AsTime()
		expiresAt := issuedAt.Add(maxAge)
		if time.Now().After(expiresAt) {
			return zero, nil, ErrSessionExpired
		}
	}

	// Unpack the Any message
	if envelope.Payload == nil {
		return zero, envelope.IssuedAt, nil
	}

	// Create a new instance of T to unmarshal into
	// We need to use reflection to create the right type
	session := zero.ProtoReflect().New().Interface().(T)

	if err := envelope.Payload.UnmarshalTo(session); err != nil {
		// Type mismatch or unmarshal error
		return zero, nil, fmt.Errorf("anypb.UnmarshalTo: %w", err)
	}

	return session, envelope.IssuedAt, nil
}

// encodeCookie encodes a protobuf message into a base64 encoded string,
// using AES-GCM mode for authenticated encryption.
// issuedAt preserves the original issue timestamp (nil for new sessions).
func encodeCookie[T proto.Message](session T, encKey []byte, maxAge time.Duration, issuedAt *timestamppb.Timestamp) (string, []byte, error) {
	plaintext, err := encodeProto(session, issuedAt)
	if err != nil {
		return "", nil, err
	}

	// Empty session means no cookie
	if plaintext == nil {
		return "", nil, nil
	}

	// Hash the plaintext for change detection
	protoHash := sha256.New()
	protoHash.Write(plaintext)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	if block.BlockSize() != blockSize {
		return "", nil, fmt.Errorf("block size assumption mismatch")
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, fmt.Errorf("io.ReadFull(rand.Reader): %w", err)
	}

	aeadCipher, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	ciphertext := aeadCipher.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), protoHash.Sum(nil), nil
}

// decodeCookie decrypts a base64-encoded cookie using AES-GCM for
// authenticated decryption and validates session expiry.
// Returns the session, hash, and original issuedAt timestamp.
func decodeCookie[T proto.Message](encoded string, encKey []byte, maxAge time.Duration) (T, []byte, *timestamppb.Timestamp, error) {
	var zero T

	cookie, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return zero, nil, nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	if len(cookie) < block.BlockSize() {
		return zero, nil, nil, fmt.Errorf("expected ciphertext(%d) to be bigger than blockSize", len(cookie))
	}

	// split the cookie data
	nonce, ciphertext := cookie[:gcmNonceSize], cookie[gcmNonceSize:]

	aeadCipher, err := cipher.NewGCM(block)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	plaintext, err := aeadCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("aeadCipher.Open: %w", err)
	}

	protoHash := sha256.New()
	protoHash.Write(plaintext)

	session, issuedAt, err := decodeProto[T](plaintext, maxAge)
	if err != nil {
		return zero, nil, nil, fmt.Errorf("decodeProto: %w", err)
	}

	return session, protoHash.Sum(nil), issuedAt, nil
}

func (s *responseWriter[T]) Write(data []byte) (int, error) {
	if atomic.LoadInt32(&s.wroteHeader) == 0 {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(data)
}

func (s *responseWriter[T]) writeCookie() {
	origCookieVal := ""
	if origCookie, err := s.req.Cookie(s.h.Config.CookieName); err == nil {
		origCookieVal = origCookie.Value
	}

	data, ok := s.req.Context().Value(contextKey[T]{}).(*sessionData[T])
	if !ok || data == nil {
		return
	}

	// Only write cookie if session was changed or is new
	session := data.session
	isZero := !session.ProtoReflect().IsValid() || proto.Equal(session, session.ProtoReflect().New().Interface())

	if isZero {
		// if we have an empty session, but the user's cookie
		// was non-empty, we need to clear out the users cookie.
		if origCookieVal != "" {
			var cookie http.Cookie
			cookie.Name = s.h.Config.CookieName
			cookie.Value = ""
			cookie.Path = "/"
			// a cookie is expired by setting it
			// with an expiration time in the past
			cookie.Expires = time.Unix(0, 0).UTC()
			http.SetCookie(s, &cookie)
		}
		return
	}

	// Use existing issuedAt to preserve timestamp (nil for new sessions)
	encoded, protoHash, err := encodeCookie(session, s.h.encKey, s.h.Config.MaxAge, data.issuedAt)
	if err != nil {
		log.Printf("encodeCookie: %s\n", err)
		return
	}

	// Only set cookie if it changed
	if !data.changed && bytes.Equal(protoHash, data.hash) {
		return
	}

	var cookie http.Cookie
	cookie.Name = s.h.Config.CookieName
	cookie.Value = encoded
	cookie.Path = s.h.Config.CookiePath
	cookie.HttpOnly = s.h.Config.HTTPOnly
	cookie.Secure = s.h.Config.Secure
	// Note: we don't set MaxAge on the cookie itself, as we handle expiry server-side
	http.SetCookie(s, &cookie)
}

func (s *responseWriter[T]) WriteHeader(code int) {
	// Note: There is a potential race condition if WriteHeader is called
	// from multiple goroutines. This is also true of the underlying
	// http.ResponseWriter. Using atomic operations provides some protection
	// but doesn't fully eliminate the race.
	if atomic.AddInt32(&s.wroteHeader, 1) == 1 {
		s.writeCookie()
	}

	s.ResponseWriter.WriteHeader(code)
}

func (s *responseWriter[T]) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// TODO: support hijacking with atomic flags
	return nil, nil, fmt.Errorf("seshcookie doesn't support hijacking")
}

func (h *Handler[T]) getCookieSession(req *http.Request) (T, []byte, *timestamppb.Timestamp) {
	var zero T

	cookie, err := req.Cookie(h.Config.CookieName)
	if err != nil {
		return zero, nil, nil
	}

	session, protoHash, issuedAt, err := decodeCookie[T](cookie.Value, h.encKey, h.Config.MaxAge)
	if err != nil {
		// Invalid cookie or expired session - treat as no session
		// Log for debugging but don't expose to user
		if errors.Is(err, ErrSessionExpired) {
			// Silently ignore expired sessions
		}
		return zero, nil, nil
	}

	return session, protoHash, issuedAt
}

func (h *Handler[T]) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Get session from cookie
	session, protoHash, issuedAt := h.getCookieSession(req)

	// Create session data to track changes
	data := &sessionData[T]{
		session:  session,
		hash:     protoHash,
		changed:  false,
		issuedAt: issuedAt,
	}

	// Store session data in context
	ctx := req.Context()
	ctx = context.WithValue(ctx, contextKey[T]{}, data)
	req = req.WithContext(ctx)

	sessionWriter := &responseWriter[T]{rw, h, req, 0}
	h.Handler.ServeHTTP(sessionWriter, req)
}

// NewHandler creates a new seshcookie Handler with a given encryption
// key and configuration. The type parameter T specifies the protobuf
// message type to use for sessions.
//
// key must be non-empty and is used to derive the encryption key.
// config can be nil, in which case DefaultConfig is used.
//
// Example:
//
//	handler := seshcookie.NewHandler[*UserSession](
//	    http.HandlerFunc(myHandler),
//	    "my-secret-key",
//	    nil,
//	)
func NewHandler[T proto.Message](handler http.Handler, key string, config *Config) (*Handler[T], error) {
	if key == "" {
		return nil, errors.New("encryption key must not be empty")
	}

	// sha256 sums are 32 bytes long. we use the first 16 bytes as
	// the aes key.
	encHash := sha256.New()
	encHash.Write([]byte(key))
	encHash.Write([]byte("-seshcookie-encryption"))

	// if the user hasn't specified a config, use the package's
	// default one
	if config == nil {
		configCopy := *DefaultConfig
		config = &configCopy
	}

	if config.CookieName == "" {
		config.CookieName = defaultCookieName
	}

	if config.MaxAge == 0 {
		config.MaxAge = DefaultConfig.MaxAge
	}

	return &Handler[T]{
		Handler: handler,
		Config:  *config,
		encKey:  encHash.Sum(nil)[:blockSize],
	}, nil
}
