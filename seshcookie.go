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
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bpowers/seshcookie/v3/internal/pb"
)

const (
	// we want 16 byte blocks, for AES-128
	blockSize    = 16
	gcmNonceSize = 12
)

const defaultCookieName = "session"

// versionPrefix is prepended to all Go-format cookies for
// unambiguous format detection during JS migration.
const versionPrefix = "sc1_"

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

// deriveKey derives an AES-128 encryption key from a user-provided key string
// using Argon2id, a memory-hard key derivation function resistant to GPU attacks.
//
// The salt is deterministically derived from the key itself to maintain the
// stateless design (no salt storage needed). While this means the salt is not
// independent, it provides defense-in-depth if the key has weak entropy.
//
// SECURITY: The key parameter should be high-entropy (e.g., from crypto/rand).
// Argon2id parameters follow OWASP recommendations for session key derivation.
func deriveKey(key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("key must not be empty")
	}

	// Derive a deterministic salt from the key
	// Format: SHA256("seshcookie-v2-salt" || key)
	saltHash := sha256.New()
	saltHash.Write([]byte("seshcookie-v2-salt"))
	saltHash.Write([]byte(key))
	salt := saltHash.Sum(nil)[:16] // 16-byte salt

	// Argon2id parameters (OWASP recommendations)
	const (
		time    = 3         // 3 iterations
		memory  = 16 * 1024 // 16 MB in KiB
		threads = 4         // 4 parallel threads
		keyLen  = 16        // 16 bytes for AES-128
	)

	// Derive key using Argon2id
	derivedKey := argon2.IDKey(
		[]byte(key),
		salt,
		time,
		memory,
		threads,
		keyLen,
	)

	if len(derivedKey) != blockSize {
		return nil, fmt.Errorf("derived key length mismatch: got %d, want %d",
			len(derivedKey), blockSize)
	}

	return derivedKey, nil
}

// contextKey is used for storing session data in context.
// We use a generic struct to ensure each Handler[T] has a unique key type.
type contextKey[T proto.Message] struct{}

// sessionData holds both the session and a hash for change detection
type sessionData[T proto.Message] struct {
	session  T
	hash     []byte
	changed  bool                   // tracks if SetSession was called
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

// Compile-time interface assertions
var (
	_ http.Hijacker = (*responseWriter[proto.Message])(nil)
	_ http.Flusher  = (*responseWriter[proto.Message])(nil)
	_ io.ReaderFrom = (*responseWriter[proto.Message])(nil)
)

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
	opts   handlerOptions[T]
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
	envelope := &pb.SessionEnvelope{
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
	var envelope pb.SessionEnvelope
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

	return versionPrefix + base64.StdEncoding.EncodeToString(ciphertext), protoHash.Sum(nil), nil
}

// decodeCookie decrypts a base64-encoded cookie using AES-GCM for
// authenticated decryption and validates session expiry.
// Returns the session, hash, and original issuedAt timestamp.
func decodeCookie[T proto.Message](encoded string, encKey []byte, maxAge time.Duration) (T, []byte, *timestamppb.Timestamp, error) {
	var zero T

	encoded = strings.TrimPrefix(encoded, versionPrefix)

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
	if hj, ok := s.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}

func (s *responseWriter[T]) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *responseWriter[T]) ReadFrom(r io.Reader) (int64, error) {
	if atomic.LoadInt32(&s.wroteHeader) == 0 {
		s.WriteHeader(http.StatusOK)
	}
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(s.ResponseWriter, r)
}

func (h *Handler[T]) getCookieSession(req *http.Request) (T, []byte, *timestamppb.Timestamp) {
	var zero T

	cookie, err := req.Cookie(h.Config.CookieName)
	if err != nil {
		return zero, nil, nil
	}

	value := cookie.Value

	if strings.HasPrefix(value, versionPrefix) {
		session, protoHash, issuedAt, err := decodeCookie[T](value, h.encKey, h.Config.MaxAge)
		if err != nil {
			return zero, nil, nil
		}
		return session, protoHash, issuedAt
	}

	// No prefix: try JS migration if configured
	if h.opts.migrate != nil {
		session, err := h.decodeJSSession(value)
		if err == nil {
			// nil hash so writeCookie always rewrites as Go format
			return session, nil, nil
		}
		// JS decode failed; fall through to legacy Go decode
	}

	// Legacy Go-format cookie (pre-sc1_ version): attempt decode
	session, _, issuedAt, err := decodeCookie[T](value, h.encKey, h.Config.MaxAge)
	if err != nil {
		return zero, nil, nil
	}
	// nil hash so writeCookie rewrites with sc1_ prefix
	return session, nil, issuedAt
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

// NewMiddleware returns a middleware constructor for a new seshcookie
// Handler with a given encryption key and configuration. The type
// parameter T specifies the protobuf message type to use for sessions.
//
// key must be non-empty and is used to derive the encryption key.
// config can be nil, in which case DefaultConfig is used.
//
// Example:
//
//	mw, err := seshcookie.NewHandler[*UserSession]("my-secret-key", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	http.Handle("/", mw(http.HandlerFunc(myHandler))
func NewMiddleware[T proto.Message](key string, config *Config, opts ...Option[T]) (func(http.Handler) http.Handler, error) {
	if key == "" {
		return nil, errors.New("encryption key must not be empty")
	}

	encKey, err := deriveKey(key)
	if err != nil {
		return nil, fmt.Errorf("deriveKey: %w", err)
	}

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

	var options handlerOptions[T]
	for _, o := range opts {
		o(&options)
	}

	return func(next http.Handler) http.Handler {
		return &Handler[T]{
			Handler: next,
			Config:  *config,
			encKey:  encKey,
			opts:    options,
		}
	}, nil
}

// NewHandler returns a new seshcookie Handler with a given inner handler,
// encryption key, and configuration. The type parameter T specifies the
// protobuf message type to use for sessions.
//
// key must be non-empty and is used to derive the encryption key.
// config can be nil, in which case DefaultConfig is used.
//
// Example:
//
//	handler, err := seshcookie.NewHandler[*UserSession](innerHandler, "my-secret-key", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	http.ListenAndServe(":8080", handler)
func NewHandler[T proto.Message](handler http.Handler, key string, config *Config, opts ...Option[T]) (*Handler[T], error) {
	if key == "" {
		return nil, errors.New("encryption key must not be empty")
	}

	encKey, err := deriveKey(key)
	if err != nil {
		return nil, fmt.Errorf("deriveKey: %w", err)
	}

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

	var options handlerOptions[T]
	for _, o := range opts {
		o(&options)
	}

	return &Handler[T]{
		Handler: handler,
		Config:  *config,
		encKey:  encKey,
		opts:    options,
	}, nil
}
