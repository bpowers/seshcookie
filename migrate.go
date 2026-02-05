// Copyright 2025 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package seshcookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
)

// MigrateFunc converts raw JSON bytes from a seshcookie-js session
// into the caller's protobuf session type. The JSON is the direct
// plaintext that was stored in the JS cookie (i.e. JSON.stringify(session)).
type MigrateFunc[T proto.Message] func(jsonData []byte) (T, error)

// migrateConfig holds pre-computed state for JS cookie migration.
type migrateConfig[T proto.Message] struct {
	jsEncKey []byte
	convert  MigrateFunc[T]
}

// Option configures optional Handler behavior.
type Option[T proto.Message] func(*handlerOptions[T])

// handlerOptions collects all optional configuration.
type handlerOptions[T proto.Message] struct {
	migrate *migrateConfig[T]
}

// WithMigration returns an Option that enables transparent migration
// from seshcookie-js cookies. jsKey is the key string that was passed
// to the JS seshcookie constructor. convert transforms the JSON session
// payload into the caller's protobuf type.
//
// When a request arrives with a JS-format cookie (no "sc1_" prefix,
// three base64 parts separated by hyphens), the handler decrypts it
// using the JS key derivation (SHA256(key)[:16]) and passes the JSON
// plaintext to convert. The resulting session is written back as a
// Go-format cookie on the response, completing the migration.
func WithMigration[T proto.Message](jsKey string, convert MigrateFunc[T]) Option[T] {
	encKey := deriveJSKey(jsKey)
	return func(o *handlerOptions[T]) {
		o.migrate = &migrateConfig[T]{
			jsEncKey: encKey,
			convert:  convert,
		}
	}
}

// deriveJSKey replicates the seshcookie-js key derivation: SHA256(key)[:16].
func deriveJSKey(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:16]
}

// decodeJSCookie decrypts a seshcookie-js cookie value and returns the
// JSON plaintext. The JS wire format is "b64(nonce)-b64(ciphertext)-b64(tag)"
// with the nonce passed as AAD.
func decodeJSCookie(encoded string, jsEncKey []byte) ([]byte, error) {
	parts := strings.Split(encoded, "-")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 parts, got %d", len(parts))
	}

	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	tag, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode tag: %w", err)
	}

	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("nonce length %d, want %d", len(nonce), gcmNonceSize)
	}

	block, err := aes.NewCipher(jsEncKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	aeadCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	// Go's aead.Open expects ciphertext with tag appended.
	// JS separates them, so concatenate before decrypting.
	// JS passes nonce as AAD via cipher.setAAD(nonce).
	plaintext, err := aeadCipher.Open(nil, nonce, slices.Concat(ciphertext, tag), nonce)
	if err != nil {
		return nil, fmt.Errorf("aeadCipher.Open: %w", err)
	}

	return plaintext, nil
}

// decodeJSSession attempts to decrypt a JS-format cookie and convert
// the JSON payload to the caller's protobuf session type. Returns the
// zero value of T and an error on failure.
func (h *Handler[T]) decodeJSSession(cookieValue string) (T, error) {
	var zero T

	if h.opts.migrate == nil {
		return zero, fmt.Errorf("no migration configured")
	}

	jsonData, err := decodeJSCookie(cookieValue, h.opts.migrate.jsEncKey)
	if err != nil {
		return zero, fmt.Errorf("decodeJSCookie: %w", err)
	}

	session, err := h.opts.migrate.convert(jsonData)
	if err != nil {
		return zero, fmt.Errorf("convert: %w", err)
	}

	return session, nil
}
