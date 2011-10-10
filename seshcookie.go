// Copyright 2011 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.
package seshcookie

import (
	"http"
	"io"
	"os"
	"log"
	"time"
	"gob"
	"bytes"
	"sync"
	"sync/atomic"
	"hash"
	"crypto/sha1"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base64"
)

// we want 16 byte blocks, for AES-128
const blockSize = 16

var (
	// if you don't need multiple independent seshcookie
	// instances, you can use this RequestSessions instance to
	// manage & access your sessions.  Simply use it as the final
	// parameter in your call to seshcookie.NewSessionHandler, and
	// whenever you want to access the current session from an
	// embedded http.Handler you can simply call:
	//
	//     seshcookie.Session.Get(req)
	Session = &RequestSessions{HttpOnly:true}

	// Hash validation of the decrypted cookie failed. Most likely
	// the session was encoded with a different cookie than we're
	// using to decode it, but its possible the client (or someone
	// else) tried to modify the session.
	HashError = os.NewError("Hash validation failed")

	// The cookie is too short, so we must exit decoding early.
	LenError = os.NewError("Bad cookie length")
)

type sessionResponseWriter struct {
	http.ResponseWriter
	h   *SessionHandler
	req *http.Request
	// int32 so we can use the sync/atomic functions on it
	wroteHeader int32
}

type SessionHandler struct {
	http.Handler
	CookieName string // name of the cookie to store our session in
	CookiePath string // resource path the cookie is valid for
	RS         *RequestSessions
	encKey     []byte
	hmacKey    []byte
}

type RequestSessions struct {
	HttpOnly bool // don't allow javascript to access cookie
	Secure   bool // only send session over HTTPS
	lk       sync.Mutex
	m        map[*http.Request]map[string]interface{}
	// stores a hash of the serialized session (the gob) that we
	// received with the start of the request.  Before setting a
	// cookie for the reply, check to see if the session has
	// actually changed.  If it hasn't, then we don't need to send
	// a new cookie.
	hm map[*http.Request][]byte
}

func (rs *RequestSessions) Get(req *http.Request) map[string]interface{} {
	rs.lk.Lock()
	defer rs.lk.Unlock()

	if rs.m == nil {
		log.Print("seshcookie: warning! trying to get session " +
			"data for unknown request. Perhaps your handler " +
			"isn't wrapped by a SessionHandler?")
		return nil
	}

	return rs.m[req]
}

func (rs *RequestSessions) getHash(req *http.Request) []byte {
	rs.lk.Lock()
	defer rs.lk.Unlock()

	if rs.hm == nil {
		return nil
	}

	return rs.hm[req]
}

func (rs *RequestSessions) Set(req *http.Request, val map[string]interface{}, gobHash []byte) {
	rs.lk.Lock()
	defer rs.lk.Unlock()

	if rs.m == nil {
		rs.m = map[*http.Request]map[string]interface{}{}
		rs.hm = map[*http.Request][]byte{}
	}

	rs.m[req] = val
	rs.hm[req] = gobHash
}

func (rs *RequestSessions) Clear(req *http.Request) {
	rs.lk.Lock()
	defer rs.lk.Unlock()

	rs.m[req] = nil, false
}

func encodeGob(obj interface{}) ([]byte, os.Error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(obj)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeGob(encoded []byte) (map[string]interface{}, os.Error) {
	buf := bytes.NewBuffer(encoded)
	dec := gob.NewDecoder(buf)
	var out map[string]interface{}
	err := dec.Decode(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// encode uses the given block cipher (in CTR mode) to encrypt the
// data, along with a hash, returning the iv and the ciphertext. What
// is returned looks like:
//
//   encrypted(salt + sessionData) + iv + hmac
//
func encode(block cipher.Block, hmac hash.Hash, data []byte) ([]byte, os.Error) {

	buf := bytes.NewBuffer(nil)

	salt := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	buf.Write(salt)
	buf.Write(data)

	session := buf.Bytes()

	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(session, session)

	buf.Write(iv)
	hmac.Write(buf.Bytes())
	buf.Write(hmac.Sum())

	return buf.Bytes(), nil
}

func encodeCookie(content interface{}, encKey, hmacKey []byte) (string, []byte, os.Error) {
	encodedGob, err := encodeGob(content)
	if err != nil {
		return "", nil, err
	}

	gobHash := sha1.New()
	gobHash.Write(encodedGob)

	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return "", nil, err
	}

	hmacHash := hmac.NewSHA256(hmacKey)

	sessionBytes, err := encode(aesCipher, hmacHash, encodedGob)
	if err != nil {
		return "", nil, err
	}

	return base64.StdEncoding.EncodeToString(sessionBytes), gobHash.Sum(), nil
}

// decode uses the given block cipher (in CTR mode) to decrypt the
// data, and validate the hash.  If hash validation fails, an error is
// returned.
func decode(block cipher.Block, hmac hash.Hash, ciphertext []byte) ([]byte, os.Error) {
	if len(ciphertext) < 2*block.BlockSize()+hmac.Size() {
		return nil, LenError
	}

	receivedHmac := ciphertext[len(ciphertext)-hmac.Size():]
	ciphertext = ciphertext[:len(ciphertext)-hmac.Size()]

	hmac.Write(ciphertext)
	if subtle.ConstantTimeCompare(hmac.Sum(), receivedHmac) != 1 {
		return nil, HashError
	}

	// split the iv and session bytes
	iv := ciphertext[len(ciphertext)-block.BlockSize():]
	session := ciphertext[:len(ciphertext)-block.BlockSize()]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(session, session)

	// skip past the iv
	session = session[block.BlockSize():]

	return session, nil
}

func decodeCookie(encoded string, encKey, hmacKey []byte) (map[string]interface{}, []byte, os.Error) {
	sessionBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}
	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, err
	}

	hmacHash := hmac.NewSHA256(hmacKey)
	gobBytes, err := decode(aesCipher, hmacHash, sessionBytes)
	if err != nil {
		return nil, nil, err
	}

	gobHash := sha1.New()
	gobHash.Write(gobBytes)

	session, err := decodeGob(gobBytes)
	if err != nil {
		log.Printf("decodeGob: %s\n", err)
		return nil, nil, err
	}
	return session, gobHash.Sum(), nil
}

func (s sessionResponseWriter) WriteHeader(code int) {
	if atomic.AddInt32(&s.wroteHeader, 1) == 1 {
		origCookie, err := s.req.Cookie(s.h.CookieName)
		var origCookieVal string
		if err != nil {
			origCookieVal = ""
		} else {
			origCookieVal = origCookie.Value
		}

		session := s.h.RS.Get(s.req)
		if len(session) == 0 {
			// if we have an empty session, but the
			// request didn't start out that way, we
			// assume the user wants us to clear the
			// session
			if origCookieVal != "" {
				//log.Println("clearing cookie")
				var cookie http.Cookie
				cookie.Name = s.h.CookieName
				cookie.Value = ""
				cookie.Path = "/"
				// a cookie is expired by setting it
				// with an expiration time in the past
				cookie.Expires = *time.SecondsToUTC(0)
				http.SetCookie(s, &cookie)
			}
			goto write
		}
		encoded, gobHash, err := encodeCookie(session, s.h.encKey, s.h.hmacKey)
		if err != nil {
			log.Printf("createCookie: %s\n", err)
			goto write
		}

		if bytes.Equal(gobHash, s.h.RS.getHash(s.req)) {
			//log.Println("not re-setting identical cookie")
			goto write
		}

		var cookie http.Cookie
		cookie.Name = s.h.CookieName
		cookie.Value = encoded
		cookie.Path = s.h.CookiePath
		cookie.HttpOnly = s.h.RS.HttpOnly
		cookie.Secure = s.h.RS.Secure
		http.SetCookie(s, &cookie)
	}
write:
	s.ResponseWriter.WriteHeader(code)
}

func (h *SessionHandler) getCookieSession(req *http.Request) (map[string]interface{}, []byte) {
	cookie, err := req.Cookie(h.CookieName)
	if err != nil {
		//log.Printf("getCookieSesh: '%#v' not found\n",
		//	h.CookieName)
		return map[string]interface{}{}, nil
	}
	session, gobHash, err := decodeCookie(cookie.Value, h.encKey, h.hmacKey)
	if err != nil {
		log.Printf("decodeCookie: %s\n", err)
		return map[string]interface{}{}, nil
	}

	return session, gobHash
}

func (h *SessionHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// get our session a little early, so that we can add our
	// authentication information to it if we get some
	session, gobHash := h.getCookieSession(req)

	h.RS.Set(req, session, gobHash)

	sessionWriter := sessionResponseWriter{rw, h, req, 0}
	h.Handler.ServeHTTP(sessionWriter, req)

	h.RS.Clear(req)
}

func NewSessionHandler(handler http.Handler, key string, rs *RequestSessions) *SessionHandler {
	// sha1 sums are 20 bytes long.  we use the first 16 bytes as
	// the aes key.
	encHash := sha1.New()
	encHash.Write([]byte(key))
	encHash.Write([]byte("-encryption"))
	hmacHash := sha1.New()
	hmacHash.Write([]byte(key))
	hmacHash.Write([]byte("-hmac"))

	// if the user hasn't specified a session handler, use the
	// package's default one
	if rs == nil {
		rs = Session
	}

	return &SessionHandler{
		Handler:    handler,
		CookieName: "session",
		CookiePath: "/",
		RS:         rs,
		encKey:     encHash.Sum()[:blockSize],
		hmacKey:    hmacHash.Sum()[:blockSize],
	}
}
