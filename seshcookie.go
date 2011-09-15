// Copyright 2011 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.
package seshcookie

import (
	"http"
	"os"
	"log"
	"time"
	"gob"
	"bytes"
	"sync"
	"sync/atomic"
	"crypto/sha1"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
)

var (
	// if you don't need multiple independent seshcookie
	// instances, you can use this RequestSessions instance to
	// manage & access your sessions.  Simply use it as the final
	// parameter in your call to seshcookie.NewSessionHandler, and
	// whenever you want to access the current session from an
	// embedded http.Handler you can simply call:
	//
	//     seshcookie.Session.Get(req)
	Session = new(RequestSessions)

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
	h           *SessionHandler
	req         *http.Request
	wroteHeader int32
}

type SessionHandler struct {
	http.Handler
	// The name of the cookie our encoded session will be stored
	// in.
	CookieName string
	RS         *RequestSessions
	key        []byte
}

type RequestSessions struct {
	lk sync.Mutex
	m  map[*http.Request]map[string]interface{}
}

func (rs *RequestSessions) Get(req *http.Request) map[string]interface{} {
	rs.lk.Lock()
	defer rs.lk.Unlock()

	if rs.m == nil {
		return nil
	}

	return rs.m[req]
}

func (rs *RequestSessions) Set(req *http.Request, val map[string]interface{}) {
	rs.lk.Lock()
	defer rs.lk.Unlock()

	if rs.m == nil {
		rs.m = map[*http.Request]map[string]interface{}{}
	}

	rs.m[req] = val
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
//   iv + encrypted(salt + sha1 + data)
//
func encode(block cipher.Block, data []byte) ([]byte, os.Error) {

	buf := bytes.NewBuffer(nil)

	dataHash := sha1.New()
	dataHash.Write(data)

	salt := make([]byte, block.BlockSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	buf.Write(salt)

	buf.Write(dataHash.Sum())
	buf.Write(data)

	session := buf.Bytes()

	iv := make([]byte, block.BlockSize(), 2*block.BlockSize()+len(session))
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(session, session)

	return append(iv, session...), nil
}

func encodeCookie(content interface{}, key []byte) (string, os.Error) {
	encodedGob, err := encodeGob(content)
	if err != nil {
		return "", err
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	sessionBytes, err := encode(aesCipher, encodedGob)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sessionBytes), nil
}

// decode uses the given block cipher (in CTR mode) to decrypt the
// data, and validate the hash.  If hash validation fails, an error is
// returned.
func decode(block cipher.Block, encoded []byte) ([]byte, os.Error) {
	if len(encoded) < block.BlockSize() {
		return nil, LenError
	}

	iv := encoded[:block.BlockSize()]
	session := encoded[block.BlockSize():]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(session, session)

	// skip past the iv
	session = session[block.BlockSize():]
	expectedHash := session[:sha1.Size]
	session = session[sha1.Size:]

	sessionHash := sha1.New()
	sessionHash.Write(session)

	if !bytes.Equal(sessionHash.Sum(), expectedHash) {
		return nil, HashError
	}

	return session, nil
}

func decodeCookie(encodedCookie string, key []byte) (map[string]interface{}, os.Error) {
	sessionBytes, err := base64.StdEncoding.DecodeString(encodedCookie)
	if err != nil {
		return nil, err
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gobBytes, err := decode(aesCipher, sessionBytes)
	if err != nil {
		return nil, err
	}

	session, err := decodeGob(gobBytes)
	if err != nil {
		log.Printf("decodeGob: %s\n", err)
		return nil, err
	}
	return session, nil
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
				log.Println("clearing cookie")
				var cookie http.Cookie
				cookie.Name = s.h.CookieName
				cookie.Value = ""
				cookie.Path = "/"
				// a cookie is expired by setting it
				// with an expiration time in the past
				cookie.Expires = *time.SecondsToUTC(0)
				http.SetCookie(s, &cookie)
			} else {
				log.Println("not setting empty cookie")
			}
			goto write
		}
		encoded, err := encodeCookie(session, s.h.key)
		if err != nil {
			log.Printf("createCookie: %s\n", err)
			goto write
		}

		if encoded == origCookieVal {
			//log.Println("not re-setting identical cookie")
			goto write
		}

		var cookie http.Cookie
		cookie.Name = s.h.CookieName
		cookie.Value = encoded
		cookie.Path = "/"
		http.SetCookie(s, &cookie)
	}
write:
	s.ResponseWriter.WriteHeader(code)
}

func (h *SessionHandler) getCookieSession(req *http.Request) map[string]interface{} {
	cookie, err := req.Cookie(h.CookieName)
	if err != nil {
		log.Printf("getCookieSesh: '%#v' not found\n",
			h.CookieName)
		return map[string]interface{}{}
	}
	session, err := decodeCookie(cookie.Value, h.key)
	if err != nil {
		log.Printf("decodeCookie: %s\n", err)
		return map[string]interface{}{}
	}

	return session
}

func (h *SessionHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// get our session a little early, so that we can add our
	// authentication information to it if we get some
	session := h.getCookieSession(req)

	h.RS.Set(req, session)

	sessionWriter := sessionResponseWriter{rw, h, req, 0}
	h.Handler.ServeHTTP(sessionWriter, req)

	h.RS.Clear(req)
}

func NewSessionHandler(handler http.Handler, cookieName, key string, rs *RequestSessions) *SessionHandler {
	// sha1 sums are 20 bytes long.  we use the first 16 bytes as
	// the aes key.
	keySha1 := sha1.New()
	keySha1.Write([]byte(key))
	sum := keySha1.Sum()
	return &SessionHandler{
		Handler:    handler,
		CookieName: cookieName,
		RS:         rs,
		key:        sum[:aes.BlockSize],
	}
}
