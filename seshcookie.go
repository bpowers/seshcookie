package seshcookie
// Copyright 2011 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

import (
	"http"
	"os"
	"log"
	"time"
	"gob"
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"crypto/sha1"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
)

// if you don't need multiple independent seshcookie instances, you
// can use this RequestSessions instance to manage & access your
// sessions.  Simply use it as the final parameter in your call to
// seshcookie.NewSessionHandler, and whenever you want to access the
// current session from an embedded http.Handler you can simply call:
//
//     seshcookie.Sessions.Get(req)
var Session = new(RequestSessions)

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
	iv         []byte
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

func encodeGob(obj interface{}) (string, os.Error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(obj)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
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

func encodeCookie(content interface{}, key, iv []byte) (string, os.Error) {
	sessionGob, err := encodeGob(content)
	if err != nil {
		return "", err
	}
	padLen := aes.BlockSize - (len(sessionGob)+4)%aes.BlockSize
	buf := bytes.NewBuffer(nil)
	var sessionLen int32 = (int32)(len(sessionGob))
	binary.Write(buf, binary.BigEndian, sessionLen)
	buf.WriteString(sessionGob)
	buf.WriteString(strings.Repeat("\000", padLen))
	sessionBytes := buf.Bytes()
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encrypter := cipher.NewCBCEncrypter(aesCipher, iv)
	encrypter.CryptBlocks(sessionBytes, sessionBytes)
	b64 := base64.StdEncoding.EncodeToString(sessionBytes)
	return b64, nil
}

func decodeCookie(encodedCookie string, key, iv []byte) (map[string]interface{}, os.Error) {
	sessionBytes, err := base64.StdEncoding.DecodeString(encodedCookie)
	if err != nil {
		log.Printf("base64.Decodestring: %s\n", err)
		return nil, err
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("aes.NewCipher: %s\n", err)
		return nil, err
	}
	// decrypt in-place
	decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	decrypter.CryptBlocks(sessionBytes, sessionBytes)

	buf := bytes.NewBuffer(sessionBytes)
	var gobLen int32
	binary.Read(buf, binary.BigEndian, &gobLen)
	gobBytes := sessionBytes[4 : 4+gobLen]
	session, err := decodeGob(gobBytes)
	if err != nil {
		log.Printf("decodeGob: %s\n", err)
		return nil, err
	}
	return session, nil
}

func (s sessionResponseWriter) WriteHeader(code int) {

	log.Printf("%d - %s\n", code, s.req.URL.Path)

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
		encoded, err := encodeCookie(session, s.h.key, s.h.iv)
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
	session, err := decodeCookie(cookie.Value, h.key, h.iv)
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
	// the aes key, and the last 16 bytes as the initialization
	// vector (understanding that they overlap, of course).
	keySha1 := sha1.New()
	keySha1.Write([]byte(key))
	sum := keySha1.Sum()
	return &SessionHandler{
		Handler:    handler,
		CookieName: cookieName,
		RS:         rs,
		key:        sum[:16],
		iv:         sum[4:],
	}
}
