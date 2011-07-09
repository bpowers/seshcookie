package seshcookie

import (
	"http"
	"os"
	"log"
	"sync/atomic"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"gob"
	"bytes"
	"crypto/sha1"
	"crypto/aes"
	"crypto/cipher"
	"time"
)

type SessionResponseWriter struct {
	http.ResponseWriter
	h           *SessionHandler
	origCookie  string
	session     map[string]interface{}
	wroteHeader int32
}

type SessionHandler struct {
	http.Handler
	CookieName string
	key        []byte
	iv         []byte
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

func (s SessionResponseWriter) createCookie() (string, os.Error) {
	sessionGob, err := encodeGob(s.session)
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
	aesCipher, err := aes.NewCipher(s.h.key)
	if err != nil {
		return "", err
	}
	encrypter := cipher.NewCBCEncrypter(aesCipher, s.h.iv)
	encrypter.CryptBlocks(sessionBytes, sessionBytes)
	b64 := base64.StdEncoding.EncodeToString(sessionBytes)
	return b64, nil
}

func (s SessionResponseWriter) WriteHeader(code int) {
	if atomic.AddInt32(&s.wroteHeader, 1) == 1 {
		if len(s.session) == 0 {
			if s.origCookie != "" {
				log.Println("SHOULD be clearing cookie")
			} else {
				log.Println("not setting empty cookie")
			}
			var cookie http.Cookie
			cookie.Name = s.h.CookieName
			cookie.Value = ""
			cookie.Path = "/"
			// a cookie is expired by setting it with an
			// expiration time in the past
			cookie.Expires = *time.SecondsToUTC(0)
			http.SetCookie(s, &cookie)

			goto write
		}
		encoded, err := s.createCookie()
		if err != nil {
			log.Printf("createCookie: %s\n", err)
			goto write
		}

		if encoded == s.origCookie {
			log.Println("not re-setting identical cookie")
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

func (h *SessionHandler) getCookieSession(req *http.Request) (session map[string]interface{}, cookie string) {
	sessionCookie, err := req.Cookie(h.CookieName)
	if err != nil {
		log.Printf("getCookieSesh: '%#v' not found\n",
			h.CookieName)
		return map[string]interface{}{}, ""
	}
	cookie = sessionCookie.Value

	sessionBytes, err := base64.StdEncoding.DecodeString(cookie)

	if err != nil {
		log.Printf("base64.Decodestring: %s\n", err)
		return map[string]interface{}{}, cookie
	}
	aesCipher, err := aes.NewCipher(h.key)
	if err != nil {
		log.Printf("aes.NewCipher: %s\n", err)
		return map[string]interface{}{}, cookie
	}
	decrypter := cipher.NewCBCDecrypter(aesCipher, h.iv)
	decrypter.CryptBlocks(sessionBytes, sessionBytes)

	buf := bytes.NewBuffer(sessionBytes)
	var gobLen int32
	binary.Read(buf, binary.BigEndian, &gobLen)
	gobBytes := sessionBytes[4 : 4+gobLen]
	session, err = decodeGob(gobBytes)
	if err != nil {
		log.Printf("decodeGob: %s\n", err)
		return map[string]interface{}{}, cookie
	}

	return
}

func (h *SessionHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// get our session a little early, so that we can add our
	// authentication information to it if we get some
	session, cookie := h.getCookieSession(req)

	if req.Env == nil {
		req.Env = map[string]interface{}{}
	}
	req.Env["session"] = session

	sessionWriter := SessionResponseWriter{rw, h, cookie, session, 0}
	h.Handler.ServeHTTP(sessionWriter, req)
}

func NewSessionHandler(handler http.Handler, cookieName, key string) *SessionHandler {
	// sha1 sums are 20 bytes long.  we use the first 16 bytes as
	// the aes key, and the last 16 bytes as the initialization
	// vector (understanding that they overlap, of course).
	keySha1 := sha1.New()
	keySha1.Write([]byte(key))
	sum := keySha1.Sum()
	return &SessionHandler{handler, cookieName, sum[:16], sum[4:]}
}
