// Copyright 2017 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.
package main

import (
	"log"
	"net/http"

	"github.com/bpowers/seshcookie"
)

var contentDir http.Dir = "./secured"

// a simple map of users to their passwords, for demo purposes
var userDb = map[string]string{
	"user1": "love",
	"user2": "sex",
	"user3": "secret",
	"user4": "god",
}

// AuthHandler is an http.Handler which is meant to be sandwiched
// between the seshcookie session handler and the handler for
// resources you wish to require authentication to access.
type AuthHandler struct {
	http.Handler
	Users map[string]string
}

// Restricts resource access to only those who have been logged in.
// In order to provide a mechanism for logging in (and logging back
// out) 2 paths are reserved for use by AuthHandler: "/login", and
// "/logout".
//
// A GET request on "/login" serves a login form, which, upon
// submission POSTs to "/login".  If the login was successful, the
// user is redirected to "/".
//
// Logging out is simply a matter of clearing the 'user' key from the
// session map and redirecting to "/login"
func (h *AuthHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	session := seshcookie.GetSession(req.Context())
	log.Printf("using session: %#v\n", session)

	switch req.URL.Path {
	case "/login":
		if req.Method != "POST" {
			http.ServeFile(rw, req, "./login.html")
			return
		}
		err := req.ParseForm()
		if err != nil {
			log.Printf("error '%s' parsing form for %#v\n", err, req)
		}
		user := req.Form.Get("user")
		expectedPass, exists := h.Users[user]
		if !exists || req.Form.Get("pass") != expectedPass {
			log.Printf("authentication failed for %s (pass:%s)\n",
				user, req.Form.Get("pass"))
			http.Redirect(rw, req, "/login", http.StatusFound)
			return
		}

		log.Printf("authorized %s\n", user)
		session["user"] = user
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	case "/logout":
		delete(session, "user")
		http.Redirect(rw, req, "/login", http.StatusFound)
		return
	}

	if _, ok := session["user"]; !ok {
		http.Redirect(rw, req, "/login", http.StatusFound)
		return
	}

	h.Handler.ServeHTTP(rw, req)
}

func main() {
	// Here we have 3 levels of handlers:
	// 1 - session handler
	// 2 - auth handler
	// 3 - file server
	//
	// When a request comes in, first it goes through the session
	// handler, which deals with decrypting and unpacking session
	// data coming in as cookies on incoming requests, and making
	// sure the session is serialized when the response header is
	// written.  After deserializing the incoming session, the
	// request is passed to AuthHandler (defined above).
	// AuthHandler directly serves requests for /login, /logout,
	// and /session.  Requests for any other resource require the
	// session map to have a user key, which is obtained by
	// logging in.  If the user key is present, the request is
	// passed to the FileServer, otherwise the browser is
	// redirected to the login page.
	handler := seshcookie.NewHandler(
		&AuthHandler{http.FileServer(contentDir), userDb},
		"session key, preferably a sequence of data from /dev/urandom",
		&seshcookie.Config{HttpOnly: true, Secure: false})

	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Printf("ListenAndServe: %s", err)
	}
}
