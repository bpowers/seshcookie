package main
// Copyright 2011 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

import (
	"log"
	"http"
	"seshcookie"
)

type AuthHandler struct {
	http.Handler
	Users map[string]string
}

func (h *AuthHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	session := seshcookie.Session.Get(req)
	log.Printf("using session: %#v\n", session)

	switch req.URL.Path {
	case "/login":
		rw.Header().Set("Content-Type", "text/html")
		http.ServeFile(rw, req, "./login.html")
		return
	case "/session":
		if req.Method != "POST" {
			http.Redirect(rw, req, "/login", http.StatusFound)
			return
		}
		err := req.ParseForm()
		if err != nil {
			log.Printf("error '%s' parsing form for %#v\n", err, req)
		}
		user := req.Form.Get("user")
		expectedPass, exists := h.Users[user]
		if !exists || req.Form.Get("pass") != expectedPass {
			log.Printf("user:%s pass:%s\n", user, req.Form.Get("pass"))
			rw.Header().Set("Content-Type", "text/html")
			http.ServeFile(rw, req, "./login.html")
			return
		}

		log.Printf("authenticated %s\n", user)
		session["user"] = user
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	case "/logout":
		session["user"] = "", false
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
	var content http.Dir = "secured"
	err := http.ListenAndServe(":8080", seshcookie.NewSessionHandler(
		&AuthHandler{http.FileServer(content),
			map[string]string{"user": "password!"}},
		"session",
		"some known but hard to guess session key",
		seshcookie.Session))
	if err != nil {
		log.Printf("ListenAndServe:", err)
	}
}
