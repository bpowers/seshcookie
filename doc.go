// Copyright 2017 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

/*
Package seshcookie enables you to associate session-state with HTTP
requests while keeping your server stateless.  Because session-state
is transferred as part of the HTTP request (in a cookie), state can be
seamlessly maintained between server restarts or load balancing.  It's
inspired by Beaker (http://pypi.python.org/pypi/Beaker), which
provides a similar service for Python webapps.  The cookies are AES
encrypted in CTR mode, with the key derived from a user-specified
string.  This makes seshcookie reliable and secure.

Storing session-state in a cookie makes building some apps trivial,
like this example that tells a user how many times they have visited
the site:

	package main

	import (
		"net/http"
		"log"
		"fmt"

		"github.com/bpowers/seshcookie"
	)

	type VisitedHandler struct{}

	func (h *VisitedHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			return
		}

		session := seshcookie.GetSession(req.Context())

		count, _ := session["count"].(int)
		count += 1
		session["count"] = count

		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(200)
		if count == 1 {
			rw.Write([]byte("this is your first visit, welcome!"))
		} else {
			rw.Write([]byte(fmt.Sprintf("page view #%d", count)))
		}
	}

	func main() {
		key := "session key, preferably a sequence of data from /dev/urandom"
		http.Handle("/", seshcookie.NewHandler(
			&VisitedHandler{},
			key,
			&seshcookie.Config{HttpOnly: true, Secure: false}))

		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal("ListenAndServe:", err)
		}
	}
*/
package seshcookie
