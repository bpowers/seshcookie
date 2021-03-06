// Copyright 2017 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

/*
Package seshcookie enables you to associate session-state with HTTP
requests while keeping your server stateless.  Because session-state
is transferred as part of the HTTP request (in a cookie), state can be
seamlessly maintained between server restarts or load balancing.  It's
inspired by Beaker (http://pypi.python.org/pypi/Beaker), which
provides a similar service for Python webapps.  The cookies are
authenticated and encrypted (using AES-GCM) with a key derived from a
string provided to the NewHandler function.  This makes seshcookie
reliable and secure: session contents are opaque to users and not able
to be manipulated or forged by third parties.

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
		count++
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
			&seshcookie.Config{HTTPOnly: true, Secure: false}))

		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("ListenAndServe: %s", err)
		}
	}
*/
package seshcookie
