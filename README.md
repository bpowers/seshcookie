seshcookie - cookie-based sessions for Go
=========================================

[![Build Status](https://travis-ci.org/bpowers/seshcookie.svg?branch=master)](https://travis-ci.org/bpowers/seshcookie)
[![GoDoc](https://godoc.org/github.com/bpowers/seshcookie?status.svg)](https://godoc.org/github.com/bpowers/seshcookie)
[![Go Report Card](https://goreportcard.com/badge/github.com/bpowers/seshcookie)](https://goreportcard.com/report/github.com/bpowers/seshcookie)

seshcookie enables you to associate session-state with HTTP requests
while keeping your server stateless.  Because session-state is
transferred as part of the HTTP request (in a cookie), state can be
seamlessly maintained between server restarts or load balancing.  It's
inspired by [Beaker](http://pypi.python.org/pypi/Beaker), which
provides a similar service for Python webapps.  The cookies are AES
encrypted in CTR mode, with the key derived from a user-specified
string.  This makes seshcookie reliable and secure.

examples
--------

The simple example below returns different content based on whether
the user has visited the site before or not:


```Go
package main

import (
	"fmt"
	"log"
	"net/http"

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
```

There is a more detailed example in example/ which uses seshcookie to
enforce authentication for a particular resource.  In particular, it
shows how you can embed (or stack) multiple http.Handlers to get the
behavior you want.

license
-------

seshcookie is offered under the MIT license, see LICENSE for details.
