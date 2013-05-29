seshcookie - cookie-based sessions for Go
=========================================

seshcookie allows you to associate session-state with http requests
while allowing your server to remain stateless.  Because session-state
is transferred as part of the HTTP request, state can be maintained
seamlessly between server-restarts or load balancing.  It's inspired
by [Beaker](http://pypi.python.org/pypi/Beaker), which provides a
similar service for Python webapps.  The cookies are AES encrypted in
CTR mode, with the key derived from a user-specified string.

examples
--------

Perhaps the simplest example would be a handler which returns
different content based on if the user has been to the site before or
not:


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
	
		session := seshcookie.Session.Get(req)
	
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
		http.Handle("/", seshcookie.NewSessionHandler(
			&VisitedHandler{},
			key,
			nil))
	
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal("ListenAndServe:", err)
		}
	}


There is a more detailed example in example/ which uses seshcookie to
enforce authentication for a particular resource.  In particular, it
shows how you can embed (or stack) multiple http.Handlers to get the
behavior you want.

license
-------

seshcookie is offered under the MIT license, see LICENSE for details.
