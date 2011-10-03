/*

	The seshcookie package implements an http.Handler which
	provides stateful sessions stored in cookies.  Because
	session-state is transferred as part of the HTTP request,
	state can be maintained seamlessly between server-restarts or
	load balancing.

	For example, here is a simple handler which returns differnet
	content if you've visited the site before:

		package main
		
		import (
			"http"
			"log"
			"fmt"
			"seshcookie"
		)
		
		type VisitedHandler struct{}
		
		func (h *VisitedHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path != "/" {
				return
			}
		
			session := seshcookie.Session.Get(req)
		
			count, ok := session["count"].(int)
			if !ok {
				session["count"] = 1
			} else {
				session["count"] = count + 1
			}
		
			rw.Header().Set("Content-Type", "text/plain")
			rw.WriteHeader(200)
			if count == 0 {
				rw.Write([]byte("this is your first visit, welcome!"))
			} else {
				rw.Write([]byte(fmt.Sprintf("page view #%d", count)))
			}
		}
		
		func main() {
			key := "session key, preferably a sequence of data from /dev/urandom"
			http.Handle("/", seshcookie.NewSessionHandler(
				&VisitedHandler{},
				"session",
				key,
				seshcookie.Session))
		
			if err := http.ListenAndServe(":8080", nil); err != nil {
				log.Fatal("ListenAndServe:", err)
			}
		}

 */
package seshcookie