seshcookie - cookie-based sessions for Go
=========================================

seshcookie allows you to associate session-state with http requests
while allowing your server to remain stateless.  Because session-state
is transferred as part of the HTTP request, state can be maintained
seamlessly between server-restarts or load balancing.  It's inspired
by [Beaker](http://pypi.python.org/pypi/Beaker), which provides a
similar service for Python webapps.  The cookies are AES encrypted in
CBC mode, with the key and initialization vector derived from a
user-specified string.

Right now it requries a small patch to the Go sources, which can be
applied by:

    $ pushd $GOROOT
    $ patch -p1 <PATH_TO_SESHCOOKIE/go_http.diff
    $ cd src; ./all.bash
    $ popd

The example uses seshcookie to enforce authentication for a particular
resource.  In particular, it shows how you embed (or stack) multiple
http.Handlers to get the behavior you want.

license
-------

seshcookie is offered under the MIT license, see COPYING for details.