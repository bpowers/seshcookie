seshcookie - cookie-based sessions for Go
=========================================

seshcookie allows you to associate session-state with http requests
while allowing your server to remain stateless.  It's inspired by
[Beaker](http://pypi.python.org/pypi/Beaker), which provides a similar
service for Python webapps.

Right now it requries a small patch to the Go sources, which can be
applied by:

    $ pushd $GOROOT
    $ patch -p1 <PATH_TO_SESHCOOKIE/go_http.diff
    $ cd src; ./all.bash
    $ popd

The example uses seshcookie in a way similar to make sure users are
authenticated before they can see a particular resource.  In
particular, it shows how you stack multiple http.Handlers together to
get the behavior you want.