include $(GOROOT)/src/Make.inc

TARG = authenticated
GOFILES = \
	auth.go

include $(GOROOT)/src/Make.cmd

.PHONY: gofmt
gofmt:
	gofmt -w $(GOFILES)
