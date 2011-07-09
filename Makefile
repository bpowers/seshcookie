include $(GOROOT)/src/Make.inc

TARG = seshcookie
GOFILES = \
	seshcookie.go

include $(GOROOT)/src/Make.pkg

.PHONY: gofmt
gofmt:
	gofmt -w $(GOFILES)
