
COV_FILE = cover.out

# quiet output, but allow us to look at what commands are being
# executed by passing 'V=1' to make, without requiring temporarily
# editing the Makefile.
ifneq ($V, 1)
MAKEFLAGS += -s
endif

# GNU make, you are the worst.
.SUFFIXES:
%: %,v
%: RCS/%,v
%: RCS/%
%: s.%
%: SCCS/s.%


all:
	go test
	go install

cover coverage:
	go test -covermode atomic -coverprofile $(COV_FILE)
	go tool cover -html=$(COV_FILE)
