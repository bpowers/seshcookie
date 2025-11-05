seshcookie - cookie-based sessions for Go
=========================================

[![Build Status](https://travis-ci.org/bpowers/seshcookie.svg?branch=master)](https://travis-ci.org/bpowers/seshcookie)
[![GoDoc](https://godoc.org/github.com/bpowers/seshcookie/v3?status.svg)](https://godoc.org/github.com/bpowers/seshcookie/v3)
[![cover.run](https://cover.run/go/github.com/bpowers/seshcookie/v3.svg?style=flat&tag=golang-1.10)](https://cover.run/go?tag=golang-1.10&repo=github.com%2Fbpowers%2Fseshcookie)
[![Go Report Card](https://goreportcard.com/badge/github.com/bpowers/seshcookie/v3)](https://goreportcard.com/report/github.com/bpowers/seshcookie/v3)

## Version 3.0 - Go Module v3

**⚠️ Breaking Change:** Version 3.0 updates the module path to follow Go's semantic import versioning. The import path is now `github.com/bpowers/seshcookie/v3`. See [Migration](#migration-from-v2x) below.

## Overview

seshcookie enables you to associate session-state with HTTP requests while keeping your server stateless. Because session-state is transferred as part of the HTTP request (in a cookie), state can be seamlessly maintained between server restarts or load balancing. It's inspired by [Beaker](http://pypi.python.org/pypi/Beaker), which provides a similar service for Python webapps.

The cookies are authenticated and encrypted (using AES-GCM) with a key derived from a string provided to the `NewHandler` function. This makes seshcookie reliable and secure: session contents are opaque to users and not able to be manipulated or forged by third parties.

## Key Features

- **Type-Safe Sessions**: Uses Protocol Buffers for strongly-typed session data
- **Server-Side Expiry**: Sessions expire based on issue time, preventing client-side manipulation
- **Secure by Default**: AES-GCM encryption, HTTPOnly and Secure flags
- **Stateless**: No server-side session storage required
- **Generic API**: Uses Go generics for compile-time type safety
- **Change Detection**: Only updates cookies when session data actually changes

## Installation

```bash
go get github.com/bpowers/seshcookie/v3
```

## Quick Start

### 1. Define Your Session Schema

Create a `.proto` file:

```protobuf
syntax = "proto3";
package myapp;
option go_package = "myapp/pb";

message UserSession {
  string username = 1;
  int32 visit_count = 2;
}
```

Generate Go code:

```bash
protoc --go_out=. --go_opt=paths=source_relative session.proto
```

### 2. Use in Your Application

```Go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/bpowers/seshcookie/v3"
	"myapp/pb"
)

type VisitedHandler struct{}

func (h *VisitedHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		return
	}

	// GetSession returns a valid protobuf message
	session, err := seshcookie.GetSession[*pb.UserSession](req.Context())
	if err != nil {
		http.Error(rw, "Internal error", 500)
		return
	}

	// Modify session
	session.VisitCount++

	// Explicitly save changes
	if err := seshcookie.SetSession(req.Context(), session); err != nil {
		http.Error(rw, "Internal error", 500)
		return
	}

	rw.Header().Set("Content-Type", "text/plain")
	rw.WriteHeader(200)
	if session.VisitCount == 1 {
		rw.Write([]byte("this is your first visit, welcome!"))
	} else {
		rw.Write([]byte(fmt.Sprintf("page view #%d", session.VisitCount)))
	}
}

func main() {
	key := "session key, preferably a sequence of data from /dev/urandom"

	handler, err := seshcookie.NewHandler[*pb.UserSession](
		&VisitedHandler{},
		key,
		&seshcookie.Config{
			HTTPOnly: true,
			Secure:   true,
			MaxAge:   24 * time.Hour,
		})

	if err != nil {
		log.Fatalf("NewHandler: %s", err)
	}

	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatalf("ListenAndServe: %s", err)
	}
}
```

## API Reference

### Creating a Handler

```go
handler, err := seshcookie.NewHandler[*YourProtoType](
    yourHandler,
    encryptionKey,
    &seshcookie.Config{
        CookieName: "session",      // cookie name
        CookiePath: "/",             // cookie path
        HTTPOnly:   true,            // prevent JavaScript access
        Secure:     true,            // only send over HTTPS
        MaxAge:     24 * time.Hour,  // server-side expiry
    })
```

### Session Operations

```go
// Get session (auto-creates if empty)
session, err := seshcookie.GetSession[*YourProtoType](ctx)

// Modify and save session
session.Field = value
err := seshcookie.SetSession(ctx, session)

// Clear session (deletes cookie)
err := seshcookie.ClearSession[*YourProtoType](ctx)
```

## Security Considerations

1. **Use Strong Keys**: Generate encryption keys from a cryptographically secure source (e.g., `/dev/urandom`)
2. **Enable HTTPS**: Always set `Secure: true` in production
3. **Set HTTPOnly**: Prevents XSS attacks from stealing session cookies
4. **Configure MaxAge**: Sessions expire server-side after this duration
5. **CSRF Protection**: Implement CSRF tokens for state-changing operations

## How It Works

1. **Envelope Pattern**: Your protobuf message is wrapped in a `SessionEnvelope` that includes:
   - `issued_at`: Timestamp when session was created
   - `payload`: Your protobuf message as a `google.protobuf.Any`

2. **Encryption**: The envelope is encrypted using AES-GCM with a unique nonce per cookie

3. **Expiry**: On each request, the server validates that `issued_at + MaxAge > now`

4. **Change Detection**: Sessions are only re-written to cookies when `SetSession` is called, and the session hash changes

## Migration from v2.x

Version 3.0 updates the module path to comply with Go's semantic import versioning requirements:

**Migration steps:**

1. Update your import statements from `github.com/bpowers/seshcookie` to `github.com/bpowers/seshcookie/v3`
2. Run `go mod tidy` to update your dependencies

That's it! The API remains the same as v2.x.

## Migration from v1.x

Version 2.0/3.0 is a breaking change from v1.x. Key differences:

| v1.x | v2.x/v3.x |
|------|------|
| `Session map[string]interface{}` | Strongly-typed protobuf messages |
| `GetSession(ctx) Session` | `GetSession[T](ctx) (T, error)` |
| Direct map modification | Explicit `SetSession(ctx, session)` |
| `NewHandler(h, key, cfg) *Handler` | `NewHandler[T](h, key, cfg) (*Handler[T], error)` |
| No expiry enforcement | Server-side expiry via `MaxAge` |
| GOB encoding | Protobuf encoding |

**Migration steps:**

1. Update imports to `github.com/bpowers/seshcookie/v3`
2. Define your session data as a protobuf message
3. Generate Go code with `protoc`
4. Update handler creation to use generic type parameter
5. Change session access to use `GetSession[T]` and `SetSession`
6. Add error handling for `NewHandler` and session operations

## Example

A complete authentication example is available in the `example/` directory, demonstrating:
- Login/logout flows
- Protobuf session messages
- Role-based access control
- Proper error handling

## Performance

- **Minimal overhead**: Only re-encodes cookies when session changes
- **No server storage**: Truly stateless, scales horizontally
- **Efficient encoding**: Protobuf is compact and fast

## License

seshcookie is offered under the MIT license, see LICENSE for details.
