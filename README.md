seshcookie - cookie-based sessions for Go
=========================================

[![Build Status](https://travis-ci.org/bpowers/seshcookie.svg?branch=master)](https://travis-ci.org/bpowers/seshcookie)
[![GoDoc](https://godoc.org/github.com/bpowers/seshcookie/v3?status.svg)](https://godoc.org/github.com/bpowers/seshcookie/v3)
[![cover.run](https://cover.run/go/github.com/bpowers/seshcookie/v3.svg?style=flat&tag=golang-1.10)](https://cover.run/go?tag=golang-1.10&repo=github.com%2Fbpowers%2Fseshcookie)
[![Go Report Card](https://goreportcard.com/badge/github.com/bpowers/seshcookie/v3)](https://goreportcard.com/report/github.com/bpowers/seshcookie/v3)

> Stateless, encrypted, type-safe session cookies for Go's `net/http` stack.

## Version 3.0 - Go Module v3

**⚠️ Breaking Change:** Version 3.0 updates the module path to follow Go's semantic import versioning. Import the package as `github.com/bpowers/seshcookie/v3`. See [Migration](#migration-from-v2x) below. The API matches v2.x (generics + protobuf sessions), so only the module path changes when upgrading from v2.

## What is seshcookie?

seshcookie keeps per-user session data inside a single AES-GCM encrypted cookie. Each request gets a strongly-typed protobuf message via `context.Context`, so handlers can mutate session state without touching shared storage. Keys are derived using Argon2id; provide a high-entropy secret, and seshcookie handles encryption, authentication, expiry, and change detection for you.

## When should you use it?

- You want "sticky" session behavior for horizontally scaled/stateless Go services or serverless functions.
- Your session payload is small (fits comfortably inside a few kilobytes) and naturally modeled as a protobuf message.
- You would rather avoid provisioning Redis or another backing store just to hold session blobs.

If you need to centrally revoke sessions, store large payloads, or share state with non-HTTP clients, a server-side store may be a better fit.

## Key Features

- **Type-Safe Sessions**: Protocol Buffers + Go generics provide compile-time schemas.
- **Secure by Default**: Argon2id key derivation, AES-GCM encryption, Secure + HTTPOnly cookies.
- **Server-Side Expiry**: Sessions expire based on the issuance timestamp, not browser-controlled metadata.
- **Stateless Scalability**: No shared storage or sticky routing; any replica can serve any request.
- **Change Detection**: Cookies are only rewritten when session data actually changes via `SetSession`.
- **Flexible Integration**: Use either a pre-wrapped `http.Handler` or a middleware constructor.

## Installation

```bash
go get github.com/bpowers/seshcookie/v3
```

## Quick Start

### 1. Define your session schema

Create a `.proto` file:

```protobuf
syntax = "proto3";
package myapp;
option go_package = "myapp/pb";

message UserSession {
  string username = 1;
  int32 visit_count = 2;
  repeated string roles = 3;
}
```

Generate Go code:

```bash
protoc --go_out=. --go_opt=paths=source_relative session.proto
```

### 2. Wrap your handlers

Wrap your top-level handler (or router) with seshcookie. Provide a high-entropy key that is shared by every replica of your service.

```go
key := os.Getenv("SESHCOOKIE_KEY") // base64 string holding 32 random bytes

handler, err := seshcookie.NewHandler[*pb.UserSession](
    &VisitedHandler{},
    key,
    &seshcookie.Config{
        HTTPOnly: true,
        Secure:   true,
        MaxAge:   24 * time.Hour,
    },
)
if err != nil {
    log.Fatalf("NewHandler: %v", err)
}

log.Fatal(http.ListenAndServe(":8080", handler))
```

Prefer middleware-style wiring when you already have a router (e.g., `http.ServeMux`, chi, gorilla/mux):

```go
mw, err := seshcookie.NewMiddleware[*pb.UserSession](key, nil)
if err != nil {
    log.Fatal(err)
}

router := http.NewServeMux()
router.HandleFunc("/", appHandler)

log.Fatal(http.ListenAndServe(":8080", mw(router)))
```

### 3. Read, mutate, and persist sessions

Within any wrapped handler, call the helpers on the request context. The session is lazily created on first access and only written back when `SetSession` (or `ClearSession`) is invoked.

```go
session, err := seshcookie.GetSession[*pb.UserSession](req.Context())
if err != nil {
    http.Error(rw, "session unavailable", http.StatusInternalServerError)
    return
}

session.VisitCount++
if err := seshcookie.SetSession(req.Context(), session); err != nil {
    http.Error(rw, "could not save session", http.StatusInternalServerError)
    return
}

if shouldLogout(req) {
    _ = seshcookie.ClearSession[*pb.UserSession](req.Context()) // drops cookie at end of request
    http.Redirect(rw, req, "/login", http.StatusSeeOther)
    return
}
```

## API Reference

### Handler or middleware constructors

- `NewHandler[T proto.Message](handler http.Handler, key string, cfg *Config) (*Handler[T], error)` wraps an existing handler.
- `NewMiddleware[T proto.Message](key string, cfg *Config) (func(http.Handler) http.Handler, error)` returns a middleware constructor you can apply to routers or existing middleware chains.

Both helpers derive the AES key from the provided string using Argon2id. Pass `nil` for `cfg` to start from `DefaultConfig` (Secure + HTTPOnly + 24h expiry).

### Session helpers

```go
session, err := seshcookie.GetSession[*YourProto](ctx) // returns zero-value message if cookie missing
err = seshcookie.SetSession(ctx, session)             // mark as changed so cookie rewrites on response
err = seshcookie.ClearSession[*YourProto](ctx)        // delete cookie, preserving statelessness
```

`GetSession` returns `ErrNoSession` if used outside a seshcookie-wrapped handler. Sessions are buffered in context and only marshaled back into cookies after `SetSession` or `ClearSession` is called, so read-only requests incur no cookie writes.

### Config reference

- `CookieName` (default `"session"`): cookie name.
- `CookiePath` (default `/`): path scope.
- `HTTPOnly` (default `true`): prevents JavaScript access.
- `Secure` (default `true`): only send over HTTPS; disable only for local development.
- `MaxAge` (default `24 * time.Hour`): server-side TTL based on issuance time.

## Best Practices

- Generate the key from `crypto/rand` (32+ bytes), store it outside source control, and keep it consistent across replicas so cookies remain decryptable everywhere.
- Keep sessions compact (IDs, roles, tokens) rather than entire user profiles; browser cookies cap around 4 KB.
- Leave `Secure` and `HTTPOnly` enabled, and terminate TLS before requests hit seshcookie. Toggle `Secure` off only for local HTTP development.
- Pick a `MaxAge` that matches your authentication policy, and rotate the key when you need to invalidate all sessions at once.
- Call `SetSession` only when data actually changes; combine with domain logic (e.g., bump visit counts, persist auth claims) to avoid needless cookie churn.
- Use `ClearSession` on logout/revocation flows and pair seshcookie with CSRF protection for state-changing requests.

## Security Model

1. **Argon2id-derived keys**: Your secret string is stretched with Argon2id into an AES-128 key (salt deterministically derived from the secret), providing defense-in-depth even if the secret has uneven entropy.
2. **AES-GCM authenticated encryption**: Cookies cannot be forged or modified without the key; each write uses a fresh nonce.
3. **HTTPOnly + Secure by default**: Protects against XSS-based theft and plaintext transport.
4. **Server-side expiry**: The issued-at timestamp plus `MaxAge` determines validity, so clients cannot prolong sessions.
5. **Change detection**: Sessions are only re-encrypted when data changes, keeping cookies stable and reducing risk from replay of stale values.

You still need standard web security measures (TLS, CSRF tokens, input validation) around your application logic.

## How It Works

1. **Key derivation**: The provided secret is transformed into an AES key via Argon2id with deterministic salt.
2. **Envelope pattern**: Your protobuf session is wrapped in an internal `SessionEnvelope` carrying the payload and `issued_at` metadata.
3. **Encryption**: The envelope is AES-GCM encrypted and base64-encoded into the cookie.
4. **Expiry enforcement**: On each request, seshcookie checks `issued_at + MaxAge` before exposing the session to your handler.
5. **Write minimization**: Cookies are rewritten only after `SetSession` or `ClearSession`, allowing long-lived sessions with stable issuance timestamps.

## Migration from v2.x

Version 3.0 updates the module path to comply with Go's semantic import versioning requirements:

**Migration steps:**

1. Update your import statements from `github.com/bpowers/seshcookie` to `github.com/bpowers/seshcookie/v3`.
2. Run `go mod tidy` to update your dependencies.

That's it! The API remains the same as v2.x.

## Migration from v1.x

Version 2.0/3.0 is a breaking change from v1.x. Key differences:

| v1.x | v2.x/v3.x |
|------|-----------|
| `Session map[string]interface{}` | Strongly-typed protobuf messages |
| `GetSession(ctx) Session` | `GetSession[T](ctx) (T, error)` |
| Direct map modification | Explicit `SetSession(ctx, session)` |
| `NewHandler(h, key, cfg) *Handler` | `NewHandler[T](h, key, cfg) (*Handler[T], error)` |
| No expiry enforcement | Server-side expiry via `MaxAge` |
| GOB encoding | Protobuf encoding |

**Migration steps:**

1. Update imports to `github.com/bpowers/seshcookie/v3`.
2. Define your session data as a protobuf message.
3. Generate Go code with `protoc`.
4. Update handler creation to use the generic type parameter.
5. Change session access to use `GetSession[T]`, `SetSession`, and `ClearSession`.
6. Add error handling for `NewHandler` and session operations.

## Example

A complete authentication example is available in the `example/` directory, demonstrating:
- Login/logout flows
- Protobuf session messages
- Role-based access control
- Proper error handling

## Performance

- **Minimal overhead**: Only re-encodes cookies when session changes.
- **No server storage**: Truly stateless, scales horizontally.
- **Efficient encoding**: Protobuf is compact and fast.

## License

seshcookie is offered under the MIT license; see `LICENSE` for details.
