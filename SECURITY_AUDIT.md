# Security Audit Report: seshcookie

**Audit Date:** 2025-10-30
**Auditor:** Claude (AI Security Analysis)
**Project:** github.com/bpowers/seshcookie
**Version:** 2.0 (protobuf + generics)

---

## Executive Summary

This security audit evaluates the seshcookie library, a Go package for cookie-based session management with encryption and authentication. The library implements AES-GCM encryption with Argon2id key derivation and Protocol Buffers serialization.

**Overall Security Posture:** MODERATE with some HIGH severity concerns

**Key Findings:**
- 2 Critical issues
- 5 High severity issues
- 5 Medium severity issues
- 3 Low severity issues
- 9 Positive security practices

---

## Scope

The audit covers:
- Cryptographic implementation (key derivation, encryption, nonce handling)
- Session management (expiry, storage, lifecycle)
- Cookie security (flags, handling, validation)
- Common web vulnerabilities (timing attacks, injection, XSS, CSRF)
- Dependency security
- Example code security practices

---

## Critical Issues

### 1. Deterministic Salt in Key Derivation (CRITICAL)

**Location:** `seshcookie.go:75-80`

**Issue:**
```go
// Derive a deterministic salt from the key
saltHash := sha256.New()
saltHash.Write([]byte("seshcookie-v2-salt"))
saltHash.Write([]byte(key))
salt := saltHash.Sum(nil)[:16] // 16-byte salt
```

The salt for Argon2id is derived deterministically from the key itself using `SHA256("seshcookie-v2-salt" || key)`. This defeats a core security benefit of salting - protecting against rainbow table attacks when keys are reused across different instances or if multiple services use the same key.

**Impact:**
- If the same key is used in multiple deployments, they will have identical derived keys
- Reduces effectiveness of Argon2id against precomputed attacks
- No salt independence as recommended by cryptographic best practices

**Recommendation:**
While the library is designed to be stateless, consider:
1. Requiring users to provide both a key AND a salt during initialization
2. Document that the key should be unique per deployment/environment
3. Add a warning that using the same key across multiple services reduces security
4. Consider using environment-specific context (hostname, deployment ID) in salt derivation

**Severity Justification:**
While the comment acknowledges this design decision, it violates cryptographic best practices. The "stateless design" benefit doesn't outweigh the security reduction, especially since storing a salt alongside the key is minimal overhead.

---

### 2. Weak Passwords in Example Code (CRITICAL)

**Location:** `example/auth.go:17-22`

**Issue:**
```go
var userDb = map[string]string{
    "user1": "love",
    "user2": "sex",
    "user3": "secret",
    "user4": "god",
}
```

The example authentication code uses extremely weak passwords without any warnings, password hashing, or guidance on proper password handling.

**Impact:**
- Developers copying this example code to production will create vulnerable applications
- No demonstration of proper password hashing (bcrypt, Argon2id)
- Passwords stored in plaintext in source code
- Sets a dangerous precedent for users of the library

**Recommendation:**
1. Replace with properly hashed passwords using bcrypt or Argon2id
2. Add prominent security warnings in comments
3. Include example of password validation and hashing
4. Add to README: "⚠️ WARNING: Example code uses weak passwords for demonstration only. NEVER use in production."

**Example Fix:**
```go
// WARNING: For demonstration only! In production:
// 1. Use bcrypt or Argon2id to hash passwords
// 2. Never store passwords in source code
// 3. Implement proper password complexity requirements
var userDb = map[string]string{
    "user1": "$2a$10$...", // bcrypt hash
    // ...
}
```

---

## High Severity Issues

### 3. Plaintext Password Comparison (HIGH)

**Location:** `example/auth.go:65`

**Issue:**
```go
if !exists || req.Form.Get("pass") != expectedPass {
```

Direct string comparison for passwords is vulnerable to timing attacks, where an attacker can determine correct password characters by measuring response times.

**Impact:**
- Timing side-channel attack vector
- Example code teaches insecure patterns

**Recommendation:**
Use `crypto/subtle.ConstantTimeCompare()` or better yet, use proper password hashing with bcrypt:

```go
import "golang.org/x/crypto/bcrypt"

err := bcrypt.CompareHashAndPassword([]byte(expectedPass), []byte(req.Form.Get("pass")))
if err != nil {
    // Authentication failed
}
```

---

### 4. No Rate Limiting (HIGH)

**Location:** Library-wide

**Issue:**
No built-in protection against brute-force attacks on session cookies or authentication endpoints.

**Impact:**
- Attackers can attempt unlimited session cookie guessing
- No protection against credential stuffing attacks
- DoS potential through repeated authentication attempts

**Recommendation:**
1. Add middleware example demonstrating rate limiting
2. Document recommended rate limiting practices
3. Consider adding optional rate limiting to the library itself
4. Suggest using packages like `golang.org/x/time/rate`

---

### 5. Error Information Leakage (HIGH)

**Location:** `seshcookie.go:407`

**Issue:**
```go
if err != nil {
    log.Printf("encodeCookie: %s\n", err)
    return
}
```

Errors during cookie encoding are logged, which could leak sensitive information about encryption failures, key issues, or session data structure.

**Impact:**
- Information disclosure through logs
- Could aid attackers in understanding system internals
- Logs may contain sensitive session data fragments

**Recommendation:**
1. Use structured logging with sanitized error messages
2. Log errors at debug level only, not to stdout/stderr
3. Never log actual session data or keys
4. Provide callback for error handling instead of direct logging

```go
// Add to Config struct
type Config struct {
    // ...
    ErrorHandler func(error) // Allow custom error handling
}
```

---

### 6. No Session Replay Protection (HIGH)

**Location:** General architecture

**Issue:**
If an attacker captures a valid session cookie, they can replay it indefinitely until expiry (up to 24 hours by default). There's no nonce, request counter, or anti-replay mechanism.

**Impact:**
- Session hijacking if cookie is intercepted (despite HTTPS)
- No defense-in-depth if TLS is compromised
- Long session lifetimes increase attack window

**Recommendation:**
1. Implement shorter default MaxAge (e.g., 1 hour)
2. Add optional "sliding window" expiry that updates on each request
3. Consider adding request counter to detect replay
4. Document that HTTPS is absolutely required
5. Add example of implementing logout-on-password-change

**Example enhancement:**
```go
type SessionEnvelope {
    IssuedAt *timestamppb.Timestamp
    LastUsed *timestamppb.Timestamp  // Add this
    RequestCount uint64                // Add this for replay detection
    // ...
}
```

---

### 7. Session Fixation Vulnerability (HIGH)

**Location:** `example/auth.go:74-77`

**Issue:**
When a user logs in, the session isn't regenerated - the same session continues with just the username added:

```go
session.Username = user
session.LoginTime = time.Now().Unix()
if err := seshcookie.SetSession(req.Context(), session); err != nil {
```

**Impact:**
- Session fixation attacks: attacker can set a session cookie, victim logs in with that cookie, attacker now has authenticated session
- Violates OWASP session management guidelines

**Recommendation:**
Provide a `RegenerateSession()` function or document that developers should clear and create new sessions on authentication state changes:

```go
// Add to seshcookie package
func RegenerateSession[T proto.Message](ctx context.Context, newSession T) error {
    // Clear old session, create new with fresh timestamp
}
```

Usage in auth:
```go
// On login, create fresh session
if err := seshcookie.ClearSession[*UserSession](req.Context()); err != nil {
    // handle error
}
newSession := &UserSession{
    Username: user,
    LoginTime: time.Now().Unix(),
}
if err := seshcookie.SetSession(req.Context(), newSession); err != nil {
    // handle error
}
```

---

## Medium Severity Issues

### 8. Missing SameSite Cookie Attribute (MEDIUM)

**Location:** `seshcookie.go:133-139`, `seshcookie.go:416-423`

**Issue:**
The `Config` struct and cookie creation don't support the `SameSite` attribute, which is critical for CSRF protection.

**Impact:**
- Cookies can be sent with cross-site requests
- Increases CSRF attack surface
- Modern browsers apply `SameSite=Lax` by default, but explicit control is better

**Recommendation:**
Add `SameSite` to the Config struct:

```go
type Config struct {
    CookieName string
    CookiePath string
    HTTPOnly   bool
    Secure     bool
    SameSite   http.SameSite  // Add this
    MaxAge     time.Duration
}

// In DefaultConfig
DefaultConfig = &Config{
    // ...
    SameSite: http.SameSiteStrictMode,  // Or SameSiteLaxMode
}
```

Apply in cookie creation:
```go
cookie.SameSite = s.h.Config.SameSite
```

---

### 9. No Cookie Size Validation (MEDIUM)

**Location:** `seshcookie.go:283-320`

**Issue:**
No validation that the encoded cookie doesn't exceed browser limits (typically 4KB per cookie, 4096 bytes).

**Impact:**
- Cookies may be silently truncated or rejected by browsers
- Application failures that are difficult to debug
- Potential security issues if truncation occurs during encryption/encoding

**Recommendation:**
Add size validation after encoding:

```go
const maxCookieSize = 4096

func encodeCookie[T proto.Message](...) (string, []byte, error) {
    // ... existing encoding ...
    encoded := base64.StdEncoding.EncodeToString(ciphertext)

    if len(encoded) > maxCookieSize {
        return "", nil, fmt.Errorf("session cookie too large: %d bytes (max %d)",
            len(encoded), maxCookieSize)
    }

    return encoded, protoHash.Sum(nil), nil
}
```

---

### 10. No Domain Attribute Support (MEDIUM)

**Location:** `seshcookie.go:133-139`

**Issue:**
Config doesn't support setting the cookie `Domain` attribute, which controls which domains/subdomains receive the cookie.

**Impact:**
- Cookies sent to all subdomains by default
- Cannot restrict cookies to specific subdomains
- Increased attack surface if any subdomain is compromised

**Recommendation:**
```go
type Config struct {
    CookieName string
    CookiePath string
    Domain     string      // Add this
    HTTPOnly   bool
    Secure     bool
    MaxAge     time.Duration
}
```

---

### 11. Race Condition in WriteHeader (MEDIUM)

**Location:** `seshcookie.go:426-436`

**Issue:**
```go
// Note: There is a potential race condition if WriteHeader is called
// from multiple goroutines. This is also true of the underlying
// http.ResponseWriter. Using atomic operations provides some protection
// but doesn't fully eliminate the race.
if atomic.AddInt32(&s.wroteHeader, 1) == 1 {
    s.writeCookie()
}
```

Comment acknowledges a race condition that isn't fully resolved.

**Impact:**
- If `WriteHeader` is called from multiple goroutines, cookies might be written multiple times or not at all
- Undefined behavior in concurrent scenarios
- Could lead to session inconsistencies

**Recommendation:**
1. Add mutex protection for header writing
2. Document that ServeHTTP should not be called concurrently for the same request
3. Add warning in README about thread safety

```go
type responseWriter[T proto.Message] struct {
    http.ResponseWriter
    h   *Handler[T]
    req *http.Request
    mu  sync.Mutex  // Add mutex
    wroteHeader bool
}

func (s *responseWriter[T]) WriteHeader(code int) {
    s.mu.Lock()
    defer s.mu.Unlock()

    if !s.wroteHeader {
        s.wroteHeader = true
        s.writeCookie()
    }
    s.ResponseWriter.WriteHeader(code)
}
```

---

### 12. Silent Error Handling in Cookie Decoding (MEDIUM)

**Location:** `seshcookie.go:452-459`

**Issue:**
```go
session, protoHash, issuedAt, err := decodeCookie[T](cookie.Value, h.encKey, h.Config.MaxAge)
if err != nil {
    // Invalid cookie or expired session - treat as no session
    // Log for debugging but don't expose to user
    if errors.Is(err, ErrSessionExpired) {
        // Silently ignore expired sessions
    }
    return zero, nil, nil
}
```

Errors during cookie decoding are silently ignored, making debugging difficult and potentially hiding attacks.

**Impact:**
- Difficult to detect and debug session issues in production
- Cannot distinguish between attacks and legitimate errors
- No visibility into cookie tampering attempts

**Recommendation:**
Add optional error callback to Config:

```go
type Config struct {
    // ...
    OnDecodeError func(error)  // Optional callback for decode errors
}

// Usage in getCookieSession
if err != nil {
    if h.Config.OnDecodeError != nil {
        h.Config.OnDecodeError(err)
    }
    return zero, nil, nil
}
```

---

## Low Severity Issues

### 13. AES-128 vs AES-256 (LOW)

**Location:** `seshcookie.go:33-34`

**Issue:**
```go
const (
    // we want 16 byte blocks, for AES-128
    blockSize    = 16
```

Uses AES-128 instead of AES-256. While AES-128 is secure, AES-256 provides higher security margins.

**Impact:**
- Slightly reduced security margin
- AES-128 still secure against known attacks

**Recommendation:**
Consider offering AES-256 as an option or default:

```go
const (
    blockSizeAES128 = 16
    blockSizeAES256 = 32
)

type Config struct {
    // ...
    KeySize int  // 16 for AES-128, 32 for AES-256
}
```

---

### 14. No Key Rotation Mechanism (LOW)

**Location:** Library-wide

**Issue:**
No mechanism for rotating encryption keys without invalidating all existing sessions.

**Impact:**
- Cannot rotate keys in response to compromise
- Long-term key use increases attack surface
- No graceful migration path

**Recommendation:**
1. Support multiple keys with key versioning
2. Add key ID to encrypted payload
3. Allow gradual migration between keys

```go
type Handler[T proto.Message] struct {
    // ...
    encKeys [][]byte  // Support multiple keys
    keyVersion int
}
```

---

### 15. Hijack Not Supported (LOW)

**Location:** `seshcookie.go:438-441`

**Issue:**
```go
func (s *responseWriter[T]) Hijack() (net.Conn, *bufio.ReadWriter, error) {
    // TODO: support hijacking with atomic flags
    return nil, nil, fmt.Errorf("seshcookie doesn't support hijacking")
}
```

WebSocket and HTTP/2 hijacking not supported.

**Impact:**
- Cannot use with WebSockets
- Limits use cases

**Recommendation:**
Either implement hijacking support or document this limitation clearly in README.

---

## Positive Security Practices

### ✅ Strong Cryptography
1. **AES-GCM for Authenticated Encryption** (`seshcookie.go:312-319`): Proper use of AES-GCM provides both confidentiality and authenticity.

2. **Argon2id for Key Derivation** (`seshcookie.go:91-98`): Uses memory-hard KDF with OWASP-recommended parameters (3 iterations, 16MB memory, 4 threads).

3. **Secure Random Nonce Generation** (`seshcookie.go:307-310`): Proper use of `crypto/rand` for nonce generation:
```go
nonce := make([]byte, gcmNonceSize)
if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
    return "", nil, fmt.Errorf("io.ReadFull(rand.Reader): %w", err)
}
```

### ✅ Session Management
4. **Server-Side Expiry Validation** (`seshcookie.go:255-261`): Sessions expire based on server time, not client-controllable cookie expiry.

5. **HTTPOnly and Secure Flags** (`seshcookie.go:43-48`): Enabled by default in `DefaultConfig`.

### ✅ Code Quality
6. **Type-Safe Sessions with Generics** (`seshcookie.go:144-148`): Compile-time type safety prevents session type confusion.

7. **Change Detection** (`seshcookie.go:412-414`): Cookies only updated when session actually changes, reducing overhead and exposure.

8. **Efficient Serialization** (protobuf): Compact and fast encoding.

9. **Comprehensive Test Coverage** (`seshcookie_test.go`): Includes security-focused tests for:
   - Key derivation determinism
   - Cookie tampering detection
   - Session expiry validation
   - Empty key rejection

---

## Dependency Analysis

**Dependencies:**
- `golang.org/x/crypto v0.43.0` (2025-10-08) - ✅ Recent, maintained
- `google.golang.org/protobuf v1.36.10` (2025-10-02) - ✅ Recent, maintained
- `golang.org/x/sys v0.37.0` - ✅ Recent

**Assessment:**
All dependencies are recent and actively maintained. No known critical vulnerabilities at audit time.

**Recommendation:**
- Implement automated dependency scanning (Dependabot, Snyk)
- Regularly update dependencies
- Monitor security advisories

---

## Attack Scenarios

### Scenario 1: Session Hijacking via Cookie Theft
**Likelihood:** Medium
**Impact:** High
**Mitigation:** Require HTTPS (Secure flag), implement shorter MaxAge, add request fingerprinting

### Scenario 2: Session Fixation
**Likelihood:** High (if example code is used)
**Impact:** High
**Mitigation:** Regenerate session on authentication (Issue #7)

### Scenario 3: Cookie Tampering
**Likelihood:** Low
**Impact:** None
**Current Protection:** AES-GCM provides authentication ✅

### Scenario 4: Brute Force Cookie Guessing
**Likelihood:** Low (cryptographically infeasible)
**Impact:** High if successful
**Current Protection:** AES-GCM with 96-bit nonce, sufficient entropy ✅

### Scenario 5: Key Compromise
**Likelihood:** Depends on key storage
**Impact:** Critical
**Mitigation:** Need key rotation mechanism (Issue #14), proper key storage guidance

---

## Recommendations Summary

### Immediate Actions (Critical/High)
1. ✅ Fix deterministic salt - require separate salt or add strong warnings
2. ✅ Fix example code weak passwords - use bcrypt and add warnings
3. ✅ Add constant-time password comparison to example
4. ✅ Remove or sanitize error logging
5. ✅ Add session regeneration function
6. ✅ Document rate limiting requirements
7. ✅ Reduce default MaxAge to 1 hour

### Short-term Improvements (Medium)
8. ✅ Add SameSite cookie attribute support
9. ✅ Implement cookie size validation
10. ✅ Add Domain attribute support
11. ✅ Fix race condition in WriteHeader
12. ✅ Add error callback mechanism

### Long-term Enhancements (Low)
13. ✅ Consider AES-256 support
14. ✅ Implement key rotation
15. ✅ Support hijacking or document limitation

### Security Best Practices Documentation
16. ✅ Add security section to README
17. ✅ Document that HTTPS is REQUIRED
18. ✅ Provide CSRF protection guidance
19. ✅ Add key generation examples
20. ✅ Document rate limiting recommendations

---

## Security Best Practices for Users

Add this section to README:

### 🔒 Security Recommendations

1. **Always use HTTPS** - Set `Secure: true` in production
2. **Generate strong keys** - Use `crypto/rand`, minimum 32 bytes
3. **Never commit keys** - Use environment variables or secret management
4. **Implement rate limiting** - Protect authentication endpoints
5. **Use short MaxAge** - Default 1 hour, maximum 24 hours
6. **Implement CSRF protection** - Use tokens for state-changing operations
7. **Regenerate sessions** - On login, logout, privilege changes
8. **Monitor for attacks** - Log authentication failures, implement alerting
9. **Keep dependencies updated** - Regularly update to patch vulnerabilities
10. **Hash passwords properly** - Use bcrypt or Argon2id for password storage

---

## Conclusion

The seshcookie library demonstrates solid cryptographic fundamentals with AES-GCM and Argon2id, but has several security concerns that should be addressed:

**Critical concerns:**
- Deterministic salt reduces KDF effectiveness
- Example code teaches dangerous patterns

**High concerns:**
- No session replay protection
- Session fixation vulnerability in example
- Missing rate limiting
- Error information leakage

**Overall assessment:** The library is suitable for production use **only if**:
1. Users implement their own rate limiting
2. Users properly regenerate sessions on auth changes
3. Example code is never used in production without significant hardening
4. Keys are properly generated and unique per deployment
5. HTTPS is enforced

**Recommended actions before production deployment:**
1. Fix critical issues #1 and #2 immediately
2. Add prominent security warnings to README and example code
3. Provide secure example implementation
4. Consider adding built-in protections for high severity issues

The maintainer should prioritize addressing the critical and high severity issues to make this library safer for general use.

---

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [AES-GCM NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Cookie Specifications RFC 6265](https://www.rfc-editor.org/rfc/rfc6265)

---

**Audit Complete**
