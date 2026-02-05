// Copyright 2025 Bobby Powers. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

/*
Package seshcookie enables you to associate session-state with HTTP
requests while keeping your server stateless. Because session-state
is transferred as part of the HTTP request (in a cookie), state can be
seamlessly maintained between server restarts or load balancing. It's
inspired by Beaker (http://pypi.python.org/pypi/Beaker), which
provides a similar service for Python webapps. The cookies are
authenticated and encrypted (using AES-GCM) with a key derived using
Argon2id from a string provided to the NewHandler function. This makes
seshcookie reliable and secure: session contents are opaque to users
and not able to be manipulated or forged by third parties.

# Version 3.0 - Go Module v3

Version 3.0 updates the module path to follow Go's semantic import versioning (v3).
Version 2.0/3.0 introduces a new API based on Protocol Buffers and Go generics.
Session data is now strongly-typed using protobuf messages, providing
better type safety and schema evolution. The library uses an envelope
pattern where metadata (like issue time) is stored separately from the
user's session payload.

Sessions have server-side expiry enforcement based on issue time, preventing
cookie manipulation to extend session lifetime.

# Basic Usage

Define your session data as a protobuf message:

	syntax = "proto3";
	package myapp;

	message UserSession {
	  string username = 1;
	  int64 login_time = 2;
	  repeated string roles = 3;
	}

Then use seshcookie with Go generics:

	package main

	import (
		"net/http"
		"log"
		"time"

		"github.com/bpowers/seshcookie/v3"
		"myapp/pb"  // your generated protobuf package
	)

	type VisitedHandler struct{}

	func (h *VisitedHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			return
		}

		// GetSession returns a valid protobuf message, never nil
		session, err := seshcookie.GetSession[*pb.UserSession](req.Context())
		if err != nil {
			http.Error(rw, "Internal error", 500)
			return
		}

		// Modify the session
		session.Username = "alice"
		session.LoginTime = time.Now().Unix()

		// Explicitly save changes
		if err := seshcookie.SetSession(req.Context(), session); err != nil {
			http.Error(rw, "Internal error", 500)
			return
		}

		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(200)
		rw.Write([]byte("Welcome " + session.Username))
	}

	func main() {
		key := "session key, preferably a sequence of data from /dev/urandom"

		// NewHandler now requires a type parameter
		handler, err := seshcookie.NewHandler[*pb.UserSession](
			&VisitedHandler{},
			key,
			&seshcookie.Config{
				HTTPOnly: true,
				Secure: true,
				MaxAge: 24 * time.Hour,  // Server-side expiry
			})

		if err != nil {
			log.Fatalf("NewHandler: %s", err)
		}

		if err := http.ListenAndServe(":8080", handler); err != nil {
			log.Fatalf("ListenAndServe: %s", err)
		}
	}

# Session Management

The API provides three main functions:

  - GetSession[T](ctx) - Retrieves session from context, auto-creates if empty
  - SetSession[T](ctx, session) - Marks session as changed for writing to cookie
  - ClearSession[T](ctx) - Clears session, causing cookie deletion

Sessions are only written to cookies when SetSession is called, preventing
unnecessary cookie updates and preserving the original issue timestamp.

# Security Features

  - Argon2id key derivation (memory-hard, GPU-resistant)
  - AES-GCM authenticated encryption
  - Server-side session expiry based on issue time
  - HTTPOnly and Secure cookie flags
  - Automatic nonce generation for each cookie
  - Change detection to minimize cookie writes
  - Type-safe session data via protobuf

# Migration from v1.x

Version 2.0 is a breaking change that replaces the map[string]interface{}
session type with strongly-typed protobuf messages. The API surface has
changed significantly:

v1.x:

	session := seshcookie.GetSession(ctx)
	session["count"] = 1

v2.x:

	session, err := seshcookie.GetSession[*MyProto](ctx)
	session.Count = 1
	seshcookie.SetSession(ctx, session)

# Migration from seshcookie-js

If you are migrating from the JavaScript/TypeScript seshcookie package,
use [WithMigration] to transparently convert JS cookies to Go format.
The JS and Go implementations use different key derivation and wire
formats, so migration requires providing the JS key and a conversion
function.

	convert := func(jsonData []byte) (*pb.MySession, error) {
	    var raw map[string]any
	    if err := json.Unmarshal(jsonData, &raw); err != nil {
	        return nil, err
	    }
	    return &pb.MySession{
	        User: raw["user"].(string),
	    }, nil
	}

	handler, err := seshcookie.NewHandler[*pb.MySession](
	    inner, goKey, nil,
	    seshcookie.WithMigration[*pb.MySession](jsKey, convert),
	)

On the first request with a JS cookie, the handler decrypts it,
converts the JSON to protobuf via the provided function, and writes
back a Go-format cookie (prefixed with "sc1_"). Subsequent requests
use the Go cookie transparently. The JS key can differ from the Go key.
*/
package seshcookie
