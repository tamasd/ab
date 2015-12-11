// Copyright 2015 Tamás Demeter-Haludka
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ab

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// This middleware enforces the correct X-CSRF-Token header on all POST, PUT, DELETE, PATCH requests.
//
// To obtain a token, use CSRFTokenHandler on a path.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
			s := GetSession(r)
			token := s["_csrf"]

			userToken := r.Header.Get("X-CSRF-Token")

			if userToken == "" || userToken != token {
				Fail(r, http.StatusForbidden, errors.New("CSRF token validation failed"))
			}
		}

		next.ServeHTTP(w, r)
	})
}

// This middleware checks the CSRF token in the urlParam URL parameter.
//
// This is useful if you want CSRF protection in a GET request. For example, this middleware is used on the auth service's login/logout endpoints.
// Adding this to the server is discouraged. The middlware should be used only on the individual handlers.
func CSRFGetMiddleware(urlParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := GetSession(r)
			token := s["_csrf"]

			userToken := r.URL.Query().Get(urlParam)

			if userToken == "" || userToken != token {
				Fail(r, http.StatusForbidden, errors.New("CSRF token validation failed"))
			}

			next.ServeHTTP(w, r)
		})
	}
}

// This middleware creates a cookie with the CSRF token.
//
// The cookie will be named prefix+"_CSRF".
func CSRFCookieMiddleware(prefix string, expiresAfter time.Duration, cookieURL *url.URL) func(http.Handler) http.Handler {
	if cookieURL == nil {
		cookieURL = &url.URL{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := GetCSRFToken(r)
			http.SetCookie(w, &http.Cookie{
				Name:     prefix + "_CSRF",
				Value:    token,
				HttpOnly: false,
				Path:     cookieURL.Path,
				Domain:   cookieURL.Host,
				Secure:   cookieURL.Scheme == "https",
				Expires:  time.Now().Add(expiresAfter),
			})
			next.ServeHTTP(w, r)
		})
	}
}

// Returns the CSRF token for the current session.
//
// If the token is not exists, the function generates one and places it inside the session.
func GetCSRFToken(r *http.Request) string {
	s := GetSession(r)
	token := s["_csrf"]

	if token == "" {
		rawToken := make([]byte, 32)
		if _, err := rand.Read(rawToken); err != nil {
			panic(err)
		}
		token = hex.EncodeToString(rawToken)
		s["_csrf"] = token
	}

	return token
}

// A simple handler which returns the valid csrf token for the current client.
//
// The return format is either JSON or text.
func CSRFTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := GetCSRFToken(r)

	Render(r).
		JSON(map[string]string{"token": token}).
		Text(token)
}
