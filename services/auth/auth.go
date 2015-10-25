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

/*
Authentication service.

This service is a generic service for authentication.
*/
package auth

import (
	"net/http"
	"time"

	"github.com/nbio/hitch"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/util"
	"github.com/tamasd/hitch-session"
)

type authProviderLabel struct {
	Id    string `json:"id"`
	Label string `json:"label"`
}

type AuthProvider interface {
	GetName() string  // machine name of the provider (usually a lowercase word, max 32 characters)
	GetLabel() string // this is displayed to the user
	Register(baseURL string, h *hitch.Hitch, user UserDelegate)
}

var _ ab.Service = &Service{}

// Auth service settings.
type Service struct {
	BaseURL     string // base URL of the server that uses this service
	providers   []AuthProvider
	user        UserDelegate
	conn        ab.DB
	stopCleanup chan struct{}
}

// Creates a new auth service.
//
// Before using this service, make sure that you called util.SetKey().
func NewService(baseURL string, user UserDelegate, conn ab.DB, providers ...AuthProvider) *Service {
	return &Service{
		BaseURL:     baseURL,
		providers:   providers,
		conn:        conn,
		user:        user,
		stopCleanup: make(chan struct{}),
	}
}

func (s *Service) SchemaInstalled(db ab.DB) bool {
	return ab.TableExists(db, "auth")
}

func (s *Service) SchemaSQL() string {
	return `
	CREATE TABLE auth (
		uuid uuid NOT NULL,
		authid character varying(256) NOT NULL,
		secret text NOT NULL,
		provider character varying(32) NOT NULL,
		CONSTRAINT auth_pkey PRIMARY KEY (uuid, provider),
		CONSTRAINT auth_authid_provider_key UNIQUE (authid, provider),
		CONSTRAINT auth_authid_check CHECK (authid::text <> ''::text)
	);

	CREATE TABLE token (
		uuid uuid NOT NULL,
		category character varying NOT NULL,
		token character(128) NOT NULL,
		expires timestamp with time zone,
		CONSTRAINT token_pkey PRIMARY KEY (uuid, category),
		CONSTRAINT token_token_key UNIQUE (token)
	);
	`
}

// Adds an OAuth1Provider or an OAuth2Provider to the service. Adding a type that only implements the OAuthProvider interface will cause a runtime panic on Register().
func (s *Service) AddProvider(p AuthProvider) {
	s.providers = append(s.providers, p)
}

func (s *Service) Register(h *hitch.Hitch) error {
	providers := []authProviderLabel{}

	for _, p := range s.providers {
		p.Register(s.BaseURL, h, s.user)

		providers = append(providers, authProviderLabel{
			Id:    p.GetName(),
			Label: p.GetLabel(),
		})
	}

	h.Get("/api/providers/auth", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ab.Render(r).JSON(providers)
	}))

	h.Get("/api/auth/logout", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := session.GetSession(r)
		for k := range sess {
			delete(sess, k)
		}

		http.Redirect(w, r, ab.RedirectDestination(r), http.StatusSeeOther)
	}), ab.CSRFGetMiddleware("token"))

	go func() {
		for {
			RemoveExpiredTokens(s.conn)
			select {
			case <-time.After(time.Hour):
			case <-s.stopCleanup:
				return
			}
		}
	}()

	return nil
}

// Stops the token cleanup goroutine.
func (s *Service) StopCleanup() {
	close(s.stopCleanup)
}

// Adds an authentication method for a user.
func AddAuthToUser(db ab.DB, uuid, authid, secret, provider string) error {
	_, err := db.Exec("INSERT INTO auth(uuid, authid, secret, provider) VALUES($1, $2, $3, $4)", uuid, authid, util.EncryptString(secret), provider)
	return err
}

// Authenticates a user with authid.
func AuthenticateUser(db ab.DB, name, authid string) (string, error) {
	var uuid string
	err := db.QueryRow("SELECT uuid FROM auth a WHERE a.provider = $1 AND a.authid = $2", name, authid).Scan(&uuid)
	return uuid, err
}

// This middlware restricts the endpoint for loggedin users.
func LoggedInMiddleware(user UserDelegate) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !user.IsLoggedIn(r) {
				ab.Fail(r, http.StatusForbidden, ab.NewVerboseError("", "user is not logged in"))
			}

			next.ServeHTTP(w, r)
		})
	}
}

// This middleware restricts the endpoint for anonymous users.
func NotLoggedInMiddleware(user UserDelegate) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if user.IsLoggedIn(r) {
				ab.Fail(r, http.StatusForbidden, ab.NewVerboseError("", "user is already logged in"))
			}

			next.ServeHTTP(w, r)
		})
	}
}
