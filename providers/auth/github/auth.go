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

package github

import (
	"net/http"

	gh "github.com/google/go-github/github"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/services/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const GITHUB_BASE = "https://api.github.com"

type GithubUserDelegate interface {
	Convert(*gh.User) ab.Entity
}

var _ auth.OAuth2ProviderDelegate = &GithubAuthProvider{}

type GithubAuthProvider struct {
	creds    auth.OAuthCredentials
	delegate GithubUserDelegate
	scopes   []string
}

func NewAuthProvider(creds auth.OAuthCredentials, delegate GithubUserDelegate) *GithubAuthProvider {
	return &GithubAuthProvider{
		creds:    creds,
		delegate: delegate,
		scopes:   []string{"user"},
	}
}

func (g *GithubAuthProvider) AddScopes(scopes ...string) {
	g.scopes = append(g.scopes, scopes...)
}

func (g *GithubAuthProvider) GetName() string {
	return "github"
}

func (g *GithubAuthProvider) GetLabel() string {
	return "GitHub"
}

func (g *GithubAuthProvider) GetConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.creds.ID,
		ClientSecret: g.creds.Secret,
		Endpoint:     github.Endpoint,
		Scopes:       g.scopes,
	}
}

func (g *GithubAuthProvider) PrepareUser(c *http.Client, t *oauth2.Token) (ab.Entity, string, error) {
	client := gh.NewClient(c)

	user, _, err := client.Users.Get("")

	if err != nil {
		return nil, "", err
	}

	return g.delegate.Convert(user), *user.Login, nil
}
