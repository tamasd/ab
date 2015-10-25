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

package google

import (
	"net/http"

	"github.com/tamasd/ab"
	"github.com/tamasd/ab/services/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/plus/v1"
)

func NewGoogleAuthProvider(creds auth.OAuthCredentials, delegate GoogleUserDelegate) *auth.OAuth2Provider {
	return auth.NewOAuth2Provider(NewGoogleAuthProviderDelegate(creds, delegate))
}

type GoogleUserDelegate interface {
	Convert(*plus.Person) ab.Entity
}

var _ auth.OAuth2ProviderDelegate = &GoogleAuthProviderDelegate{}

type GoogleAuthProviderDelegate struct {
	creds    auth.OAuthCredentials
	delegate GoogleUserDelegate
}

func NewGoogleAuthProviderDelegate(creds auth.OAuthCredentials, delegate GoogleUserDelegate) *GoogleAuthProviderDelegate {
	return &GoogleAuthProviderDelegate{
		creds:    creds,
		delegate: delegate,
	}
}

func (g *GoogleAuthProviderDelegate) GetLabel() string {
	return "Google"
}

func (g *GoogleAuthProviderDelegate) GetName() string {
	return "google"
}

func (g *GoogleAuthProviderDelegate) GetConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.creds.ID,
		ClientSecret: g.creds.Secret,
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"profile",
			"email",
		},
	}
}

func (g *GoogleAuthProviderDelegate) PrepareUser(c *http.Client, token *oauth2.Token) (ab.Entity, string, error) {
	plusService, err := plus.New(c)
	if err != nil {
		return nil, "", err
	}

	person, err := plusService.People.Get("me").Do()
	if err != nil {
		return nil, "", err
	}

	entity := g.delegate.Convert(person)
	return entity, person.Url, nil

}
