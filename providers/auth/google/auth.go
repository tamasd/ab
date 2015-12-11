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
	"strings"

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
	Convert(*plus.Person) (ab.Entity, error)
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

	entity, err := g.delegate.Convert(person)
	if err != nil {
		return nil, "", err
	}

	return entity, person.Id, nil
}

type ErrorNoEmail struct {
	Emails []*plus.PersonEmails
}

func (e ErrorNoEmail) Error() string {
	mails := []string{}
	for _, m := range e.Emails {
		if m != nil {
			mails = append(mails, m.Value+" ("+m.Type+")")
		} else {
			mails = append(mails, "<nil>")
		}
	}

	mailList := "<empty list>"
	if len(mails) > 0 {
		mailList = strings.Join(mails, ", ")
	}

	return "no valid email found (" + mailList + ")"
}
