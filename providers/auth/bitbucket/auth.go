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

package bitbucket

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/garyburd/go-oauth/oauth"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/services/auth"
	"github.com/tamasd/ab/util"
)

const BITBUCKET_BASE = "https://api.bitbucket.org/1.0"

type BitbucketUserDelegate interface {
	Convert(BitbucketUserResponse) ab.Entity
}

var _ auth.OAuth1ProviderDelegate = &BitbucketAuthProvider{}

type BitbucketAuthProvider struct {
	creds    auth.OAuthCredentials
	delegate BitbucketUserDelegate
}

func NewAuthProvider(creds auth.OAuthCredentials, delegate BitbucketUserDelegate) *BitbucketAuthProvider {
	return &BitbucketAuthProvider{
		creds:    creds,
		delegate: delegate,
	}
}

func (b *BitbucketAuthProvider) GetName() string {
	return "bitbucket"
}

func (b *BitbucketAuthProvider) GetLabel() string {
	return "BitBucket"
}

func (b *BitbucketAuthProvider) GetClient() *oauth.Client {
	return &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  b.creds.ID,
			Secret: b.creds.Secret,
		},
		TemporaryCredentialRequestURI: "https://bitbucket.org/api/1.0/oauth/request_token",
		ResourceOwnerAuthorizationURI: "https://bitbucket.org/api/1.0/oauth/authenticate",
		TokenRequestURI:               "https://bitbucket.org/api/1.0/oauth/access_token",
		SignatureMethod:               oauth.HMACSHA1,
	}
}

func (b *BitbucketAuthProvider) PrepareUser(creds *oauth.Credentials) (ab.Entity, string, error) {
	c := b.GetClient()

	resp, err := c.Get(nil, creds, BITBUCKET_BASE+"/user", nil)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("invalid status code while retrieving bitbucket user: %d\n%s", resp.StatusCode, util.ResponseBodyToString(resp))
	}

	var bbuser BitbucketUserResponse
	if err = json.NewDecoder(resp.Body).Decode(&bbuser); err != nil {
		return nil, "", err
	}

	resp, err = c.Get(nil, creds, BITBUCKET_BASE+"/users/"+bbuser.User.Username+"/emails", nil)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("invalid status code while retrieving bitbucket emails: %d\n%s", resp.StatusCode, util.ResponseBodyToString(resp))
	}

	var bbemails []BitbucketEmail
	if err = json.NewDecoder(resp.Body).Decode(&bbemails); err != nil {
		return nil, "", err
	}

	var email string
	for _, bbemail := range bbemails {
		if bbemail.Primary {
			email = bbemail.Email
		}
	}
	if email == "" {
		return nil, "", fmt.Errorf("no primary email is associated with the account: %s", bbuser.User.Username)
	}

	return b.delegate.Convert(bbuser), bbuser.User.Username, nil
}

type BitbucketEmail struct {
	Active  bool
	Email   string
	Primary bool
}

type BitbucketUser struct {
	Username  string
	FirstName string
	LastName  string
	IsTeam    bool
	Avatar    string
}

type BitbucketUserResponse struct {
	User BitbucketUser
}
