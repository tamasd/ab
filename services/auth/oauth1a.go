package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/garyburd/go-oauth/oauth"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/util"
)

type OAuth1ProviderDelegate interface {
	OAuthProvider
	GetClient() *oauth.Client
	PrepareUser(*oauth.Credentials) (ab.Entity, string, error)
}

var _ AuthProvider = &OAuth1Provider{}

type OAuth1Provider struct {
	delegate   OAuth1ProviderDelegate
	controller *ab.EntityController
}

func NewOAuth1Provider(ec *ab.EntityController, delegate OAuth1ProviderDelegate) *OAuth1Provider {
	return &OAuth1Provider{
		delegate:   delegate,
		controller: ec,
	}
}

func (p *OAuth1Provider) GetName() string {
	return p.delegate.GetName()
}

func (p *OAuth1Provider) GetLabel() string {
	return p.delegate.GetLabel()
}

func (p *OAuth1Provider) Register(baseURL string, srv *ab.Server, user UserDelegate) {
	name := p.GetName()
	c := p.delegate.GetClient()
	callback := baseURL + "api/auth/" + name + "/callback"

	srv.Get("/api/auth/"+name+"/connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpCred, err := c.RequestTemporaryCredentials(nil, callback+"?token="+r.URL.Query().Get("token"), nil)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, nil)
		}
		s := ab.GetSession(r)
		s["oauth_"+name+"_tmpcred"] = util.EncryptString(tmpCred.Token + ":" + tmpCred.Secret)

		url := c.AuthorizationURL(tmpCred, nil)
		http.Redirect(w, r, url, http.StatusSeeOther)
	}), ab.CSRFGetMiddleware("token"))

	srv.Get("/api/auth/"+name+"/callback", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := ab.GetSession(r)
		tmpCredEncoded := util.DecryptString(s["oauth_"+name+"_tmpcred"])
		if tmpCredEncoded == "" {
			ab.Fail(r, http.StatusBadRequest, nil)
		}
		tmpCredParts := strings.Split(tmpCredEncoded, ":")
		if len(tmpCredParts) != 2 {
			ab.Fail(r, http.StatusBadRequest, nil)
		}
		delete(s, "oauth_"+name+"_tmpcred")
		tmpCred := &oauth.Credentials{
			Token:  tmpCredParts[0],
			Secret: tmpCredParts[1],
		}
		if tmpCred.Token != r.URL.Query().Get("oauth_token") {
			ab.Fail(r, http.StatusBadRequest, nil)
		}
		tokenCred, _, err := c.RequestToken(nil, tmpCred, r.URL.Query().Get("oauth_verifier"))
		if err != nil {
			ab.Fail(r, http.StatusBadRequest, err)
		}

		oauthuser, authid, err := p.delegate.PrepareUser(tokenCred)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, err)
		}

		jsontokens, err := json.Marshal(tokenCred)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, err)
		}

		db := ab.GetTransaction(r)

		if user.IsLoggedIn(r) {
			id := user.CurrentUser(r)
			AddAuthToUser(db, id, authid, string(jsontokens), name)
		} else {
			id, _ := AuthenticateUser(db, name, authid)
			if id == "" {
				if err := p.controller.Insert(db, oauthuser); err != nil {
					ab.Fail(r, http.StatusInternalServerError, err)
				}
				id = oauthuser.GetID()
				if err := AddAuthToUser(db, id, authid, string(jsontokens), name); err != nil {
					ab.Fail(r, http.StatusInternalServerError, err)
				}
			}

			user.LoginUser(r, id)
		}

		http.Redirect(w, r, ab.RedirectDestination(r), http.StatusSeeOther)
	}), ab.CSRFGetMiddleware("token"))
}

func GetOAuth1Client(db ab.DB, logger *log.Log, provider OAuth1ProviderDelegate, uid string) *oauth.Credentials {
	token := ""
	if err := db.QueryRow("SELECT secret FROM auth WHERE uuid = $1 AND provider = $2", uid, provider.GetName()).Scan(&token); err != nil {
		logger.User().Println(err)
		return nil
	}

	token = util.DecryptString(token)

	c := &oauth.Credentials{}
	if err := json.Unmarshal([]byte(token), c); err != nil {
		logger.User().Println(err)
		return nil
	}

	return c
}
