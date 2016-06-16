package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tamasd/ab"
	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/util"
	"golang.org/x/oauth2"
)

type OAuth2ProviderDelegate interface {
	OAuthProvider
	GetConfig() *oauth2.Config
	PrepareUser(*http.Client, *oauth2.Token) (ab.Entity, string, error)
}

var _ AuthProvider = &OAuth2Provider{}

type OAuth2Provider struct {
	delegate   OAuth2ProviderDelegate
	controller *ab.EntityController
}

func NewOAuth2Provider(ec *ab.EntityController, delegate OAuth2ProviderDelegate) *OAuth2Provider {
	return &OAuth2Provider{
		delegate:   delegate,
		controller: ec,
	}
}

func (p *OAuth2Provider) GetName() string {
	return p.delegate.GetName()
}

func (p *OAuth2Provider) GetLabel() string {
	return p.delegate.GetLabel()
}

func (p *OAuth2Provider) Register(baseURL string, srv *ab.Server, user UserDelegate) {
	name := p.GetName()
	c := p.delegate.GetConfig()
	c.RedirectURL = baseURL + "api/auth/" + name + "/callback"

	srv.Get("/api/auth/"+name+"/connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")

		url := c.AuthCodeURL(token, oauth2.AccessTypeOffline)
		ab.LogTrace(r).Println("redirecting to OAuth2 provider", name)
		http.Redirect(w, r, url, http.StatusSeeOther)
	}), ab.CSRFGetMiddleware("token"))

	srv.Get("/api/auth/"+name+"/callback", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			ab.Fail(r, http.StatusBadRequest, errors.New("empty code from "+name))
		}

		token, err := c.Exchange(oauth2.NoContext, code)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, err)
		}

		client := c.Client(oauth2.NoContext, token)

		oauthuser, authid, err := p.delegate.PrepareUser(client, token)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, ab.WrapError(err, "Failed to retrieve the required data from the provider. Check your privacy settings."))
		}
		if authid == "" {
			ab.Fail(r, http.StatusInternalServerError, ab.WrapError(nil, "Failed to retrieve the required data from the provider. Check your privacy settings."))
		}

		jsontokens, err := json.Marshal(token)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, err)
		}

		db := ab.GetDB(r)

		if user.IsLoggedIn(r) {
			// User is already logged in. This scenario is likely to happen
			// when the user intends to add a new service.
			ab.LogTrace(r).Println("user is already logged in, adding new service")
			id := user.CurrentUser(r)
			ab.MaybeFail(r, http.StatusInternalServerError, AddAuthToUser(db, id, authid, string(jsontokens), name))
		} else {
			// User is not logged in.
			// First let's try to authenticate, assuming that the user exists.
			ab.LogTrace(r).Println("user is not logged in")
			id, _ := AuthenticateUser(db, name, authid)
			// The user is not found. Let's register the user.
			if id == "" {
				ab.LogTrace(r).Println("user not found, creating new user")
				if err := p.controller.Insert(ab.GetTransaction(r), oauthuser); err != nil {
					ab.Fail(r, http.StatusInternalServerError, err)
				}
				id = oauthuser.GetID()
				if err := AddAuthToUser(db, id, authid, string(jsontokens), name); err != nil {
					ab.Fail(r, http.StatusInternalServerError, err)
				}
			}

			ab.LogTrace(r).Println("logging in user")
			user.LoginUser(r, id)
		}

		http.Redirect(w, r, ab.RedirectDestination(r), http.StatusSeeOther)
	}), ab.CSRFGetMiddleware("state"))
}

func GetOAuth2Client(db ab.DB, logger *log.Log, provider OAuth2ProviderDelegate, uid string) *http.Client {
	token := ""
	if err := db.QueryRow("SELECT secret FROM auth WHERE uuid = $1 AND provider = $2", uid, provider.GetName()).Scan(&token); err != nil {
		logger.User().Println(err)
		return nil
	}

	token = util.DecryptString(token)

	t := &oauth2.Token{}
	if err := json.Unmarshal([]byte(token), t); err != nil {
		logger.User().Println(err)
		return nil
	}
	cfg := provider.GetConfig()
	client := cfg.Client(oauth2.NoContext, t)
	tok, err := json.Marshal(t)
	if err != nil {
		logger.User().Println(err)
		return nil
	}

	if _, err = db.Exec("UPDATE auth SET secret = $1 WHERE uuid = $2 AND provider = $3", string(tok), uid, provider.GetName()); err != nil {
		logger.User().Println(err)
		return nil
	}

	return client
}
