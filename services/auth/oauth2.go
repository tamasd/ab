package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/nbio/hitch"
	"github.com/tamasd/ab"
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
	delegate OAuth2ProviderDelegate
}

func NewOAuth2Provider(delegate OAuth2ProviderDelegate) *OAuth2Provider {
	return &OAuth2Provider{
		delegate: delegate,
	}
}

func (p *OAuth2Provider) GetName() string {
	return p.delegate.GetName()
}

func (p *OAuth2Provider) GetLabel() string {
	return p.delegate.GetLabel()
}

func (p *OAuth2Provider) Register(baseURL string, h *hitch.Hitch, user UserDelegate) {
	name := p.GetName()
	c := p.delegate.GetConfig()
	c.RedirectURL = baseURL + "api/auth/" + name + "/callback"

	h.Get("/api/auth/"+name+"/connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")

		url := c.AuthCodeURL(token, oauth2.AccessTypeOffline)
		http.Redirect(w, r, url, http.StatusSeeOther)
	}), ab.CSRFGetMiddleware("token"))

	h.Get("/api/auth/"+name+"/callback", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			ab.Fail(r, http.StatusBadRequest, nil)
		}

		token, err := c.Exchange(oauth2.NoContext, code)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, err)
		}

		client := c.Client(oauth2.NoContext, token)

		oauthuser, authid, err := p.delegate.PrepareUser(client, token)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, err)
		}

		jsontokens, err := json.Marshal(token)
		if err != nil {
			ab.Fail(r, http.StatusInternalServerError, err)
		}

		db := ab.GetDB(r)

		if user.IsLoggedIn(r) {
			// User is already logged in. This scenario is likely to happen
			// when the user intends to add a new service.
			id := user.CurrentUser(r)
			ab.MaybeFail(r, http.StatusInternalServerError, AddAuthToUser(db, id, authid, string(jsontokens), name))
		} else {
			// User is not logged in.
			// First let's try to authenticate, assuming that the user exists.
			id, _ := AuthenticateUser(db, name, authid)
			// The user is not found. Let's register the user.
			if id == "" {
				if err := oauthuser.Insert(db); err != nil {
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
	}), ab.CSRFGetMiddleware("state"))
}

func GetOAuth2Client(db ab.DB, provider OAuth2ProviderDelegate, uid string) *http.Client {
	token := ""
	if err := db.QueryRow("SELECT secret FROM auth WHERE uuid = $1 AND provider = $2", uid, provider.GetName()).Scan(&token); err != nil {
		log.Println(err)
		return nil
	}

	token = util.DecryptString(token)

	t := &oauth2.Token{}
	if err := json.Unmarshal([]byte(token), t); err != nil {
		log.Println(err)
		return nil
	}
	cfg := provider.GetConfig()
	client := cfg.Client(oauth2.NoContext, t)
	tok, err := json.Marshal(t)
	if err != nil {
		log.Println(err)
		return nil
	}

	if _, err = db.Exec("UPDATE auth SET secret = $1 WHERE uuid = $2 AND provider = $3", string(tok), uid, provider.GetName()); err != nil {
		log.Println(err)
		return nil
	}

	return client
}
