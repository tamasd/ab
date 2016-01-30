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

package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/boombuler/barcode/qr"
	"github.com/dgryski/dgoogauth"
	"github.com/lib/pq"
	"github.com/nbio/hitch"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/util"
	"golang.org/x/crypto/scrypt"
)

var (
	PASSWORD_HASH_SALT_LENGTH = 32
	PASSWORD_HASH_N           = 32768
	PASSWORD_HASH_R           = 8
	PASSWORD_HASH_P           = 1
	PASSWORD_HASH_KEYLEN      = 64
)

var hashVerifiers = map[string]func(pw, hash string) (bool, error){
	"scrypt": scryptVerify,
}

type PasswordAuthProviderDelegate interface {
	GetPassword() Password
	GetDBErrorConverter() func(*pq.Error) ab.VerboseError
	GetAuthID(ab.Entity) string
	GetEmail(ab.Entity) string
	Get2FAIssuer() string
	LoadUserByMail(string) (ab.Entity, error)
}

var _ AuthProvider = &PasswordAuthProvider{}

type PasswordAuthProvider struct {
	delegate      PasswordAuthProviderDelegate
	emailDelegate PasswordAuthEmailSenderDelegate
}

func NewPasswordAuthProvider(delegate PasswordAuthProviderDelegate, emailDelegate PasswordAuthEmailSenderDelegate) *PasswordAuthProvider {
	return &PasswordAuthProvider{
		delegate:      delegate,
		emailDelegate: emailDelegate,
	}
}

func (p *PasswordAuthProvider) GetName() string {
	return "password"
}

func (p *PasswordAuthProvider) GetLabel() string {
	return "Password"
}

func (p *PasswordAuthProvider) Register(baseURL string, h *hitch.Hitch, user UserDelegate) {
	name := p.GetName()

	h.Post("/api/auth/"+name+"/register", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postData := p.delegate.GetPassword()

		ab.MustDecode(r, postData)

		if postData.GetID() != "" {
			ab.Fail(r, http.StatusBadRequest, ab.NewVerboseError("", "id was provided for user"))
		}

		ab.MaybeFail(r, http.StatusBadRequest, postData.Validate())
		ab.MaybeFail(r, http.StatusBadRequest, postData.ValidatePassword())

		db := ab.GetTransaction(r)

		err := postData.Insert(db)
		ab.MaybeFail(r, http.StatusBadRequest, ab.ConvertDBError(err, p.delegate.GetDBErrorConverter()))

		hash, err := defaultHashPassword(postData.GetPassword())
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		emailTokenBuf := make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, emailTokenBuf)
		ab.MaybeFail(r, http.StatusInternalServerError, err)
		emailToken := hex.EncodeToString(emailTokenBuf)

		authData, _ := json.Marshal(passwordAuthData{
			PasswordHash:           hash,
			EmailVerificationToken: emailToken,
		})
		err = AddAuthToUser(db, postData.GetID(), p.delegate.GetAuthID(postData), string(authData), name)
		ab.MaybeFail(r, http.StatusInternalServerError, ab.ConvertDBError(err, p.delegate.GetDBErrorConverter()))

		err = p.emailDelegate.SendRegistrationEmail(p.delegate.GetEmail(postData), "/api/auth/"+name+"/verifyemail?token="+ab.GetCSRFToken(r)+"&code="+emailToken+"&uuid="+postData.GetID())
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		ab.Render(r).SetCode(http.StatusCreated)
	}), NotLoggedInMiddleware(user))

	h.Get("/api/auth/"+name+"/verifyemail", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uuid := r.URL.Query().Get("uuid")
		code := r.URL.Query().Get("code")

		if code == "" || uuid == "" {
			ab.Fail(r, http.StatusBadRequest, errors.New("uuid or code is missing"))
		}

		db := ab.GetTransaction(r)

		authData, err := getAuthData(db, uuid, p.GetName())
		ab.MaybeFail(r, http.StatusBadRequest, err)

		if authData.EmailVerificationToken == "" || authData.EmailVerificationToken != code {
			ab.Fail(r, http.StatusForbidden, nil)
		}

		authData.EmailVerificationToken = ""

		err = updateAuthData(db, uuid, p.GetName(), authData)
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		user.LoginUser(r, uuid)
	}), ab.CSRFGetMiddleware("token"), NotLoggedInMiddleware(user))

	h.Post("/api/auth/"+name+"/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := ab.GetSession(r)
		db := ab.GetDB(r)

		ld := PasswordLoginData{}
		ab.MustDecode(r, &ld)

		var uuid string
		var secret string
		if err := db.QueryRow("SELECT uuid, secret FROM auth a WHERE a.provider = $1 AND a.authid = $2", p.GetName(), ld.Identifier).Scan(&uuid, &secret); err != nil {
			ab.Fail(r, http.StatusInternalServerError, ab.ConvertDBError(err, p.delegate.GetDBErrorConverter()))
		}

		authData := passwordAuthData{}
		if err := json.Unmarshal([]byte(util.DecryptString(secret)), &authData); err != nil {
			ab.Fail(r, http.StatusInternalServerError, err)
		}

		if authData.EmailVerificationToken != "" {
			ab.Fail(r, http.StatusForbidden, errors.New("email is not verified"))
		}

		ok, err := verifyPassword(ld.Password, authData.PasswordHash)
		ab.MaybeFail(r, http.StatusInternalServerError, err)
		if !ok {
			ab.Fail(r, http.StatusForbidden, errors.New("invalid password"))
		}

		if authData.TwoFAToken == "" {
			user.LoginUser(r, uuid)
		} else {
			sess["2fa_user"] = uuid
			ab.Render(r).SetCode(http.StatusAccepted)
		}
	}), NotLoggedInMiddleware(user))

	h.Post("/api/auth/"+name+"/2fa", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := ab.GetSession(r)
		tmpUser := sess["2fa_user"]
		if tmpUser == "" {
			ab.Fail(r, http.StatusBadRequest, nil)
		}

		delete(sess, "2fa_user")

		d := add2faData{}
		ab.MustDecode(r, &d)

		db := ab.GetDB(r)

		authData, err := getAuthData(db, tmpUser, p.GetName())
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		valid, err := otpAuth(authData.TwoFAToken, d.Token)
		ab.MaybeFail(r, http.StatusBadRequest, err)

		if valid {
			user.LoginUser(r, tmpUser)
		} else {
			ab.Fail(r, http.StatusForbidden, nil)
		}
	}), NotLoggedInMiddleware(user))

	h.Get("/api/auth/"+name+"/add2fa", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := ab.GetSession(r)
		sec := make([]byte, 6)
		_, err := io.ReadFull(rand.Reader, sec)
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		secret := base32.StdEncoding.EncodeToString(sec)

		issuer := p.delegate.Get2FAIssuer()
		auth_string := "otpauth://totp/" + user.CurrentUser(r) + "?secret=" + secret + "&issuer=" + issuer

		code, err := qr.Encode(auth_string, qr.H, qr.Unicode)
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		sess["2fa_secret"] = util.EncryptString(secret)

		buf := bytes.NewBuffer(nil)
		ab.MaybeFail(r, http.StatusInternalServerError, png.Encode(buf, code))
		img := buf.Bytes()

		ab.Render(r).AddOffer("image/png", func(w http.ResponseWriter) {
			w.Write(img)
		}).JSON(map[string]string{
			"secret": secret,
			"image":  base64.StdEncoding.EncodeToString(img),
		}).SetCode(http.StatusAccepted)
	}), ab.CSRFGetMiddleware("token"), LoggedInMiddleware(user))

	h.Post("/api/auth/"+name+"/add2fa", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := ab.GetSession(r)
		secret := util.DecryptString(sess["2fa_secret"])

		if secret == "" {
			ab.Fail(r, http.StatusForbidden, nil)
		}

		delete(sess, "2fa_secret")

		d := add2faData{}
		ab.MustDecode(r, &d)

		valid, err := otpAuth(secret, d.Token)
		ab.MaybeFail(r, http.StatusBadRequest, err)

		if valid {
			currentUser := user.CurrentUser(r)
			db := ab.GetTransaction(r)
			authData, err := getAuthData(db, currentUser, p.GetName())
			ab.MaybeFail(r, http.StatusBadRequest, err)
			authData.TwoFAToken = secret
			err = updateAuthData(db, currentUser, p.GetName(), authData)
			ab.MaybeFail(r, http.StatusInternalServerError, err)
		} else {
			ab.Fail(r, http.StatusForbidden, nil)
		}
	}), LoggedInMiddleware(user))

	h.Post("/api/auth/"+name+"/disable2fa", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := remove2faData{}
		ab.MustDecode(r, &d)

		db := ab.GetTransaction(r)
		uid := user.CurrentUser(r)

		authData, err := getAuthData(db, uid, p.GetName())
		ab.MaybeFail(r, http.StatusBadRequest, err)

		ok, err := verifyPassword(d.Password, authData.PasswordHash)
		if err != nil || !ok {
			ab.Fail(r, http.StatusForbidden, err)
		}

		authData.TwoFAToken = ""

		err = updateAuthData(db, uid, p.GetName(), authData)
		ab.MaybeFail(r, http.StatusInternalServerError, err)
	}), LoggedInMiddleware(user))

	h.Post("/api/auth/"+name+"/changepassword", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := ab.GetSession(r)
		db := ab.GetTransaction(r)
		uid := user.CurrentUser(r)
		otlcode := sess["otlcode"]
		delete(sess, "otlcode")

		pwchg := PasswordChangeFields{}
		ab.MustDecode(r, &pwchg)

		ab.MaybeFail(r, http.StatusBadRequest, pwchg.ValidatePassword())

		authData, err := getAuthData(db, uid, p.GetName())
		ab.MaybeFail(r, http.StatusBadRequest, err)

		if otlcode == "" {
			ok, err := verifyPassword(pwchg.GetOldPassword(), authData.PasswordHash)
			ab.MaybeFail(r, http.StatusInternalServerError, err)
			if !ok {
				ab.Fail(r, http.StatusBadRequest, nil)
			}
		} else {
			ok, err := ConsumeToken(db, uid, "otlcode", otlcode)
			ab.MaybeFail(r, http.StatusInternalServerError, err)
			if !ok {
				ab.Fail(r, http.StatusBadRequest, nil)
			}
		}

		authData.PasswordHash, err = defaultHashPassword(pwchg.GetPassword())
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		err = updateAuthData(db, uid, p.GetName(), authData)
		ab.MaybeFail(r, http.StatusInternalServerError, err)
	}), LoggedInMiddleware(user))

	h.Post("/api/auth/"+name+"/lostpassword", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := lostPasswordData{}
		ab.MustDecode(r, &d)

		user, err := p.delegate.LoadUserByMail(d.Email)
		ab.MaybeFail(r, http.StatusBadRequest, err)
		if user.GetID() == "" {
			ab.Fail(r, http.StatusNotFound, errors.New("user not found"))
		}

		db := ab.GetDB(r)

		exp := time.Now().Add(24 * time.Hour)
		t, err := CreateToken(db, user.GetID(), "lostpassword", &exp)
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		err = p.emailDelegate.SendLostPasswordLink(d.Email, "/api/auth/"+name+"/onetimelogin?code="+t+"&uuid="+user.GetID())
		ab.MaybeFail(r, http.StatusInternalServerError, err)
	}), NotLoggedInMiddleware(user))

	h.Get("/api/auth/"+name+"/onetimelogin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		uuid := r.URL.Query().Get("uuid")
		if code == "" || uuid == "" {
			ab.Fail(r, http.StatusNotFound, nil)
		}

		db := ab.GetDB(r)

		ok, err := ConsumeToken(db, uuid, "lostpassword", code)
		ab.MaybeFail(r, http.StatusNotFound, err)
		if !ok {
			ab.Fail(r, http.StatusNotFound, nil)
		}

		exp := time.Now().Add(time.Hour)
		otlcode, err := CreateToken(db, uuid, "otlcode", &exp)
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		sess := ab.GetSession(r)
		sess["otlcode"] = otlcode
		user.LoginUser(r, uuid)
	}), NotLoggedInMiddleware(user))
}

func otpAuth(secret, token string) (bool, error) {
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}

	return otpc.Authenticate(token)
}

func getAuthData(db ab.DB, uuid, provider string) (d passwordAuthData, err error) {
	secret := ""
	err = db.QueryRow("SELECT secret FROM auth a WHERE a.provider = $1 AND a.uuid = $2", provider, uuid).Scan(&secret)
	if err != nil {
		return
	}

	err = json.Unmarshal([]byte(util.DecryptString(secret)), &d)
	if err != nil {
		return
	}

	return
}

func updateAuthData(db ab.DB, uuid, provider string, d passwordAuthData) error {
	jsonD, err := json.Marshal(d)
	if err != nil {
		return err
	}
	secret := util.EncryptString(string(jsonD))

	_, err = db.Exec("UPDATE auth SET secret = $1 WHERE uuid = $2 AND provider = $3", secret, uuid, provider)

	return err
}

func defaultHashPassword(pw string) (string, error) {
	return hashPassword(pw,
		PASSWORD_HASH_SALT_LENGTH,
		PASSWORD_HASH_N,
		PASSWORD_HASH_R,
		PASSWORD_HASH_P,
		PASSWORD_HASH_KEYLEN,
	)
}

func hashPassword(pw string, saltlen, n, r, p, keylen int) (string, error) {
	salt := make([]byte, saltlen)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return "", err
	}

	hash, err := scrypt.Key([]byte(pw), salt, n, r, p, keylen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("scrypt$%s$%d$%d$%d$%s",
		hex.EncodeToString(salt),
		n, r, p,
		hex.EncodeToString(hash),
	), nil
}

func verifyPassword(pw, hash string) (bool, error) {
	parts := strings.SplitN(hash, "$", 2)
	if len(parts) != 2 {
		return false, errors.New("invalid hash")
	}

	alg := parts[0]

	if fn, ok := hashVerifiers[alg]; ok {
		return fn(pw, hash)
	} else {
		return false, errors.New("unknown hash algorithm: " + alg)
	}
}

func scryptVerify(pw, hash string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, err
	}

	n, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, err
	}

	r, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, err
	}

	p, err := strconv.Atoi(parts[4])
	if err != nil {
		return false, err
	}

	pwhash, err := hex.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	newhash, err := scrypt.Key([]byte(pw), salt, n, r, p, len(pwhash))
	if err != nil {
		return false, err
	}

	if len(pwhash) != len(newhash) {
		return false, nil
	}

	ok := true
	for i := 0; i < len(pwhash); i++ {
		ok = ok && (pwhash[i] == newhash[i])
	}

	return ok, nil
}

type Password interface {
	ab.Entity
	GetPassword() string
	ValidatePassword() error
}

type PasswordFields struct {
	Password        string `json:"password"`
	PasswordConfirm string `json:"password_confirm"`
}

func (pf PasswordFields) ValidatePassword() error {
	if pf.Password == "" {
		return ab.NewVerboseError("", "password must not be empty")
	}

	if pf.Password != pf.PasswordConfirm {
		return ab.NewVerboseError("", "passwords do not match")
	}

	return nil
}

func (pf PasswordFields) GetPassword() string {
	return pf.Password
}

type PasswordChangeFields struct {
	PasswordFields
	OldPassword string
}

type PasswordLoginData struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

func (pcf PasswordChangeFields) GetOldPassword() string {
	return pcf.OldPassword
}

type passwordAuthData struct {
	PasswordHash           string
	TwoFAToken             string
	EmailVerificationToken string
}

type add2faData struct {
	Token string `json:"token"`
}

type remove2faData struct {
	Password string `json:"password"`
}

type lostPasswordData struct {
	Email string `json:"email"`
}

type PasswordAuthEmailSenderDelegate interface {
	SendRegistrationEmail(address, url string) error
	SendLostPasswordLink(address, url string) error
}

var _ PasswordAuthEmailSenderDelegate = &PasswordAuthSMTPEmailSenderDelegate{}

type PasswordAuthSMTPEmailSenderDelegate struct {
	baseURL   string
	smtpAuth  smtp.Auth
	SMTPAddr  string
	SiteEmail string

	RegistrationEmailTemplate string
	LostPasswordEmailTemplate string
}

func NewPasswordAuthSMTPEmailSenderDelegate(smtpAuth smtp.Auth, baseURL string) *PasswordAuthSMTPEmailSenderDelegate {
	return &PasswordAuthSMTPEmailSenderDelegate{
		smtpAuth: smtpAuth,
		baseURL:  baseURL,
	}
}

func (d *PasswordAuthSMTPEmailSenderDelegate) SendRegistrationEmail(address, url string) error {
	msg := strings.Replace(d.RegistrationEmailTemplate, "URL", d.baseURL+url, -1)
	return smtp.SendMail(d.SMTPAddr, d.smtpAuth, d.SiteEmail, []string{address}, []byte(msg))
}

func (d *PasswordAuthSMTPEmailSenderDelegate) SendLostPasswordLink(address, url string) error {
	msg := strings.Replace(d.LostPasswordEmailTemplate, "URL", d.baseURL+url, -1)
	return smtp.SendMail(d.SMTPAddr, d.smtpAuth, d.SiteEmail, []string{address}, []byte(msg))
}
