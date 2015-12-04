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
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dgryski/dgoogauth"
	"github.com/lib/pq"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/util"
)

//go:generate abt --generate-service-struct-name=testUserService --output=password_entity_test.go entity TestUser

const base = "http://localhost:9997"
const pw = `VmlX7sn_+ti(BC{<'@8>]xHAhLN!p}w=vbBiHxNXv{_7#lfO|f(GAjF<::7=aw/]`

var hasDB = false

type TestUser struct {
	UUID string `dbtype:"uuid" dbdefault:"uuid_generate_v4()" json:"uuid"`
	Mail string `json:"mail"`
}

func setupServer() *viper.Viper {
	cfg := viper.New()
	cfg.SetConfigName("test")
	cfg.AddConfigPath(".")
	cfg.AutomaticEnv()
	cfg.ReadInConfig()
	cfg.Set("CookieSecret", "a1b95d2b2ace33d3352abd0beeb9aeb165dc7fcedcff454155907eab621c6d40b1ba598a74e2dbbaa4d031d5b4ecb841d37eb68562519409cd2ef244cdf5dd9c")
	cfg.Set("assetsDir", "./")

	hasDB = cfg.IsSet("PGConnectString")

	s, err := ab.PetBunny(cfg, nil, nil)
	if err != nil {
		panic(err)
	}

	pwprovider := NewPasswordAuthProvider(&pwDelegate{db: s.GetDBConnection()}, &mailDelegate{})

	userDelegate := &SessionUserDelegate{
		DB:         s.GetDBConnection(),
		TableName:  "testuser",
		UUIDColumn: "uuid",
	}
	authsvc := NewService(base, userDelegate, s.GetDBConnection(), pwprovider)

	s.RegisterService(authsvc)

	tus := &testUserService{}
	s.RegisterService(tus)

	s.Get("/me", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := ab.GetSession(r)
		ab.Render(r).Text(sess["uid"])
	}))

	go s.StartHTTP("localhost:9997")

	authsvc.StopCleanup()

	return cfg
}

func TestMain(m *testing.M) {
	util.SetKey([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2})

	cfg := setupServer()

	res := m.Run()

	connStr := cfg.GetString("PGConnectString")
	if connStr != "" {
		conn, _ := sql.Open("postgres", connStr)
		conn.Exec(`
			DROP SCHEMA public CASCADE;
			CREATE SCHEMA public;
			GRANT ALL ON SCHEMA public TO postgres;
			GRANT ALL ON SCHEMA public TO public;
			COMMENT ON SCHEMA public IS 'standard public schema';
		`)

		conn.Close()
	}

	os.Exit(res)
}

func TestRegistrationLogin(t *testing.T) {
	Convey("Given a user", t, func() {
		http.DefaultClient.Jar, _ = cookiejar.New(nil)
		token := getToken()
		mail := "ab@example.com"

		Convey("It should be able to register and log in", func() {
			uuid, code := assertRegister(token, mail, pw)
			assertVerifyEmail(uuid, code, token)
			assertLoggedIn(true)
			assertLogout(token)
			assertLoggedIn(false)
			token = getToken()
			assertLogin(token, mail, pw, false)
			assertLoggedIn(true)

			Convey("It should be able to add 2fa and login with it", func() {
				secret := assertGetAdd2fa(token)
				assertPostAdd2fa(token, secret)
				assertLogout(token)
				assertLoggedIn(false)
				token = getToken()
				assertLogin(token, mail, pw, true)
				assertLoggedIn(false)
				assert2faLogin(token, secret)
				assertLoggedIn(true)

				Convey("It should be able to disable 2fa", func() {
					assertDisable2fa(token, pw)
					assertLogout(token)
					assertLoggedIn(false)
					token = getToken()
					assertLogin(token, mail, pw, false)
					assertLoggedIn(true)
				})
			})
		})
	})
}

func TestPasswordChange(t *testing.T) {
	Convey("Given a registered user", t, func() {
		http.DefaultClient.Jar, _ = cookiejar.New(nil)
		token := getToken()
		mail := "abpwchg@example.com"
		pass := "asdf"
		uuid, code := assertRegister(token, mail, pass)
		assertVerifyEmail(uuid, code, token)
		assertLoggedIn(true)

		Convey("It should be able to change its password", func() {
			newpw := "foobar"
			assertChangePassword(token, pass, newpw)
			assertLogout(token)
			assertLoggedIn(false)
			token = getToken()
			assertLogin(token, mail, newpw, false)
			assertLoggedIn(true)
		})
	})
}

func TestLostPassword(t *testing.T) {
	Convey("Given a registered user", t, func() {
		http.DefaultClient.Jar, _ = cookiejar.New(nil)
		token := getToken()
		mail := "ablostpw@example.com"
		pass := "qwer"
		uuid, code := assertRegister(token, mail, pass)
		assertVerifyEmail(uuid, code, token)
		assertLoggedIn(true)
		assertLogout(token)
		assertLoggedIn(false)
		token = getToken()

		Convey("It should be able to log in and change its password", func() {
			uuid, code := assertLostPassword(token, mail)
			assertOTL(uuid, code)
			assertLoggedIn(true)
			assertChangePassword(token, "", pw)
			assertLogout(token)
			assertLoggedIn(false)
			token = getToken()
			assertLogin(token, mail, pw, false)
			assertLoggedIn(true)
		})
	})
}

func TestHash(t *testing.T) {
	Convey("Given a hash", t, func() {
		hash, err := defaultHashPassword(pw)
		So(err, ShouldBeNil)
		So(hash, ShouldNotEqual, "")

		Convey("It should match", func() {
			ok, err := verifyPassword(pw, hash)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("It should error if invalid algorithm", func() {
			parts := strings.Split(hash, "$")
			parts[0] = "asdf"
			ok, err := verifyPassword(pw, strings.Join(parts, "$"))
			So(err, ShouldNotBeNil)
			So(ok, ShouldBeFalse)
		})
	})
}

func TestOAuthCreds(t *testing.T) {
	Convey("An empty OAuthCredentials should be empty", t, func() {
		So(OAuthCredentials{}.Empty(), ShouldBeTrue)
	})
}

type regData struct {
	*TestUser
	PasswordFields
}

var _ PasswordAuthProviderDelegate = &pwDelegate{}

type pwDelegate struct {
	db ab.DB
}

func (pd *pwDelegate) GetPassword() Password {
	return &regData{
		TestUser:       EmptyTestUser(),
		PasswordFields: PasswordFields{},
	}
}

func (pd *pwDelegate) Get2FAIssuer() string {
	return "authtest"
}

func (pd *pwDelegate) GetAuthID(e ab.Entity) string {
	return pd.GetEmail(e)
}

func (pd *pwDelegate) GetEmail(e ab.Entity) string {
	return e.(*regData).Mail
}

func (pd *pwDelegate) GetDBErrorConverter() func(*pq.Error) ab.VerboseError {
	return func(err *pq.Error) ab.VerboseError {
		return ab.NewVerboseError(err.Error(), "")
	}
}

func (pd *pwDelegate) LoadUserByMail(mail string) (ab.Entity, error) {
	u := &TestUser{}
	err := pd.db.QueryRow("SELECT uuid, mail FROM testuser WHERE mail = $1", mail).Scan(&u.UUID, &u.Mail)
	return u, err
}

var _ PasswordAuthEmailSenderDelegate = &mailDelegate{}

type mailDelegate struct {
}

func (d *mailDelegate) sendMail(category, address, rawurl string) {
	mailQ.Lock()
	defer mailQ.Unlock()

	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}

	mailQ.mails = append(mailQ.mails, email{
		category: category,
		url:      u,
		address:  address,
	})
}

func (d *mailDelegate) SendRegistrationEmail(address, url string) error {
	d.sendMail("reg", address, url)
	return nil
}

func (d *mailDelegate) SendLostPasswordLink(address, url string) error {
	d.sendMail("lost", address, url)
	return nil
}

var mailQ = &emailQueue{}

type emailQueue struct {
	sync.Mutex
	mails []email
}

func (q *emailQueue) fetchMail(category, address string) []email {
	mails := []email{}

	q.Lock()
	defer q.Unlock()

	othermails := []email{}

	for _, m := range q.mails {
		if m.category == category && m.address == address {
			mails = append(mails, m)
		} else {
			othermails = append(othermails, m)
		}
	}

	q.mails = othermails

	return mails
}

type email struct {
	category string
	url      *url.URL
	address  string
}

func getToken() string {
	req, _ := http.NewRequest("GET", base+"/api/token", nil)
	req.Header.Add("Accept", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusOK)

	token := util.ResponseBodyToString(resp)
	So(token, ShouldNotEqual, "")

	cookieToken := ""
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "_CSRF" {
			cookieToken = cookie.Value
			break
		}
	}

	So(cookieToken, ShouldEqual, token)

	return token
}

func consumePrefix(r *http.Response) {
	prefix := make([]byte, 6)
	n, err := r.Body.Read(prefix)
	So(n, ShouldEqual, 6)
	So(err, ShouldBeNil)
	So(prefix, ShouldResemble, []byte(")]}',\n"))
}

func readBody(r *http.Response, hasPrefix bool) string {
	if hasPrefix {
		consumePrefix(r)
	}

	b, err := ioutil.ReadAll(r.Body)
	So(err, ShouldBeNil)

	return string(b)
}

func assertLoggedIn(loggedin bool) {
	req, _ := http.NewRequest("GET", base+"/me", nil)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusOK)
	body := readBody(resp, false)
	if loggedin {
		So(body, ShouldNotEqual, "")
	} else {
		So(body, ShouldEqual, "")
	}
}

func assertRegister(token, mail, pw string) (string, string) {
	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(struct {
		*TestUser
		PasswordFields
	}{
		TestUser: &TestUser{Mail: mail},
		PasswordFields: PasswordFields{
			Password:        pw,
			PasswordConfirm: pw,
		},
	})
	req, _ := http.NewRequest("POST", base+"/api/auth/password/register", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-Token", token)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusCreated)

	mails := mailQ.fetchMail("reg", mail)
	So(len(mails), ShouldEqual, 1)

	code := mails[0].url.Query().Get("code")
	uuid := mails[0].url.Query().Get("uuid")
	So(code, ShouldNotEqual, "")
	So(uuid, ShouldNotEqual, "")

	return uuid, code
}

func assertVerifyEmail(uuid, code, token string) {
	req, _ := http.NewRequest("GET", base+"/api/auth/password/verifyemail?token="+token+"&code="+code+"&uuid="+uuid, nil)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
}

func assertLogout(token string) {
	req, _ := http.NewRequest("GET", base+"/api/auth/logout?token="+token, nil)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
}

func assertLogin(token, mail, pw string, is2fa bool) {
	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(PasswordLoginData{
		Identifier: mail,
		Password:   pw,
	})
	req, _ := http.NewRequest("POST", base+"/api/auth/password/login", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-Token", token)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	if is2fa {
		So(resp.StatusCode, ShouldEqual, http.StatusAccepted)
	} else {
		So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
	}
}

func assert2faLogin(token, secret string) {
	buf := bytes.NewBuffer(nil)
	otpToken := calculateTOTP(secret)
	json.NewEncoder(buf).Encode(add2faData{
		Token: strconv.Itoa(otpToken),
	})
	req, _ := http.NewRequest("POST", base+"/api/auth/password/2fa", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-Token", token)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
}

func assertGetAdd2fa(token string) string {
	req, _ := http.NewRequest("GET", base+"/api/auth/password/add2fa?token="+token, nil)
	req.Header.Add("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusAccepted)
	d := map[string]string{}
	consumePrefix(resp)
	err = json.NewDecoder(resp.Body).Decode(&d)
	So(err, ShouldBeNil)
	secret := d["secret"]
	So(secret, ShouldNotEqual, "")
	So(d["image"], ShouldNotEqual, "")

	return secret
}

func assertPostAdd2fa(token, secret string) {
	buf := bytes.NewBuffer(nil)
	otpToken := calculateTOTP(secret)
	json.NewEncoder(buf).Encode(add2faData{
		Token: strconv.Itoa(otpToken),
	})
	req, _ := http.NewRequest("POST", base+"/api/auth/password/add2fa", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-Token", token)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusNoContent) // TODO sometimes this fail
}

func assertDisable2fa(token, pw string) {
	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(remove2faData{
		Password: pw,
	})
	req, _ := http.NewRequest("POST", base+"/api/auth/password/disable2fa", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-Token", token)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
}

func calculateTOTP(secret string) int {
	value := time.Now().Unix() / 30
	return dgoogauth.ComputeCode(secret, value)
}

func assertChangePassword(token, oldpw, newpw string) {
	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(PasswordChangeFields{
		PasswordFields: PasswordFields{
			Password:        newpw,
			PasswordConfirm: newpw,
		},
		OldPassword: oldpw,
	})
	req, _ := http.NewRequest("POST", base+"/api/auth/password/changepassword", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-Token", token)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
}

func assertLostPassword(token, mail string) (string, string) {
	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(lostPasswordData{
		Email: mail,
	})
	req, _ := http.NewRequest("POST", base+"/api/auth/password/lostpassword", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-Token", token)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusNoContent)

	mails := mailQ.fetchMail("lost", mail)
	So(len(mails), ShouldEqual, 1)

	code := mails[0].url.Query().Get("code")
	uuid := mails[0].url.Query().Get("uuid")
	So(code, ShouldNotEqual, "")
	So(uuid, ShouldNotEqual, "")

	return uuid, code
}

func assertOTL(uuid, code string) {
	req, _ := http.NewRequest("GET", base+"/api/auth/password/onetimelogin?code="+code+"&uuid="+uuid, nil)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
}
