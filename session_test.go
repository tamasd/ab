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

package ab

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/tamasd/ab/lib/log"
	"golang.org/x/net/publicsuffix"
)

func getSecretKey() SecretKey {
	buf := make([]byte, 32)
	rand.Read(buf)

	return SecretKey(buf)
}

func randomString(length int) string {
	buf := make([]byte, length)
	rand.Read(buf)

	return hex.EncodeToString(buf)
}

func getBody(body io.ReadCloser) string {
	data, err := ioutil.ReadAll(body)
	So(err, ShouldBeNil)

	return string(data)
}

func TestEncDec(t *testing.T) {
	Convey("Tests encoding and decoding the cookie data", t, func() {
		key := getSecretKey()
		sess := Session{}
		sess["foo"] = "bar"
		sess["bar"] = "baz"

		c := sess.cookie(key, "", nil, time.Hour)

		data := c.Value

		s, err := readCookie(data, key)
		So(err, ShouldBeNil)
		So(s, ShouldResemble, sess)
	})
}

func TestHTTPScenario(t *testing.T) {
	Convey("Given a simple HTTP scenario", t, func() {
		key := getSecretKey()

		srv := NewServer(nil)
		srv.Use(DefaultLoggerMiddleware(log.LOG_OFF))
		srv.Use(SessionMiddleware("", key, nil, time.Hour))
		srv.Post("/set", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := ioutil.ReadAll(r.Body)

			s := GetSession(r)
			s["data"] = string(data)
		}))
		srv.Get("/get", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := GetSession(r)
			io.WriteString(w, s["data"])
		}))
		srv.Get("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := GetSession(r)
			io.WriteString(w, s.Id())
		}))

		go http.ListenAndServe("localhost:31337", srv.Handler())
		<-time.After(time.Second)

		jar, _ := cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})
		baseURL := "http://localhost:31337"
		c := &http.Client{
			Jar: jar,
		}

		data := randomString(128)

		Convey("A session ID should be created", func() {
			r, err := c.Get(baseURL + "/")
			So(err, ShouldBeNil)
			sid := getBody(r.Body)

			Convey("And that session ID should be the same over different requests", func() {
				r, err := c.Get(baseURL + "/")
				So(err, ShouldBeNil)
				So(getBody(r.Body), ShouldEqual, sid)
			})
		})

		Convey("When a request is made to the post endpoint", func() {
			_, err := c.Post(baseURL+"/set", "text/plain", strings.NewReader(data))
			So(err, ShouldBeNil)

			Convey("The result at the get endpoint should match it", func() {
				r, err := c.Get(baseURL + "/get")
				So(err, ShouldBeNil)

				So(getBody(r.Body), ShouldEqual, data)
			})
		})
	})
}
