// Copyright 2016 Tamás Demeter-Haludka
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
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/util"
)

type TestServer struct {
	ConfigName string
	AssetsDir  string
	Addr       string
}

func (s *TestServer) StartAndCleanUp(m *testing.M, setup func(cfg *viper.Viper, s *Server) error) {
	util.SetKey([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2})

	cfg := s.Start(setup)

	res := m.Run()

	connStr := cfg.GetString("db")
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

func (s *TestServer) Start(setup func(cfg *viper.Viper, s *Server) error) *viper.Viper {
	if s.ConfigName == "" {
		s.ConfigName = "test"
	}
	if s.AssetsDir == "" {
		s.AssetsDir = "./"
	}
	if s.Addr == "" {
		s.Addr = "localhost:9999"
	}

	cfg := viper.New()
	cfg.SetConfigName(s.ConfigName)
	cfg.AddConfigPath(".")
	cfg.AutomaticEnv()
	cfg.ReadInConfig()
	cfg.Set("CookieSecret", genSecret())
	cfg.Set("assetsDir", s.AssetsDir)

	srv, err := PetBunny(cfg, log.DefaultLogger(ioutil.Discard))
	if err != nil {
		panic(err)
	}

	if setup != nil {
		if err := setup(cfg, srv); err != nil {
			panic(err)
		}
	}

	go srv.StartHTTP(s.Addr)

	return cfg
}

func genSecret() string {
	buf := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

type TestClient struct {
	Client *http.Client
	Token  string
	base   string
}

func NewTestClient(base string) *TestClient {
	c := &http.Client{}
	c.Jar, _ = cookiejar.New(nil)

	return &TestClient{
		Client: c,
		base:   base,
	}
}

func NewTestClientWithToken(base string) *TestClient {
	c := NewTestClient(base)
	c.GetToken()
	return c
}

func (tc *TestClient) Request(method, endpoint string, body io.Reader, processReq func(*http.Request), processResp func(*http.Response), statusCode int) {
	req, _ := http.NewRequest(method, tc.base+endpoint, body)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if tc.Token != "" {
		req.Header.Set("X-CSRF-Token", tc.Token)
	}
	if processReq != nil {
		processReq(req)
	}

	resp, err := tc.Client.Do(req)
	So(err, ShouldBeNil)
	defer resp.Body.Close()
	So(resp.StatusCode, ShouldEqual, statusCode)
	if processResp != nil {
		processResp(resp)
	}
}

func (tc *TestClient) JSONBuffer(v interface{}) io.Reader {
	buf := bytes.NewBuffer(nil)
	So(json.NewEncoder(buf).Encode(v), ShouldBeNil)
	return buf
}

func (tc *TestClient) AssertJSON(resp *http.Response, v, d interface{}) {
	tc.ConsumePrefix(resp)
	So(json.NewDecoder(resp.Body).Decode(v), ShouldBeNil)
	So(v, ShouldResemble, d)
}

func (tc *TestClient) AssertFile(resp *http.Response, path string) {
	body, err := ioutil.ReadAll(resp.Body)
	So(err, ShouldBeNil)

	file, err := ioutil.ReadFile(path)
	So(err, ShouldBeNil)

	So(body, ShouldResemble, file)
}

func (tc *TestClient) GetToken() {
	tc.Request("GET", "/api/token", nil, func(req *http.Request) {
		req.Header.Set("Accept", "text/plain")
	}, func(resp *http.Response) {
		token := tc.ReadBody(resp, false)
		So(token, ShouldNotEqual, "")

		cookieToken := ""
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "_CSRF" {
				cookieToken = cookie.Value
				break
			}
		}

		So(cookieToken, ShouldEqual, token)

		tc.Token = token
	}, http.StatusOK)
}

func (tc *TestClient) ConsumePrefix(r *http.Response) bool {
	prefix := make([]byte, 6)
	_, err := io.ReadFull(r.Body, prefix)
	So(err, ShouldBeNil)
	return string(prefix) == ")]}',\n"
}

func (tc *TestClient) ReadBody(r *http.Response, JSONPrefix bool) string {
	if JSONPrefix {
		So(tc.ConsumePrefix(r), ShouldBeTrue)
	}

	b, err := ioutil.ReadAll(r.Body)
	So(err, ShouldBeNil)

	return string(b)
}
