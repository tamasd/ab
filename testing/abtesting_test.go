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

package abtesting

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/util"
)

const base = "http://localhost:9988"

var hasDB = false

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

	s.RegisterService(&Service{})
	s.RegisterService(&Service2{})

	http.DefaultClient.Jar, _ = cookiejar.New(nil)

	go s.StartHTTP("localhost:9988")

	return cfg
}

func TestMain(m *testing.M) {
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

func getToken() string {
	req, _ := http.NewRequest("GET", base+"/api/token", nil)
	req.Header.Add("Accept", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusOK)

	token := util.ResponseBodyToString(resp)
	So(token, ShouldNotEqual, "")

	return token
}

func consumePrefix(r *http.Response) {
	prefix := make([]byte, 6)
	n, err := r.Body.Read(prefix)
	So(n, ShouldEqual, 6)
	So(err, ShouldBeNil)
	So(prefix, ShouldResemble, []byte(")]}',\n"))
}

func TestCRUD(t *testing.T) {
	Convey("Given a test entity service", t, func() {
		token := getToken()

		Convey("It should save an entity", func() {
			t := NewTest(new(string), new(string))
			*t.Name = "name"
			*t.Mail = "mail@example.com"
			buf := bytes.NewBuffer(nil)
			So(json.NewEncoder(buf).Encode(t), ShouldBeNil)
			req, _ := http.NewRequest("POST", base+"/api/test", buf)
			req.Header.Add("X-CSRF-Token", token)
			req.Header.Add("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusCreated)

			tc := &Test{}
			consumePrefix(resp)
			So(json.NewDecoder(resp.Body).Decode(tc), ShouldBeNil)
			So(tc.UUID, ShouldNotBeNil)
			So(*tc.UUID, ShouldNotEqual, "")

			Convey("It should find the entity", func() {
				resp, err := http.Get(base + "/api/test/" + *tc.UUID)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				tl := EmptyTest()
				consumePrefix(resp)
				So(json.NewDecoder(resp.Body).Decode(tl), ShouldBeNil)
				So(tl, ShouldResemble, tc)

				Convey("It should be the only entity in the listing", func() {
					resp, err := http.Get(base + "/api/test")
					So(err, ShouldBeNil)
					So(resp.StatusCode, ShouldEqual, http.StatusOK)
					tl := []*Test{}
					consumePrefix(resp)
					So(json.NewDecoder(resp.Body).Decode(&tl), ShouldBeNil)
					So(len(tl), ShouldEqual, 1)
					So(tl[0], ShouldResemble, tc)

					Convey("It should be edited", func() {
						*tc.Bio = "asdf"
						buf := bytes.NewBuffer(nil)
						So(json.NewEncoder(buf).Encode(tc), ShouldBeNil)
						req, _ := http.NewRequest("PUT", base+"/api/test/"+*tc.UUID, buf)
						req.Header.Add("X-CSRF-Token", token)
						req.Header.Add("Content-Type", "application/json")
						resp, err := http.DefaultClient.Do(req)
						So(err, ShouldBeNil)
						So(resp.StatusCode, ShouldEqual, http.StatusOK)
						tec := &Test{}
						consumePrefix(resp)
						So(json.NewDecoder(resp.Body).Decode(tec), ShouldBeNil)
						So(tec, ShouldResemble, tc)

						Convey("The edit should be saved", func() {
							resp, err := http.Get(base + "/api/test/" + *tc.UUID)
							So(err, ShouldBeNil)
							So(resp.StatusCode, ShouldEqual, http.StatusOK)
							tu := EmptyTest()
							consumePrefix(resp)
							So(json.NewDecoder(resp.Body).Decode(tu), ShouldBeNil)
							So(tu, ShouldResemble, tc)

							Convey("It should be deleted", func() {
								req, _ := http.NewRequest("DELETE", base+"/api/test/"+*tc.UUID, nil)
								req.Header.Add("X-CSRF-Token", token)
								resp, err := http.DefaultClient.Do(req)
								So(err, ShouldBeNil)
								So(resp.StatusCode, ShouldEqual, http.StatusNoContent)

								Convey("The content listing should be empty", func() {
									resp, err := http.Get(base + "/api/test")
									So(err, ShouldBeNil)
									So(resp.StatusCode, ShouldEqual, http.StatusOK)
									tl := []*Test{}
									consumePrefix(resp)
									So(json.NewDecoder(resp.Body).Decode(&tl), ShouldBeNil)
									So(len(tl), ShouldEqual, 0)
								})
							})
						})
					})
				})
			})
		})

		Convey("It should return http.StatusNotFound on an invalid id", func() {
			resp, err := http.Get(base + "/api/test/3715408b-3156-415c-aff4-0e05b1c1b67e")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})
	})
}

func TestCRUD2(t *testing.T) {
	Convey("Given a test entity service", t, func() {
		token := getToken()

		Convey("It should save an entity", func() {
			t := NewTest2("", "")
			t.Name = "name"
			t.Mail = "mail@example.com"
			buf := bytes.NewBuffer(nil)
			So(json.NewEncoder(buf).Encode(t), ShouldBeNil)
			req, _ := http.NewRequest("POST", base+"/api/test2", buf)
			req.Header.Add("X-CSRF-Token", token)
			req.Header.Add("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusCreated)

			tc := &Test2{}
			consumePrefix(resp)
			So(json.NewDecoder(resp.Body).Decode(tc), ShouldBeNil)
			So(tc.UUID, ShouldNotBeNil)
			So(tc.UUID, ShouldNotEqual, "")

			Convey("It should find the entity", func() {
				resp, err := http.Get(base + "/api/test2/" + tc.UUID)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				tl := EmptyTest2()
				consumePrefix(resp)
				So(json.NewDecoder(resp.Body).Decode(tl), ShouldBeNil)
				So(tl, ShouldResemble, tc)

				Convey("It should be the only entity in the listing", func() {
					resp, err := http.Get(base + "/api/test2")
					So(err, ShouldBeNil)
					So(resp.StatusCode, ShouldEqual, http.StatusOK)
					tl := []*Test2{}
					consumePrefix(resp)
					So(json.NewDecoder(resp.Body).Decode(&tl), ShouldBeNil)
					So(len(tl), ShouldEqual, 1)
					So(tl[0], ShouldResemble, tc)

					Convey("It should be edited", func() {
						tc.Bio = "asdf"
						buf := bytes.NewBuffer(nil)
						So(json.NewEncoder(buf).Encode(tc), ShouldBeNil)
						req, _ := http.NewRequest("PUT", base+"/api/test2/"+tc.UUID, buf)
						req.Header.Add("X-CSRF-Token", token)
						req.Header.Add("Content-Type", "application/json")
						resp, err := http.DefaultClient.Do(req)
						So(err, ShouldBeNil)
						So(resp.StatusCode, ShouldEqual, http.StatusOK)
						tec := EmptyTest2()
						consumePrefix(resp)
						So(json.NewDecoder(resp.Body).Decode(tec), ShouldBeNil)
						So(tec, ShouldResemble, tc)

						Convey("The edit should be saved", func() {
							resp, err := http.Get(base + "/api/test2/" + tc.UUID)
							So(err, ShouldBeNil)
							So(resp.StatusCode, ShouldEqual, http.StatusOK)
							tu := EmptyTest2()
							consumePrefix(resp)
							So(json.NewDecoder(resp.Body).Decode(tu), ShouldBeNil)
							So(tu, ShouldResemble, tc)

							Convey("It should be deleted", func() {
								req, _ := http.NewRequest("DELETE", base+"/api/test2/"+tc.UUID, nil)
								req.Header.Add("X-CSRF-Token", token)
								resp, err := http.DefaultClient.Do(req)
								So(err, ShouldBeNil)
								So(resp.StatusCode, ShouldEqual, http.StatusNoContent)

								Convey("The content listing should be empty", func() {
									resp, err := http.Get(base + "/api/test2")
									So(err, ShouldBeNil)
									So(resp.StatusCode, ShouldEqual, http.StatusOK)
									tl := []*Test{}
									consumePrefix(resp)
									So(json.NewDecoder(resp.Body).Decode(&tl), ShouldBeNil)
									So(len(tl), ShouldEqual, 0)
								})
							})
						})
					})
				})
			})
		})

		Convey("It should return http.StatusNotFound on an invalid id", func() {
			resp, err := http.Get(base + "/api/test2/3715408b-3156-415c-aff4-0e05b1c1b67e")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})
	})
}
