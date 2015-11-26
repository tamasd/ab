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

	"github.com/naoina/toml"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/util"
)

const base = "http://localhost:9988"

var hasDB = false

type testConfig struct {
	PGConnectString string
}

func setupServer(c testConfig) {
	s := ab.PetBunny(ab.ServerConfig{
		CookieSecret:    ab.SecretKey{161, 185, 93, 43, 42, 206, 51, 211, 53, 42, 189, 11, 238, 185, 174, 177, 101, 220, 127, 206, 220, 255, 69, 65, 85, 144, 126, 171, 98, 28, 109, 64, 177, 186, 89, 138, 116, 226, 219, 186, 164, 208, 49, 213, 180, 236, 184, 65, 211, 126, 182, 133, 98, 81, 148, 9, 205, 46, 242, 68, 205, 245, 221, 156},
		PGConnectString: c.PGConnectString,
		AssetsDir:       "./",
	})

	s.RegisterService(&Service{})
	s.RegisterService(&Service2{})

	http.DefaultClient.Jar, _ = cookiejar.New(nil)

	go s.StartHTTP("localhost:9988")
}

func TestMain(m *testing.M) {
	c := testConfig{}

	if _, err := os.Stat("test.toml"); err == nil {
		f, _ := os.Open("test.toml")
		toml.NewDecoder(f).Decode(&c)
		f.Close()
	}

	hasDB = c.PGConnectString != ""

	setupServer(c)

	res := m.Run()

	if c.PGConnectString != "" {
		conn, _ := sql.Open("postgres", c.PGConnectString)
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
