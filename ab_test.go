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
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"testing"

	"github.com/naoina/toml"
	"github.com/nbio/hitch"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/tamasd/ab/util"
	"github.com/tamasd/hitch-session"
)

const base = "http://localhost:9999"

var hasDB = false

var config testConfig

type testDecode struct {
	A int
	B string
}

type testConfig struct {
	PGConnectString string
}

var _ Service = &testService{}

type testService struct {
}

func (s *testService) Register(h *hitch.Hitch) error {
	h.Get("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := GetDB(r).Query("SELECT * FROM test ORDER BY a")
		MaybeFail(r, http.StatusInternalServerError, err)
		ret := []testDecode{}
		for rows.Next() {
			d := testDecode{}
			rows.Scan(&d.A, &d.B)
			ret = append(ret, d)
		}

		Render(r).JSON(ret)
	}))

	h.Get("/test/:id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := hitch.Params(r).ByName("id")
		d := testDecode{}
		MaybeFail(r, http.StatusInternalServerError, GetDB(r).QueryRow("SELECT * FROM test WHERE a = $1", id).Scan(&d.A, &d.B))

		Render(r).JSON(d)
	}))

	h.Post("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := testDecode{}
		MustDecode(r, &d)
		_, err := GetTransaction(r).Exec("INSERT INTO test(b) VALUES($1)", d.B)
		MaybeFail(r, http.StatusBadRequest, err)
		Render(r).SetCode(http.StatusCreated)
	}))

	h.Put("/test/:id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(hitch.Params(r).ByName("id"))
		MaybeFail(r, http.StatusBadRequest, err)
		d := testDecode{}
		MustDecode(r, &d)
		if d.A != id {
			Fail(r, http.StatusBadRequest, fmt.Errorf("ids must match"))
		}

		res, err := GetTransaction(r).Exec("UPDATE test SET b = $1 WHERE a = $2", d.B, d.A)
		MaybeFail(r, http.StatusInternalServerError, err)
		aff, _ := res.RowsAffected()
		if aff == 0 {
			Fail(r, http.StatusNotFound, nil)
		}
	}))

	h.Delete("/test/:id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := hitch.Params(r).ByName("id")
		res, err := GetTransaction(r).Exec("DELETE FROM test WHERE a = $1", id)
		MaybeFail(r, http.StatusInternalServerError, err)
		aff, _ := res.RowsAffected()
		if aff == 0 {
			Fail(r, http.StatusNotFound, nil)
		}
	}))

	return nil
}

func (s *testService) SchemaInstalled(db DB) bool {
	return TableExists(db, "test")
}

func (s *testService) SchemaSQL() string {
	return "CREATE TABLE test(a serial NOT NULL PRIMARY KEY, b text NOT NULL)"
}

func setupServer(c testConfig) {
	s := PetBunny(ServerConfig{
		CookieSecret:    session.SecretKey{161, 185, 93, 43, 42, 206, 51, 211, 53, 42, 189, 11, 238, 185, 174, 177, 101, 220, 127, 206, 220, 255, 69, 65, 85, 144, 126, 171, 98, 28, 109, 64, 177, 186, 89, 138, 116, 226, 219, 186, 164, 208, 49, 213, 180, 236, 184, 65, 211, 126, 182, 133, 98, 81, 148, 9, 205, 46, 242, 68, 205, 245, 221, 156},
		PGConnectString: c.PGConnectString,
		Logger:          log.New(ioutil.Discard, "", 0),
		AssetsDir:       "testing/",
	})
	s.AddFile("/frontend", "testing/index.html")

	s.Get("/csrf", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Render(r).Text("CSRF SUCCESS")
	}), CSRFGetMiddleware("token"))
	s.Post("/csrf", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Render(r).Text("CSRF SUCCESS")
	}))

	s.Get("/empty", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	s.Get("/restricted", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Render(r).Text("RESTRICTED")
	}), RestrictAddressMiddleware("192.168.255.255/8"))

	s.Get("/restrictedok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Render(r).Text("RestrictedOK")
	}), RestrictAddressMiddleware("127.0.0.1/8"))

	s.Post("/decode", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := testDecode{}
		MustDecode(r, &v)

		Render(r).JSON(v)
	}))

	s.Get("/panic", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("oops")
	}))

	s.Get("/fail", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		MaybeFail(r, http.StatusInternalServerError, errors.New("oops"))
	}))

	buf1k := make([]byte, 512)
	io.ReadFull(rand.Reader, buf1k)
	hex1k := hex.EncodeToString(buf1k)
	s.Get("/1k", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Render(r).Text(hex1k)
	}))

	s.Get("/binary", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, err := os.Open("testing/binary.bin")
		MaybeFail(r, http.StatusInternalServerError, err)
		Render(r).Binary("application/octet-stream", "binary.bin", file)
	}))

	http.DefaultClient.Jar, _ = cookiejar.New(nil)

	svc := &testService{}
	s.RegisterService(svc)

	go s.StartHTTP("localhost:9999")
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Lshortfile)

	if _, err := os.Stat("test.toml"); err == nil {
		f, _ := os.Open("test.toml")
		toml.NewDecoder(f).Decode(&config)
		f.Close()
	}

	hasDB = config.PGConnectString != ""

	setupServer(config)

	res := m.Run()

	if config.PGConnectString != "" {
		conn, _ := sql.Open("postgres", config.PGConnectString)
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

func TestServiceCRUD(t *testing.T) {
	if !hasDB {
		t.SkipNow()
	}

	Convey("Given a simple service, loaded with sample content", t, func() {
		token := getToken()

		ct := []testDecode{
			testDecode{1, "a"},
			testDecode{2, "b"},
			testDecode{3, "c"},
			testDecode{4, "d"},
			testDecode{5, "e"},
		}

		for _, c := range ct {
			buf := bytes.NewBuffer(nil)
			So(json.NewEncoder(buf).Encode(c), ShouldBeNil)
			req, _ := http.NewRequest("POST", base+"/test", buf)
			req.Header.Add("X-CSRF-Token", token)
			req.Header.Add("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusCreated)
		}

		Convey("It should return all content", func() {
			data := []testDecode{}
			resp, err := http.Get(base + "/test")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			consumePrefix(resp)
			So(json.NewDecoder(resp.Body).Decode(&data), ShouldBeNil)
			So(data, ShouldResemble, ct)
		})
	})
}

func TestFrontendPath(t *testing.T) {
	Convey("Given a frontend path", t, func() {
		data, err := ioutil.ReadFile("testing/index.html")
		datastr := string(data)
		So(err, ShouldBeNil)

		Convey("It should return the index.html file", func() {
			resp, err := http.Get(base + "/frontend")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			respdata, err := ioutil.ReadAll(resp.Body)
			respdatastr := string(respdata)
			So(err, ShouldBeNil)
			So(respdatastr, ShouldResemble, datastr)
		})
	})
}

func TestDecode(t *testing.T) {
	Convey("Given an endpoint which accepts JSON", t, func() {
		token := getToken()

		Convey("It should fail on invalid data", func() {
			buf := bytes.NewBuffer(nil)
			buf.WriteString("[<>?<<><]]]}}}}")
			req, _ := http.NewRequest("POST", base+"/decode", buf)
			req.Header.Add("X-CSRF-Token", token)
			req.Header.Add("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("It should fail on invalid content type", func() {
			req, _ := http.NewRequest("POST", base+"/decode", nil)
			req.Header.Add("X-CSRF-Token", token)
			req.Header.Add("Content-Type", "xxx/invalid")
			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusUnsupportedMediaType)
		})

		Convey("It should return the POST data", func() {
			data := testDecode{
				A: 65536,
				B: "asdf",
			}
			buf := bytes.NewBuffer(nil)
			So(json.NewEncoder(buf).Encode(data), ShouldBeNil)
			req, _ := http.NewRequest("POST", base+"/decode", buf)
			req.Header.Add("X-CSRF-Token", token)
			req.Header.Add("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			consumePrefix(resp)
			respData := testDecode{}
			So(json.NewDecoder(resp.Body).Decode(&respData), ShouldBeNil)
			So(respData, ShouldResemble, data)
		})
	})
}

func TestError(t *testing.T) {
	Convey("Given a handler which panics", t, func() {
		Convey("It must return http.StatusInternalServerError", func() {
			resp, err := http.Get(base + "/panic")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})
	})

	Convey("Given an endpoint which fails", t, func() {
		Convey("It should return http.StatusInternalServerError", func() {
			resp, err := http.Get(base + "/fail")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})
	})
}

func TestCSRF(t *testing.T) {
	Convey("Given a simple server", t, func() {
		Convey("A request without token must return Forbidden", func() {
			resp, err := http.PostForm(base+"/csrf", nil)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusForbidden)
		})

		Convey("A request with token should succeed", func() {
			token := getToken()

			req, _ := http.NewRequest("POST", base+"/csrf", nil)
			req.Header.Add("X-CSRF-Token", token)
			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			data := util.ResponseBodyToString(resp)
			So(data, ShouldEqual, "CSRF SUCCESS")
		})

		Convey("A GET request without token should fail", func() {
			resp, err := http.Get(base + "/csrf")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusForbidden)
		})

		Convey("A GET request with token should succeed", func() {
			token := getToken()

			resp, err := http.Get(base + "/csrf?token=" + token)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			data := util.ResponseBodyToString(resp)
			So(data, ShouldEqual, "CSRF SUCCESS")
		})
	})
}

func TestBinary(t *testing.T) {
	Convey("Given a simple server", t, func() {
		resp, err := http.Get(base + "/binary")
		So(err, ShouldBeNil)
		So(resp.StatusCode, ShouldEqual, http.StatusOK)

		file, err := ioutil.ReadFile("testing/binary.bin")
		So(err, ShouldBeNil)

		recv, err := ioutil.ReadAll(resp.Body)
		So(err, ShouldBeNil)
		So(recv, ShouldResemble, file)
	})
}

func TestEmptyEndpoint(t *testing.T) {
	Convey("Given an empty endpoint", t, func() {
		Convey("A request should return http.StatusNoContent", func() {
			resp, err := http.Get(base + "/empty")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
		})
	})
}

func TestRestrictedEndpoint(t *testing.T) {
	Convey("Given restricted endpoints", t, func() {
		Convey("A request must return http.StatusServiceUnavailable with an invalid IP", func() {
			resp, err := http.Get(base + "/restricted")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusServiceUnavailable)
		})

		Convey("A request must not return http.StatusServiceUnavailable with a valid IP", func() {
			resp, err := http.Get(base + "/restrictedok")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
		})
	})
}

func BenchmarkEmpty(b *testing.B) {
	req, _ := http.NewRequest("GET", base+"/", nil)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			http.DefaultClient.Do(req)
		}
	})
}

func Benchmark1k(b *testing.B) {
	req, _ := http.NewRequest("GET", base+"/1k", nil)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, _ := http.DefaultClient.Do(req)
			ioutil.ReadAll(resp.Body)
			resp.Body.Close()
		}
	})
}
