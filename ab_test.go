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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
)

type testDecode struct {
	A int
	B string
}

const base = "http://localhost:9999"

var ServerSetups []func(*viper.Viper, *Server) error

func TestMain(m *testing.M) {
	srv := &TestServer{
		AssetsDir: "./testing/",
		Addr:      "localhost:9999",
	}
	srv.StartAndCleanUp(m, func(cfg *viper.Viper, s *Server) error {
		for _, setup := range ServerSetups {
			if err := setup(cfg, s); err != nil {
				return err
			}
		}
		return nil
	})
}

func init() {
	ServerSetups = append(ServerSetups, func(cfg *viper.Viper, s *Server) error {
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

		svc := &testService{}
		s.RegisterService(svc)

		return nil
	})
}

var _ Service = &testService{}

type testService struct {
}

func (s *testService) Register(srv *Server) error {
	srv.Get("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	srv.Get("/test/:id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := GetParams(r).ByName("id")
		d := testDecode{}
		MaybeFail(r, http.StatusInternalServerError, GetDB(r).QueryRow("SELECT * FROM test WHERE a = $1", id).Scan(&d.A, &d.B))

		Render(r).JSON(d)
	}))

	srv.Post("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := testDecode{}
		MustDecode(r, &d)
		_, err := GetDB(r).Exec("INSERT INTO test(b) VALUES($1)", d.B)
		MaybeFail(r, http.StatusBadRequest, err)
		Render(r).SetCode(http.StatusCreated)
	}), TransactionMiddleware)

	srv.Put("/test/:id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(GetParams(r).ByName("id"))
		MaybeFail(r, http.StatusBadRequest, err)
		d := testDecode{}
		MustDecode(r, &d)
		if d.A != id {
			Fail(r, http.StatusBadRequest, fmt.Errorf("ids must match"))
		}

		res, err := GetDB(r).Exec("UPDATE test SET b = $1 WHERE a = $2", d.B, d.A)
		MaybeFail(r, http.StatusInternalServerError, err)
		aff, _ := res.RowsAffected()
		if aff == 0 {
			Fail(r, http.StatusNotFound, nil)
		}
	}), TransactionMiddleware)

	srv.Delete("/test/:id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := GetParams(r).ByName("id")
		res, err := GetDB(r).Exec("DELETE FROM test WHERE a = $1", id)
		MaybeFail(r, http.StatusInternalServerError, err)
		aff, _ := res.RowsAffected()
		if aff == 0 {
			Fail(r, http.StatusNotFound, nil)
		}
	}), TransactionMiddleware)

	return nil
}

func (s *testService) SchemaInstalled(db DB) bool {
	return TableExists(db, "test")
}

func (s *testService) SchemaSQL() string {
	return "CREATE TABLE test(a serial NOT NULL PRIMARY KEY, b text NOT NULL)"
}

func TestServiceCRUD(t *testing.T) {
	Convey("Given a simple service, loaded with sample content", t, func() {
		ct := []testDecode{
			testDecode{1, "a"},
			testDecode{2, "b"},
			testDecode{3, "c"},
			testDecode{4, "d"},
			testDecode{5, "e"},
		}

		tc := NewTestClientWithToken(base)

		for _, c := range ct {
			tc.Request("POST", "/test", tc.JSONBuffer(c), nil, nil, http.StatusCreated)
		}

		Convey("It should return all content", func() {
			tc.Request("GET", "/test", nil, nil, func(resp *http.Response) {
				tc.AssertJSON(resp, &[]testDecode{}, &ct)
			}, http.StatusOK)
		})
	})
}

func TestFrontendPath(t *testing.T) {
	Convey("Given a frontend path", t, func() {
		tc := NewTestClient(base)

		Convey("It should return the index.html file", func() {
			tc.Request("GET", "/frontend", nil, func(req *http.Request) {
				req.Header.Set("Accept", "text/html")
			}, func(resp *http.Response) {
				tc.AssertFile(resp, "testing/index.html")
			}, http.StatusOK)
		})
	})
}

func TestDecode(t *testing.T) {
	Convey("Given an endpoint which accepts JSON", t, func() {
		tc := NewTestClientWithToken(base)

		Convey("It should fail on invalid data", func() {
			buf := bytes.NewBuffer(nil)
			buf.WriteString("[<>?<<><]]]}}}}")
			tc.Request("POST", "/decode", buf, nil, nil, http.StatusBadRequest)
		})

		Convey("It should fail on invalid content type", func() {
			tc.Request("POST", "/decode", nil, func(req *http.Request) {
				req.Header.Set("Content-Type", "xxx/invalid")
			}, nil, http.StatusUnsupportedMediaType)
		})

		Convey("It should return the POST data", func() {
			data := testDecode{
				A: 65536,
				B: "asdf",
			}
			tc.Request("POST", "/decode", tc.JSONBuffer(data), nil, func(resp *http.Response) {
				tc.AssertJSON(resp, &testDecode{}, &data)
			}, http.StatusOK)
		})
	})
}

func TestError(t *testing.T) {
	Convey("Given a handler which panics", t, func() {
		tc := NewTestClient(base)
		Convey("It must return http.StatusInternalServerError", func() {
			tc.Request("GET", "/panic", nil, nil, nil, http.StatusInternalServerError)
		})
	})

	Convey("Given an endpoint which fails", t, func() {
		tc := NewTestClient(base)
		Convey("It should return http.StatusInternalServerError", func() {
			tc.Request("GET", "/fail", nil, nil, nil, http.StatusInternalServerError)
		})
	})
}

func TestCSRF(t *testing.T) {
	Convey("Given a simple server", t, func() {
		tc := NewTestClientWithToken(base)

		Convey("A request without token must return Forbidden", func() {
			tc.Request("POST", "/csrf", nil, func(req *http.Request) {
				req.Header.Del("X-CSRF-Token")
			}, nil, http.StatusForbidden)
		})

		Convey("A request with token should succeed", func() {
			tc.Request("POST", "/csrf", nil, nil, func(resp *http.Response) {
				So(tc.ReadBody(resp, false), ShouldEqual, "CSRF SUCCESS")
			}, http.StatusOK)
		})

		Convey("A GET request without token should fail", func() {
			tc.Request("GET", "/csrf", nil, nil, nil, http.StatusForbidden)
		})

		Convey("A GET request with token should succeed", func() {
			tc.Request("GET", "/csrf?token="+tc.Token, nil, nil, func(resp *http.Response) {
				So(tc.ReadBody(resp, false), ShouldEqual, "CSRF SUCCESS")
			}, http.StatusOK)
		})
	})
}

func TestBinary(t *testing.T) {
	Convey("Given a binary endpoint", t, func() {
		tc := NewTestClient(base)
		Convey("The response must be exactly the same as the file", func() {
			tc.Request("GET", "/binary", nil, nil, func(resp *http.Response) {
				tc.AssertFile(resp, "testing/binary.bin")
			}, http.StatusOK)
		})
	})
}

func TestEmptyEndpoint(t *testing.T) {
	Convey("Given an empty endpoint", t, func() {
		tc := NewTestClient(base)
		Convey("A request should return http.StatusNoContent", func() {
			tc.Request("GET", "/empty", nil, nil, nil, http.StatusNoContent)
		})
	})
}

func TestRestrictedEndpoint(t *testing.T) {
	Convey("Given restricted endpoints", t, func() {
		tc := NewTestClient(base)
		Convey("A request must return http.StatusServiceUnavailable with an invalid IP", func() {
			tc.Request("GET", "/restricted", nil, nil, nil, http.StatusServiceUnavailable)
		})

		Convey("A request must not return http.StatusServiceUnavailable with a valid IP", func() {
			tc.Request("GET", "/restrictedok", nil, nil, nil, http.StatusOK)
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
