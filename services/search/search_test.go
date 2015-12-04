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

package search

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"

	"github.com/manveru/faker"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/util"
)

//go:generate abt --generate-service-struct-name=testContentService --output=search_entity_test.go entity TestContent

const base = "http://localhost:9996"

type TestContent struct {
	UUID    string `dbtype:"uuid" dbdefault:"uuid_generate_v4()" json:"uuid"`
	Owner   string `dbtype:"uuid" json:"owner"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

type testContentSearchServiceDelegate struct {
	db     ab.DB
	logger *log.Log
}

func (t *testContentSearchServiceDelegate) IndexEntity(entity ab.Entity) []IndexData {
	data := []IndexData{}
	c := entity.(*TestContent)

	data = append(data, IndexDataFromText("en", c.Title, 0.7, "")...)
	data = append(data, IndexDataFromText("en", c.Content, 0.5, "")...)

	return data
}

func (t *testContentSearchServiceDelegate) LoadEntities(uuids []string) []ab.Entity {
	contents, err := selectTestContentFromQuery(t.db, "SELECT "+testcontentFields+" FROM testcontent t WHERE uuid IN ("+util.GeneratePlaceholders(1, uint(len(uuids))+1)+")", util.StringSliceToInterfaceSlice(uuids)...)
	if err != nil {
		t.logger.User().Println(err)
		return []ab.Entity{}
	}

	ents := make([]ab.Entity, len(contents))
	for i, c := range contents {
		ents[i] = c
	}

	return ents
}

func setupServer() (ab.DB, *SearchService, *viper.Viper) {
	cfg := viper.New()
	cfg.SetConfigName("test")
	cfg.AddConfigPath(".")
	cfg.AutomaticEnv()
	cfg.ReadInConfig()
	cfg.Set("CookieSecret", "a1b95d2b2ace33d3352abd0beeb9aeb165dc7fcedcff454155907eab621c6d40b1ba598a74e2dbbaa4d031d5b4ecb841d37eb68562519409cd2ef244cdf5dd9c")
	cfg.Set("assetsDir", "./")

	s, err := ab.PetBunny(cfg, nil, nil)
	if err != nil {
		panic(err)
	}

	s.RegisterService(&testContentService{})
	searchDelegate := &testContentSearchServiceDelegate{
		logger: log.DefaultOSLogger(),
		db:     s.GetDBConnection(),
	}
	searchService := NewSearchService(s.GetDBConnection(), nil)
	searchService.AddDelegate("TestContent", searchDelegate)
	s.RegisterService(searchService)

	go s.StartHTTP("localhost:9996")

	return s.GetDBConnection(), searchService, cfg
}

var words []string

func mockData(db ab.DB, s *SearchService) {
	f, err := faker.New("en")
	if err != nil {
		panic(err)
	}

	for i := 0; i < 100; i++ {
		c := &TestContent{
			Owner:   "00000000-0000-0000-0000-000000000000",
			Title:   f.Name(),
			Content: strings.Join(f.Paragraphs(rand.Intn(12)+8, true), "\n\n"),
		}

		tw := TextToStemmedWords("en", c.Title)
		cw := TextToStemmedWords("en", c.Content)
		words = append(words, tw[rand.Intn(len(tw))], cw[rand.Intn(len(cw))])

		if err = c.Insert(db); err != nil {
			panic(err)
		}

		if err = s.IndexEntity("TestContent", c); err != nil {
			panic(err)
		}
	}
}

func TestMain(m *testing.M) {
	util.SetKey([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2})

	db, s, cfg := setupServer()

	http.DefaultClient.Jar, _ = cookiejar.New(nil)

	mockData(db, s)

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

func TestSearch(t *testing.T) {
	Convey("A search should return a result", t, func() {
		keywords := ""
		numWords := rand.Intn(4) + 2
		for i := 0; i < numWords; i++ {
			keywords += words[rand.Intn(len(words))] + " "
		}
		token := getToken()

		search(token, keywords)
	})
}

func search(token, keywords string) {
	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(SearchPostData{
		Search: keywords,
		Owners: []string{"00000000-0000-0000-0000-000000000000"},
	})
	req, _ := http.NewRequest("POST", base+"/api/search", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-Token", token)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusOK)
	consumePrefix(resp)
	res := []struct {
		Entity TestContent `json:"entity"`
		Type   string      `json:"type"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	So(err, ShouldBeNil)
	So(len(res), ShouldNotEqual, 0)
}

func consumePrefix(r *http.Response) {
	prefix := make([]byte, 6)
	n, err := r.Body.Read(prefix)
	So(n, ShouldEqual, 6)
	So(err, ShouldBeNil)
	So(prefix, ShouldResemble, []byte(")]}',\n"))
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
