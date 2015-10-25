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
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"

	"github.com/manveru/faker"
	"github.com/naoina/toml"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/util"
	"github.com/tamasd/hitch-session"
)

//go:generate ab --generate-service-struct-name=testContentService --output=search_entity_test.go entity TestContent

const base = "http://localhost:9996"

var config testConfig

type testConfig struct {
	PGConnectString string
}

type TestContent struct {
	UUID    string `dbtype:"uuid" dbdefault:"uuid_generate_v4()" json:"uuid"`
	Owner   string `dbtype:"uuid" json:"owner"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

type testContentSearchServiceDelegate struct {
	db ab.DB
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
		log.Println(err)
		return []ab.Entity{}
	}

	ents := make([]ab.Entity, len(contents))
	for i, c := range contents {
		ents[i] = c
	}

	return ents
}

func setupServer() (ab.DB, *SearchService) {
	s := ab.PetBunny(ab.ServerConfig{
		CookieSecret:    session.SecretKey{161, 185, 93, 43, 42, 206, 51, 211, 53, 42, 189, 11, 238, 185, 174, 177, 101, 220, 127, 206, 220, 255, 69, 65, 85, 144, 126, 171, 98, 28, 109, 64, 177, 186, 89, 138, 116, 226, 219, 186, 164, 208, 49, 213, 180, 236, 184, 65, 211, 126, 182, 133, 98, 81, 148, 9, 205, 46, 242, 68, 205, 245, 221, 156},
		PGConnectString: config.PGConnectString,
		Logger:          log.New(ioutil.Discard, "", 0),
		AssetsDir:       "./",
	})

	s.RegisterService(&testContentService{})
	searchDelegate := &testContentSearchServiceDelegate{
		db: s.GetDBConnection(),
	}
	searchService := NewSearchService(s.GetDBConnection(), nil)
	searchService.AddDelegate("TestContent", searchDelegate)
	s.RegisterService(searchService)

	go s.StartHTTP("localhost:9996")

	return s.GetDBConnection(), searchService
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
			log.Fatalln(err)
		}

		if err = s.IndexEntity("TestContent", c); err != nil {
			log.Fatalln(err)
		}
	}
}

func TestMain(m *testing.M) {
	if _, err := os.Stat("test.toml"); err == nil {
		f, _ := os.Open("test.toml")
		toml.NewDecoder(f).Decode(&config)
		f.Close()
	}

	util.SetKey([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2})

	db, s := setupServer()

	http.DefaultClient.Jar, _ = cookiejar.New(nil)

	mockData(db, s)

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
