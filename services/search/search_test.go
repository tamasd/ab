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
	"encoding/json"
	"math/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/manveru/faker"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/util"
)

const base = "http://localhost:9996"

type testContentSearchResult struct {
	Entity TestContent `json:"entity"`
	Type   string      `json:"type"`
}

type TestContent struct {
	UUID    string `dbtype:"uuid" dbdefault:"uuid_generate_v4()" json:"uuid"`
	Owner   string `dbtype:"uuid" json:"owner"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

func (tc *TestContent) GetID() string {
	return tc.UUID
}

type testContentSearchServiceDelegate struct {
	db     ab.DB
	logger *log.Log
	ec     *ab.EntityController
}

func (t *testContentSearchServiceDelegate) IndexEntity(entity ab.Entity) []IndexData {
	data := []IndexData{}
	c := entity.(*TestContent)

	data = append(data, IndexDataFromText("en", c.Title, 0.7, "")...)
	data = append(data, IndexDataFromText("en", c.Content, 0.5, "")...)

	return data
}

func (t *testContentSearchServiceDelegate) LoadEntities(uuids []string) []ab.Entity {
	contents, err := t.ec.LoadFromQuery(nil, "testcontent", "SELECT "+t.ec.FieldList("testcontent")+" FROM testcontent t WHERE uuid IN ("+util.GeneratePlaceholders(1, uint(len(uuids))+1)+")", util.StringSliceToInterfaceSlice(uuids)...)
	if err != nil {
		t.logger.User().Println(err)
		return []ab.Entity{}
	}

	return contents
}

var words []string

func mockData(db ab.DB, ec *ab.EntityController, s *SearchService) {
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

		if err = ec.Insert(nil, c); err != nil {
			panic(err)
		}

		if err = s.IndexEntity("TestContent", c); err != nil {
			panic(err)
		}
	}
}

func TestMain(m *testing.M) {
	ts := &ab.TestServer{
		Addr: "localhost:9996",
	}

	ts.StartAndCleanUp(m, func(cfg *viper.Viper, s *ab.Server) error {
		db := s.GetDBConnection()
		ec := ab.NewEntityController(db)
		ec.Add(&TestContent{}, nil)
		entres := ab.EntityResource(ec, &TestContent{}, ab.EntityResourceConfig{})
		s.RegisterService(entres)
		searchDelegate := &testContentSearchServiceDelegate{
			logger: log.DefaultOSLogger(),
			db:     s.GetDBConnection(),
			ec:     ec,
		}
		searchService := NewSearchService(s.GetDBConnection(), nil)
		searchService.AddDelegate("TestContent", searchDelegate)
		s.RegisterService(searchService)

		mockData(db, ec, searchService)

		return nil
	})
}

func TestSearch(t *testing.T) {
	Convey("A search should return a result", t, func() {
		keywords := ""
		numWords := rand.Intn(4) + 2
		for i := 0; i < numWords; i++ {
			keywords += words[rand.Intn(len(words))] + " "
		}
		search(keywords)
	})
}

func search(keywords string) {
	pd := SearchPostData{
		Search: keywords,
		Owners: []string{"00000000-0000-0000-0000-000000000000"},
	}
	tc := ab.NewTestClientWithToken(base)
	tc.Request("POST", "/api/search", tc.JSONBuffer(pd), nil, func(resp *http.Response) {
		tc.ConsumePrefix(resp)
		res := []testContentSearchResult{}
		So(json.NewDecoder(resp.Body).Decode(&res), ShouldBeNil)
		So(len(res), ShouldNotEqual, 0)
	}, http.StatusOK)
}
