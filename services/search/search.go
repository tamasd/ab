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
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/nbio/hitch"
	"github.com/tamasd/ab"
	"github.com/tamasd/ab/util"
)

var ErrorDelegateNotFound = errors.New("delegate not found")

type SearchResult struct {
	ab.Entity `json:"entity"`
	Type      string `json:"type"`
}

type IndexData struct {
	Keyword   string
	Relevance float64
	Owner     string
}

type rawIndexData struct {
	UUID string
	Type string
}

type SearchServiceCacheDelegate interface {
	Set(search string, results []SearchResult)
	Get(search string) []SearchResult
}

type SearchServiceDelegate interface {
	IndexEntity(ab.Entity) []IndexData
	LoadEntities([]string) []ab.Entity
}

var _ ab.Service = &SearchService{}

type SearchService struct {
	db        ab.DB
	delegates map[string]SearchServiceDelegate
	cache     SearchServiceCacheDelegate
}

func NewSearchService(db ab.DB, cache SearchServiceCacheDelegate) *SearchService {
	return &SearchService{
		db:        db,
		cache:     cache,
		delegates: make(map[string]SearchServiceDelegate),
	}
}

var searchSplitRegex = regexp.MustCompile(`[^\.\w]+`)

func (s *SearchService) normalizeKeywords(keywords []string) string {
	sort.Strings(keywords)
	return strings.Join(keywords, " ")
}

func (s *SearchService) cacheLookup(keywords []string) []SearchResult {
	if len(keywords) == 0 || s.cache == nil {
		return []SearchResult{}
	}

	key := s.normalizeKeywords(keywords)

	return s.cache.Get(key)
}

func (s *SearchService) cacheSave(keywords []string, results []SearchResult) {
	if len(keywords) == 0 || len(results) == 0 || s.cache == nil {
		return
	}

	key := s.normalizeKeywords(keywords)

	s.cache.Set(key, results)
}

func (s *SearchService) Search(search string, owners []string) ([]SearchResult, error) {
	search = strings.TrimSpace(search)
	search = strings.ToLower(search)

	if len(search) == 0 {
		return []SearchResult{}, nil
	}

	keywords := searchSplitRegex.Split(search, -1)

	if len(keywords) == 0 {
		return []SearchResult{}, nil
	}

	if res := s.cacheLookup(keywords); len(res) > 0 {
		return res, nil
	}

	placeholders := util.GeneratePlaceholders(1, uint(len(keywords))+1)
	ownerCheck := ""
	if len(owners) > 0 {
		ownerPlaceholders := util.GeneratePlaceholders(uint(len(keywords))+1, uint(len(keywords)+len(owners))+1)
		ownerCheck = `AND owner IN (` + ownerPlaceholders + `)`
	}

	rows, err := s.db.Query(`
		WITH
			uuids AS (SELECT uuid, SUM(relevance) rel FROM search_metadata WHERE keyword IN (`+placeholders+`) GROUP BY uuid),
			types AS (SELECT DISTINCT uuid, type, owner FROM search_metadata)
		SELECT t.uuid, t.type FROM uuids u NATURAL JOIN types t WHERE u.rel > 0 `+ownerCheck+` ORDER BY u.rel DESC
	`, append(util.StringSliceToInterfaceSlice(keywords), util.StringSliceToInterfaceSlice(owners)...)...)
	if err != nil {
		return []SearchResult{}, err
	}

	uuids := make(map[string][]string)
	matches := []rawIndexData{}

	defer rows.Close()
	for rows.Next() {
		d := rawIndexData{}
		err = rows.Scan(&d.UUID, &d.Type)
		if err != nil {
			return []SearchResult{}, err
		}

		matches = append(matches, d)
		uuids[d.Type] = append(uuids[d.Type], d.UUID)
	}
	if err := rows.Err(); err != nil {
		return []SearchResult{}, err
	}

	entities := map[string]ab.Entity{}

	for t, u := range uuids {
		delegate := s.delegates[t]
		if delegate == nil {
			return []SearchResult{}, ErrorDelegateNotFound
		}

		for _, entity := range delegate.LoadEntities(u) {
			entities[entity.GetID()] = entity
		}
	}

	results := []SearchResult{}

	for _, match := range matches {
		if _, ok := entities[match.UUID]; !ok {
			continue
		}

		results = append(results, SearchResult{
			Entity: entities[match.UUID],
			Type:   match.Type,
		})
	}

	s.cacheSave(keywords, results)

	return results, nil
}

func (s *SearchService) IndexEntity(entityType string, entity ab.Entity) error {
	s.db.Exec("DELETE FROM search_metadata WHERE uuid = $1", entity.GetID())

	delegate, ok := s.delegates[entityType]
	if !ok {
		return ErrorDelegateNotFound
	}

	data := delegate.IndexEntity(entity)
	if len(data) == 0 {
		return nil
	}

	placeholders := []string{}
	values := []interface{}{}
	uuid := entity.GetID()

	for i, d := range data {
		if d.Owner == "" {
			d.Owner = "00000000-0000-0000-0000-000000000000"
		}
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)", i*5+1, i*5+2, i*5+3, i*5+4, i*5+5))
		values = append(values, uuid, entityType, d.Keyword, d.Relevance, d.Owner)
	}

	_, err := s.db.Exec("INSERT INTO search_metadata(uuid, type, keyword, relevance, owner) VALUES "+strings.Join(placeholders, ", ")+";", values...)
	return err
}

func (s *SearchService) RemoveEntity(uuid string) error {
	_, err := s.db.Exec("DELETE FROM search_metadata WHERE uuid = $1", uuid)
	return err
}

func (s *SearchService) PurgeIndex() error {
	_, err := s.db.Exec("DELETE FROM search_metadata")
	return err
}

func (s *SearchService) AddDelegate(delegateType string, delegate SearchServiceDelegate) *SearchService {
	s.delegates[delegateType] = delegate
	return s
}

func (s *SearchService) Register(h *hitch.Hitch) error {
	h.Post("/api/search", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := SearchPostData{}
		ab.MustDecode(r, &d)

		results, err := s.Search(d.Search, d.Owners)
		ab.MaybeFail(r, http.StatusInternalServerError, err)

		ab.Render(r).JSON(results)
	}))

	return nil
}

func (s *SearchService) SchemaInstalled(db ab.DB) bool {
	return ab.TableExists(db, "search_metadata")
}

func (s *SearchService) SchemaSQL() string {
	return `
		CREATE TABLE search_metadata (
			uuid uuid NOT NULL,
			type character varying NOT NULL,
			owner uuid,
			keyword character varying NOT NULL,
			relevance double precision NOT NULL,
			CONSTRAINT search_metadata_pkey PRIMARY KEY (uuid, keyword, owner),
			CONSTRAINT search_metadata_keyword_check CHECK (keyword::text <> ''::text),
			CONSTRAINT search_metadata_relevance_check CHECK (relevance <= 1::double precision AND relevance >= 0::double precision)
		);

		CREATE INDEX search_metadata_keyword_idx
			ON search_metadata
			USING hash (keyword);
	`
}

type SearchPostData struct {
	Search string   `json:"search"`
	Owners []string `json:"owners"`
}
