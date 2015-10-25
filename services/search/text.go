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
	"regexp"
	"strings"

	"github.com/surge/porter2"
)

var Stemmers = map[string]func(string) string{
	"en": porter2.Stem,
}

// Creates IndexData entries from a text.
//
// TODO(tamasd): change the relevance parameter from float64 to some kind of a function.
func IndexDataFromText(lang, s string, relevance float64, owner string) []IndexData {
	stems := TextToStemmedWords(lang, s)
	d := []IndexData{}
	for _, stem := range stems {
		if stem != "" {
			d = append(d, IndexData{
				Keyword:   stem,
				Relevance: relevance,
				Owner:     owner,
			})
		}
	}

	return d
}

func TextToStemmedWords(lang, s string) []string {
	return textToWordsWithStemmer(s, Stemmers[lang])
}

var wordTokenizerRegex = regexp.MustCompile(`[\W]+`)

func textToWordsWithStemmer(s string, stem func(string) string) []string {
	if s == "" {
		return []string{}
	}

	words := wordTokenizerRegex.Split(strings.TrimSpace(s), -1)

	uniqueWords := make(map[string]struct{})

	for _, word := range words {
		word = strings.ToLower(word)
		if stem != nil {
			word = stem(word)
		}
		uniqueWords[word] = struct{}{}
	}

	list := []string{}
	for word, _ := range uniqueWords {
		list = append(list, word)
	}

	return list
}
