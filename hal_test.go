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
	"encoding/json"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var _ EndpointLinker = &item{}

type item struct {
	A int    `json:"a"`
	B string `json:"b"`
	C uint   `json:"c,omitempty"`
}

func (i *item) Links() map[string][]string {
	return map[string][]string{
		"rel0": []string{"http://example.com", "http://asdf.example.com"},
		"rel1": []string{"http://xzcv.example.com"},
	}
}

func (i *item) Curies() []HALCurie {
	return []HALCurie{
		HALCurie{
			Name:      "qwerty",
			Href:      "http://qwerty.example.com",
			Templated: false,
		},
		HALCurie{
			Name:      "asdf",
			Href:      "http://asdf.example.com/{rel}",
			Templated: true,
		},
	}
}

type nonhalitem struct {
	A int
	B string
}

const haljson = `{"_links":{"curies":[{"name":"qwerty","href":"http://qwerty.example.com","templated":false},{"name":"asdf","href":"http://asdf.example.com/{rel}","templated":true}],"rel0":[{"href":"http://example.com"},{"href":"http://asdf.example.com"}],"rel1":[{"href":"http://xzcv.example.com"}]},"a":5,"b":"asdf"}`

func TestHAL(t *testing.T) {
	Convey("Given a simple struct embedded in a HAL wrapper", t, func() {
		i := &item{
			A: 5,
			B: "asdf",
		}

		w := newHalWrapper(i)

		Convey("The JSON marshalling should produce a flattened struct", func() {
			marshaled, err := json.Marshal(w)
			So(err, ShouldBeNil)
			So(string(marshaled), ShouldEqual, haljson)
		})
	})
}

const reslisthaljson = `{"items":[{"_links":{"curies":[{"name":"qwerty","href":"http://qwerty.example.com","templated":false},{"name":"asdf","href":"http://asdf.example.com/{rel}","templated":true}],"rel0":[{"href":"http://example.com"},{"href":"http://asdf.example.com"}],"rel1":[{"href":"http://xzcv.example.com"}]},"a":5,"b":"asdf","c":8},{"_links":{"curies":[{"name":"qwerty","href":"http://qwerty.example.com","templated":false},{"name":"asdf","href":"http://asdf.example.com/{rel}","templated":true}],"rel0":[{"href":"http://example.com"},{"href":"http://asdf.example.com"}],"rel1":[{"href":"http://xzcv.example.com"}]},"a":2,"b":"zxcvbn"},{"A":1,"B":"bar"},{"A":7,"B":"baz"}],"_links":{"curies":[{"name":"foo","href":"http://foo.example.com","templated":false},{"name":"bar","href":"http://bar.example.com","templated":false},{"name":"baz","href":"http://baz.example.com","templated":false}],"page next":[{"href":"/api/foo?page=6"}],"page previous":[{"href":"/api/foo?page=4"}],"rel test":[{"href":"http://test.example.com"}]}}`

func TestResourceListHAL(t *testing.T) {
	Convey("Given a list of HAL and non-HAL resources in a ResourceList", t, func() {
		l := ResourceList{
			Items: []Resource{
				&item{A: 5, B: "asdf", C: 8},
				&item{A: 2, B: "zxcvbn"},
				&nonhalitem{A: 1, B: "bar"},
				&nonhalitem{A: 7, B: "baz"},
			},
			page:     5,
			pageSize: 4,
			basePath: "/api/foo",
			Curies: []HALCurie{
				HALCurie{Name: "foo", Href: "http://foo.example.com"},
				HALCurie{Name: "bar", Href: "http://bar.example.com"},
				HALCurie{Name: "baz", Href: "http://baz.example.com"},
			},
			Rels: map[string][]string{
				"rel test": []string{"http://test.example.com"},
			},
		}

		Convey("The JSON should have _links on all applicable places", func() {
			marshaled, err := json.Marshal(l)
			So(err, ShouldBeNil)
			So(string(marshaled), ShouldEqual, reslisthaljson)
		})
	})
}
