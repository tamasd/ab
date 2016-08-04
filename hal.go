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
	"reflect"
	"strings"
)

type halWrapper struct {
	Item  interface{}            `json:"item"`
	Links map[string]interface{} `json:"_links"`
}

func newHalWrapper(el EndpointLinker) halWrapper {
	w := halWrapper{
		Item:  el,
		Links: createHALLinkList(el.Links(), el.Curies()),
	}

	return w
}

func createHALLinkList(linkmap map[string][]string, curies []HALCurie) map[string]interface{} {
	out := make(map[string]interface{})

	for rel, links := range linkmap {
		la := make([]halLink, len(links))
		for i, link := range links {
			la[i] = halLink{
				Href: link,
			}
		}

		out[rel] = la
	}

	out["curies"] = curies

	return out
}

func (w halWrapper) MarshalJSON() ([]byte, error) {
	val := reflect.ValueOf(w.Item)
	if val.Type().Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Type().Kind() != reflect.Struct {
		return json.Marshal(w)
	}

	out := make(map[string]interface{})

	n := val.Type().NumField()
	for i := 0; i < n; i++ {
		f := val.Type().Field(i)
		d := getMarshalData(f)
		v := val.Field(i)

		if d.omitempty && isEmptyValue(v) {
			continue
		}

		if d.name == "-" {
			continue
		}

		out[d.name] = v.Interface()
	}

	out["_links"] = w.Links

	return json.Marshal(out)
}

func getMarshalData(f reflect.StructField) marshalData {
	d := marshalData{
		name: f.Name,
	}

	if tag := f.Tag.Get("json"); tag != "" {
		parts := strings.Split(tag, ",")
		d.name = parts[0]
		if len(parts) > 1 && parts[1] == "omitempty" {
			d.omitempty = true
		}
	}

	return d
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

type marshalData struct {
	name      string
	omitempty bool
}

type EndpointLinker interface {
	Links() map[string][]string
	Curies() []HALCurie
}

type halLink struct {
	Href string `json:"href"`
}

type HALCurie struct {
	Name      string `json:"name"`
	Href      string `json:"href"`
	Templated bool   `json:"templated"`
}
