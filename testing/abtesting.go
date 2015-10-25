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

//go:generate ab entity Test
//go:generate ab --output=entity2.go --generate-service-struct-name=Service2 entity Test2

type Test struct {
	UUID       *string      `dbtype:"uuid" dbdefault:"uuid_generate_v4()" json:",omitempty"`
	Name, Mail *string      `constructor:"true" json:",omitempty"`
	Secret     *[]string    `nodb:"true" json:",omitempty"`
	Bio        *string      `dbtype:"text" json:",omitempty"`
	Data       *[]jsonStuff `dbtype:"jsonb" json:",omitempty"`
}

type Test2 struct {
	UUID       string       `dbtype:"uuid" dbdefault:"uuid_generate_v4()" json:",omitempty"`
	Name, Mail string       `constructor:"true" json:",omitempty"`
	Secret     []string     `nodb:"true" json:",omitempty"`
	Bio        string       `dbtype:"text" json:",omitempty"`
	Data       []*jsonStuff `dbtype:"jsonb" json:",omitempty"`
}

type jsonStuff struct {
	A int
	B string
}
