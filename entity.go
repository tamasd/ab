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

// Reserved for later use. Currectly used by the entity generator only.
type Validator interface {
	Validate() error
}

// Interface for the entities.
//
// Currently this is used by the entity generator only. See the documentation of the entity package for more information.
type Entity interface {
	Validator
	GetID() string
	Insert(DB) error
	Update(DB) error
	Delete(DB) error
}
