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

type EntityReadEvent interface {
	Before(entityType string, query string, args []interface{}) (string, []interface{})
	After(entityType string, entities []Entity, err error) ([]Entity, error)
}

type EntityWriteEvent interface {
	Before(entityType string, e Entity)
	After(entityType string, e Entity, err error) error
}

type entityReadEvents []EntityReadEvent

func (e entityReadEvents) invokeBefore(entityType string, query string, args []interface{}) (string, []interface{}) {
	for _, evt := range e {
		query, args = evt.Before(entityType, query, args)
	}

	return query, args
}

func (e entityReadEvents) invokeAfter(entityType string, entities []Entity, err error) ([]Entity, error) {
	for _, evt := range e {
		entities, err = evt.After(entityType, entities, err)
	}

	return entities, err
}

type entityWriteEvents []EntityWriteEvent

func (e entityWriteEvents) invokeBefore(entityType string, entity Entity) {
	for _, evt := range e {
		evt.Before(entityType, entity)
	}
}

func (e entityWriteEvents) invokeAfter(entityType string, entity Entity, err error) error {
	for _, evt := range e {
		err = evt.After(entityType, entity, err)
	}

	return err
}
