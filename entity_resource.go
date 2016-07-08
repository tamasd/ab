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
	"net/http"
	"reflect"
	"strconv"
)

func EntityResource(ec *EntityController, entity Entity, config EntityResourceConfig) *ResourceController {
	delegate := newEntityResourceDelegate(ec, entity, config)

	res := NewResourceController(delegate)

	if !config.DisableList {
		res.List(delegate, config.ListMiddlewares...)
	}

	if !config.DisablePost {
		res.Post(delegate, config.PostMiddlewares...)
	}

	if !config.DisableGet {
		res.Get(delegate, config.GetMiddlewares...)
	}

	if !config.DisablePut {
		res.Put(delegate, config.PutMiddlewares...)
	}

	if !config.DisableDelete {
		res.Delete(delegate, config.DeleteMiddlewares...)
	}

	return res
}

type EntityResourceExtraSchema interface {
	SchemaSQL() string
	SchemaInstalled(DB) bool
}

type EntityResourceLister interface {
	List(r *http.Request, start, limit int) (string, []interface{})
}

type EntityResourceLoader interface {
	Load(id string, r *http.Request) (Resource, error)
}

type EntityResourceConfig struct {
	PageLen       int
	Validator     func(data Resource, r *http.Request)
	DisableList   bool
	DisablePost   bool
	DisableGet    bool
	DisablePut    bool
	DisableDelete bool

	ListMiddlewares   []func(http.Handler) http.Handler
	PostMiddlewares   []func(http.Handler) http.Handler
	GetMiddlewares    []func(http.Handler) http.Handler
	PutMiddlewares    []func(http.Handler) http.Handler
	DeleteMiddlewares []func(http.Handler) http.Handler

	EntityResourceLister
	EntityResourceLoader
	EntityResourceExtraSchema
}

var _ ResourceControllerDelegate = &entityResourceDelegate{}
var _ ResourceListDelegate = &entityResourceDelegate{}
var _ ResourcePostDelegate = &entityResourceDelegate{}
var _ ResourceGetDelegate = &entityResourceDelegate{}
var _ ResourcePutDelegate = &entityResourceDelegate{}
var _ ResourceDeleteDelegate = &entityResourceDelegate{}

type entityResourceDelegate struct {
	EntityResourceConfig
	controller  *EntityController
	entity      Entity
	entityType  reflect.Type
	machineName string
}

func newEntityResourceDelegate(ec *EntityController, entity Entity, config EntityResourceConfig) *entityResourceDelegate {
	er := &entityResourceDelegate{
		controller:           ec,
		entity:               entity,
		machineName:          ec.Type(entity),
		EntityResourceConfig: config,
	}

	if er.PageLen == 0 {
		er.PageLen = 25
	}

	return er
}

func (er *entityResourceDelegate) getEntity(data Resource) Entity {
	e := data.(Entity)

	if er.controller.Type(e) != er.machineName {
		panic("invalid entity")
	}

	return e
}

func (er *entityResourceDelegate) List(r *http.Request, start, limit int) ([]Resource, error) {
	query, args := "", []interface{}{}
	if er.EntityResourceLister != nil {
		query, args = er.EntityResourceLister.List(r, start, limit)
	} else {
		query = "SELECT " + er.controller.FieldList(er.machineName) + " FROM \"" + er.machineName + "\" " + er.controller.TableAbbrev(er.machineName) + " LIMIT " + strconv.Itoa(limit) + " OFFSET " + strconv.Itoa(start)
	}
	entities, err := er.controller.LoadFromQuery(GetDB(r), er.machineName, query, args...)
	if err != nil {
		return []Resource{}, err
	}

	resources := make([]Resource, len(entities))
	for i, e := range entities {
		resources[i] = e.(Resource)
	}

	return resources, nil
}

func (er *entityResourceDelegate) PageLength() int {
	return er.PageLen
}

func (er *entityResourceDelegate) Empty() Resource {
	return er.controller.Empty(er.machineName).(Resource)
}

func (er *entityResourceDelegate) Validate(data Resource, r *http.Request) {
	if er.Validator != nil {
		er.Validator(data, r)
	}
	e := er.getEntity(data)
	err := er.controller.Validate(e)
	MaybeFail(r, http.StatusBadRequest, err)
}

func (er *entityResourceDelegate) Insert(data Resource, r *http.Request) error {
	e := er.getEntity(data)
	return er.controller.Insert(GetDB(r), e)
}

func (er *entityResourceDelegate) Load(id string, r *http.Request) (Resource, error) {
	if er.EntityResourceLoader != nil {
		return er.EntityResourceLoader.Load(id, r)
	}

	entity, err := er.controller.Load(GetDB(r), er.machineName, id)
	if entity == nil {
		return nil, err
	}
	return entity.(Resource), err
}

func (er *entityResourceDelegate) GetID(data Resource) string {
	return data.(Entity).GetID()
}

func (er *entityResourceDelegate) Update(data Resource, r *http.Request) error {
	e := er.getEntity(data)
	return er.controller.Update(GetDB(r), e)
}

func (er *entityResourceDelegate) Delete(data Resource, r *http.Request) error {
	e := er.getEntity(data)
	return er.controller.Delete(GetDB(r), e)
}

func (er *entityResourceDelegate) GetName() string {
	return er.machineName
}

func (er *entityResourceDelegate) GetTables() []string {
	return []string{er.machineName}
}

func (er *entityResourceDelegate) GetSchemaSQL() string {
	sql := er.controller.SchemaSQL(er.entity)

	if er.EntityResourceExtraSchema != nil {
		sql += er.EntityResourceExtraSchema.SchemaSQL()
	}

	return sql
}

func (er *entityResourceDelegate) SchemaInstalled(db DB) bool {
	installed := true

	for _, table := range er.GetTables() {
		installed = installed && TableExists(db, table)
	}

	if er.EntityResourceExtraSchema != nil {
		installed = installed && er.EntityResourceExtraSchema.SchemaInstalled(db)
	}

	return installed
}
