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
	"errors"
	"net/http"

	"github.com/lib/pq"
)

var ErrNoEndpoints = errors.New("no endpoints are enabled for this resource")

type Resource interface {
}

type ResourceListDelegate interface {
	List(r *http.Request, start, limit int) ([]Resource, error)
	PageLength() int
}

type ResourcePostDelegate interface {
	Empty() Resource
	Validate(data Resource, r *http.Request)
	Insert(data Resource, r *http.Request) error
}

type ResourceGetDelegate interface {
	Load(id string, r *http.Request) (Resource, error)
}

type ResourcePutDelegate interface {
	Empty() Resource
	Load(id string, r *http.Request) (Resource, error)
	GetID(Resource) string
	Validate(data Resource, r *http.Request)
	Update(data Resource, r *http.Request) error
}

type ResourceDeleteDelegate interface {
	Load(id string, r *http.Request) (Resource, error)
	Delete(data Resource, r *http.Request) error
}

type ResourcePathOverrider interface {
	OverridePath(string) string
}

type ResourceFormatter interface {
	FormatSingle(Resource, *Renderer)
	FormatMulti([]Resource, *Renderer)
}

type ResourceControllerDelegate interface {
	GetName() string
	GetTables() []string
	GetSchemaSQL() string
	SchemaInstalled(db DB) bool
}

var _ Service = &ResourceController{}

type ResourceController struct {
	ResourceFormatter
	delegate       ResourceControllerDelegate
	errorConverter func(err *pq.Error) VerboseError

	listDelegate    ResourceListDelegate
	listMiddlewares []func(http.Handler) http.Handler

	postDelegate    ResourcePostDelegate
	postMiddlewares []func(http.Handler) http.Handler

	getDelegate    ResourceGetDelegate
	getMiddlewares []func(http.Handler) http.Handler

	putDelegate    ResourcePutDelegate
	putMiddlewares []func(http.Handler) http.Handler

	deleteDelegate    ResourceDeleteDelegate
	deleteMiddlewares []func(http.Handler) http.Handler

	listEvents   resourceListEvents
	postEvents   resourceEvents
	getEvents    resourceEvents
	putEvents    resourceEvents
	deleteEvents resourceEvents

	ExtraEndpoints func(s *Server) error
}

func NewResourceController(delegate ResourceControllerDelegate) *ResourceController {
	return &ResourceController{
		ResourceFormatter: &DefaultResourceFormatter{},
		delegate:          delegate,
		postMiddlewares:   []func(http.Handler) http.Handler{TransactionMiddleware},
		putMiddlewares:    []func(http.Handler) http.Handler{TransactionMiddleware},
		deleteMiddlewares: []func(http.Handler) http.Handler{TransactionMiddleware},
		errorConverter: func(err *pq.Error) VerboseError {
			return NewVerboseError(err.Message, err.Detail)
		},
	}
}

func (res *ResourceController) GetName() string {
	return res.delegate.GetName()
}

func (res *ResourceController) AddListEvent(evt ...ResourceListEvent) *ResourceController {
	res.listEvents = append(res.listEvents, evt...)
	return res
}

func (res *ResourceController) AddPostEvent(evt ...ResourceEvent) *ResourceController {
	res.postEvents = append(res.postEvents, evt...)
	return res
}

func (res *ResourceController) AddGetEvent(evt ...ResourceEvent) *ResourceController {
	res.getEvents = append(res.getEvents, evt...)
	return res
}

func (res *ResourceController) AddPutEvent(evt ...ResourceEvent) *ResourceController {
	res.putEvents = append(res.putEvents, evt...)
	return res
}

func (res *ResourceController) AddDeleteEvent(evt ...ResourceEvent) *ResourceController {
	res.deleteEvents = append(res.deleteEvents, evt...)
	return res
}

func (res *ResourceController) List(d ResourceListDelegate, middlewares ...func(http.Handler) http.Handler) *ResourceController {
	res.listDelegate = d
	res.listMiddlewares = middlewares

	return res
}

func (res *ResourceController) Post(d ResourcePostDelegate, middlewares ...func(http.Handler) http.Handler) *ResourceController {
	res.postDelegate = d
	res.postMiddlewares = middlewares

	return res
}

func (res *ResourceController) Get(d ResourceGetDelegate, middlewares ...func(http.Handler) http.Handler) *ResourceController {
	res.getDelegate = d
	res.getMiddlewares = middlewares

	return res
}

func (res *ResourceController) Put(d ResourcePutDelegate, middlewares ...func(http.Handler) http.Handler) *ResourceController {
	res.putDelegate = d
	res.putMiddlewares = middlewares

	return res
}

func (res *ResourceController) Delete(d ResourceDeleteDelegate, middlewares ...func(http.Handler) http.Handler) *ResourceController {
	res.deleteDelegate = d
	res.deleteMiddlewares = middlewares

	return res
}

func (res *ResourceController) convertError(err error) error {
	return ConvertDBError(err, res.errorConverter)
}

func (res *ResourceController) listHandler(w http.ResponseWriter, r *http.Request) {
	limit := res.listDelegate.PageLength()
	start := Pager(r, limit)

	res.listEvents.invokeBefore(r)

	list, err := res.listDelegate.List(r, start, limit)
	MaybeFail(http.StatusInternalServerError, res.convertError(err))

	res.listEvents.invokeAfter(r, &list)

	res.ResourceFormatter.FormatMulti(list, Render(r))
}

func (res *ResourceController) postHandler(w http.ResponseWriter, r *http.Request) {
	d := res.postDelegate.Empty()
	MustDecode(r, d)

	res.postEvents.invokeBefore(r, d)

	res.postDelegate.Validate(d, r)

	if v, ok := d.(Validator); ok {
		err := v.Validate()
		MaybeFail(http.StatusBadRequest, err)
	}

	res.postEvents.invokeInside(r, d)

	err := res.postDelegate.Insert(d, r)
	MaybeFail(http.StatusInternalServerError, res.convertError(err))

	res.postEvents.invokeAfter(r, d)

	res.ResourceFormatter.FormatSingle(d, Render(r).SetCode(http.StatusCreated))
}

func (res *ResourceController) getHandler(w http.ResponseWriter, r *http.Request) {
	id := GetParams(r).ByName("id")

	res.getEvents.invokeBefore(r, nil)

	d, err := res.getDelegate.Load(id, r)
	MaybeFail(http.StatusInternalServerError, res.convertError(err))
	if d == nil {
		Fail(http.StatusNotFound, nil)
	}

	res.getEvents.invokeAfter(r, d)

	res.ResourceFormatter.FormatSingle(d, Render(r))
}

func (res *ResourceController) putHandler(w http.ResponseWriter, r *http.Request) {
	id := GetParams(r).ByName("id")

	d := res.putDelegate.Empty()
	MustDecode(r, d)

	res.putEvents.invokeBefore(r, d)

	if res.putDelegate.GetID(d) != id {
		Fail(http.StatusBadRequest, nil)
	}

	res.putDelegate.Validate(d, r)

	if v, ok := d.(Validator); ok {
		err := v.Validate()
		MaybeFail(http.StatusBadRequest, err)
	}

	res.putEvents.invokeInside(r, d)

	err := res.putDelegate.Update(d, r)
	MaybeFail(http.StatusInternalServerError, res.convertError(err))

	res.putEvents.invokeAfter(r, d)

	res.ResourceFormatter.FormatSingle(d, Render(r))
}

func (res *ResourceController) deleteHandler(w http.ResponseWriter, r *http.Request) {
	id := GetParams(r).ByName("id")

	res.deleteEvents.invokeBefore(r, nil)

	d, err := res.deleteDelegate.Load(id, r)
	MaybeFail(http.StatusInternalServerError, res.convertError(err))
	if d == nil {
		Fail(http.StatusNotFound, nil)
	}

	res.deleteEvents.invokeInside(r, d)

	err = res.deleteDelegate.Delete(d, r)
	MaybeFail(http.StatusInternalServerError, res.convertError(err))

	res.deleteEvents.invokeAfter(r, d)
}

func (res *ResourceController) Register(srv *Server) error {
	if res.listDelegate == nil && res.postDelegate == nil && res.getDelegate == nil && res.putDelegate == nil && res.deleteDelegate == nil && res.ExtraEndpoints == nil {
		return ErrNoEndpoints
	}

	base := "/api/" + res.delegate.GetName()
	id := base + "/:id"

	if res.listDelegate != nil {
		path := base
		if po, ok := res.listDelegate.(ResourcePathOverrider); ok {
			path = po.OverridePath(path)
		}
		srv.Get(path, http.HandlerFunc(res.listHandler), res.listMiddlewares...)
	}

	if res.postDelegate != nil {
		path := base
		if po, ok := res.postDelegate.(ResourcePathOverrider); ok {
			path = po.OverridePath(path)
		}
		srv.Post(path, http.HandlerFunc(res.postHandler), res.postMiddlewares...)
	}

	if res.getDelegate != nil {
		path := id
		if po, ok := res.getDelegate.(ResourcePathOverrider); ok {
			path = po.OverridePath(path)
		}
		srv.Get(path, http.HandlerFunc(res.getHandler), res.getMiddlewares...)
	}

	if res.putDelegate != nil {
		path := id
		if po, ok := res.putDelegate.(ResourcePathOverrider); ok {
			path = po.OverridePath(path)
		}
		srv.Put(path, http.HandlerFunc(res.putHandler), res.putMiddlewares...)
	}

	if res.deleteDelegate != nil {
		path := id
		if po, ok := res.deleteDelegate.(ResourcePathOverrider); ok {
			path = po.OverridePath(path)
		}
		srv.Delete(path, http.HandlerFunc(res.deleteHandler), res.deleteMiddlewares...)
	}

	if res.ExtraEndpoints != nil {
		return res.ExtraEndpoints(srv)
	}
	return nil
}

func (res *ResourceController) SchemaInstalled(db DB) bool {
	installed := true

	for _, table := range res.delegate.GetTables() {
		installed = installed && TableExists(db, table)
	}

	return installed && res.delegate.SchemaInstalled(db)
}

func (res *ResourceController) SchemaSQL() string {
	return res.delegate.GetSchemaSQL()
}
