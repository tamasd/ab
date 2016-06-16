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

import "net/http"

type ResourceListEvent interface {
	Before(*http.Request)
	After(*http.Request, *[]Resource)
}

type resourceListEvents []ResourceListEvent

func (e resourceListEvents) invokeBefore(r *http.Request) {
	for _, evt := range e {
		evt.Before(r)
	}
}

func (e resourceListEvents) invokeAfter(r *http.Request, res *[]Resource) {
	for _, evt := range e {
		evt.After(r, res)
	}
}

type ResourceListEventCallback struct {
	BeforeCallback func(*http.Request)
	AfterCallback  func(*http.Request, *[]Resource)
}

func (c ResourceListEventCallback) Before(r *http.Request) {
	if c.BeforeCallback != nil {
		c.BeforeCallback(r)
	}
}

func (c ResourceListEventCallback) After(r *http.Request, res *[]Resource) {
	if c.AfterCallback != nil {
		c.AfterCallback(r, res)
	}
}

type ResourceEvent interface {
	Before(*http.Request, Resource)
	Inside(*http.Request, Resource)
	After(*http.Request, Resource)
}

type resourceEvents []ResourceEvent

func (e resourceEvents) invokeBefore(r *http.Request, res Resource) {
	for _, evt := range e {
		evt.Before(r, res)
	}
}

func (e resourceEvents) invokeInside(r *http.Request, res Resource) {
	for _, evt := range e {
		evt.Inside(r, res)
	}
}

func (e resourceEvents) invokeAfter(r *http.Request, res Resource) {
	for _, evt := range e {
		evt.After(r, res)
	}
}

var _ ResourceEvent = ResourceEventCallback{}

type ResourceEventCallback struct {
	BeforeCallback func(*http.Request, Resource)
	InsideCallback func(*http.Request, Resource)
	AfterCallback  func(*http.Request, Resource)
}

func (c ResourceEventCallback) Before(r *http.Request, res Resource) {
	if c.BeforeCallback != nil {
		c.BeforeCallback(r, res)
	}
}

func (c ResourceEventCallback) Inside(r *http.Request, res Resource) {
	if c.InsideCallback != nil {
		c.InsideCallback(r, res)
	}
}

func (c ResourceEventCallback) After(r *http.Request, res Resource) {
	if c.AfterCallback != nil {
		c.AfterCallback(r, res)
	}
}
