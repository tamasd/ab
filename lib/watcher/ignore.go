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

package watcher

import "regexp"

type Ignorer interface {
	Ignored(string) bool
}

type IgnorerFunc func(string) bool

func (f IgnorerFunc) Ignored(s string) bool {
	return f(s)
}

func NewStringIgnorer(ignore string) Ignorer {
	return IgnorerFunc(func(s string) bool {
		return s == ignore
	})
}

func NewRegexpIgnorer(r *regexp.Regexp) Ignorer {
	return IgnorerFunc(func(s string) bool {
		return r.MatchString(s)
	})
}
