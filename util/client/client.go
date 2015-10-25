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

package client

import (
	"io"
	"io/ioutil"
	"net/http"
)

var JSONPrefix = true

func ConsumePrefix(r *http.Response) (bool, error) {
	prefix := make([]byte, 6)
	_, err := io.ReadFull(r.Body, prefix)
	return string(prefix) == ")]}',\n", err
}

func ReadBody(r *http.Response) (string, error) {
	if JSONPrefix {
		_, err := ConsumePrefix(r)
		if err != nil {
			return "", err
		}
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
