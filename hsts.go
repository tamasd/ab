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

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HSTSConfig struct {
	MaxAge            time.Duration
	IncludeSubDomains bool
	HostBlacklist     []string
}

func (c HSTSConfig) String() string {
	directives := []string{}

	if c.MaxAge > 0 {
		directives = append(directives, "max-age="+strconv.Itoa(int(c.MaxAge.Seconds())))
	}

	if c.IncludeSubDomains {
		directives = append(directives, "includeSubDomains")
	}

	if len(directives) == 0 {
		return ""
	}

	return strings.Join(directives, "; ")
}

func (c HSTSConfig) isHostBlacklisted(host string) bool {
	for _, blacklistedHost := range c.HostBlacklist {
		if blacklistedHost == host {
			return true
		}
	}

	return false
}

func HTSTMiddleware(config HSTSConfig) func(http.Handler) http.Handler {
	headerValue := config.String()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !config.isHostBlacklisted(r.Host) {
				w.Header().Set("Strict-Transport-Security", headerValue)
			}
			next.ServeHTTP(w, r)
		})
	}
}
