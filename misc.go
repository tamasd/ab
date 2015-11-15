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
	"net"
	"net/http"
	"strings"
)

// Restricts access based on the IP address of the client. Only IP addresses in the given CIDR address ranges will be allowed.
func RestrictAddressMiddleware(addresses ...string) func(http.Handler) http.Handler {
	cidrnets := make([]*net.IPNet, len(addresses))
	var err error
	for i, address := range addresses {
		_, cidrnets[i], err = net.ParseCIDR(address)
		if err != nil {
			panic(err)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqAddress := strings.Split(r.RemoteAddr, ":")[0]
			ip := net.ParseIP(reqAddress)
			for _, cidrnet := range cidrnets {
				if cidrnet.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		})
	}
}

func RestrictPrivateAddressMiddleware() func(http.Handler) http.Handler {
	return RestrictAddressMiddleware("10.255.255.255/8", "172.31.255.255/12", "192.168.255.255/16", "127.0.0.0/8")
}

// Constucts an URL to the redirect destination.
//
// The redirect destination is read from the destination URL parameter.
func RedirectDestination(r *http.Request) string {
	return "/" + r.URL.Query().Get("destination")
}
