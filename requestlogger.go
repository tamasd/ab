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
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/agtorre/gocolorize"
)

// Creates a request logger middleware.
//
// The l parameter defines a logger to use. If l is nil, then the standard logger will be used.
func RequestLoggerMiddleware(l *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var start, end int64
			start = time.Now().UnixNano()

			path := r.URL.Path

			rw := &requestLoggerResponseWriter{
				ResponseWriter: w,
				code:           http.StatusOK,
			}

			next.ServeHTTP(rw, r)

			end = time.Now().UnixNano()
			duration := end - start
			time := ""
			if duration >= 1000000000 {
				time = fmt.Sprintf("%.2fs", float64(duration)/1000000000)
			} else if duration >= 1000000 {
				time = fmt.Sprintf("%.2fms", float64(duration)/1000000)
			} else if duration >= 1000 {
				time = fmt.Sprintf("%.2fµs", float64(duration)/1000)
			} else {
				time = fmt.Sprintf("%ldns", duration)
			}

			httpCode := rw.GetCode()
			code := fmt.Sprintf("%d", httpCode)
			if httpCode >= 100 && httpCode <= 199 {
				code = gocolorize.NewColor("black+b:white").Paint(code)
			} else if httpCode >= 200 && httpCode <= 299 {
				code = gocolorize.NewColor("white+b:green").Paint(code)
			} else if httpCode >= 300 && httpCode <= 399 {
				code = gocolorize.NewColor("white+b:blue").Paint(code)
			} else if httpCode >= 400 && httpCode <= 499 {
				code = gocolorize.NewColor("white+b:yellow").Paint(code)
			} else if httpCode >= 500 && httpCode <= 599 {
				code = gocolorize.NewColor("white+b:red").Paint(code)
			}

			if l == nil {
				log.Printf("%s\t%s\t%s\t%s\n", gocolorize.NewColor("cyan").Paint(r.Method), gocolorize.NewColor("blue").Paint(path), code, time)
			} else {
				l.Printf("%s\t%s\t%s\t%s\n", gocolorize.NewColor("cyan").Paint(r.Method), gocolorize.NewColor("blue").Paint(path), code, time)
			}
		})
	}
}

var _ http.ResponseWriter = &requestLoggerResponseWriter{}

type requestLoggerResponseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *requestLoggerResponseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *requestLoggerResponseWriter) GetCode() int {
	return rw.code
}
