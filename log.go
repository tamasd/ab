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
	"bytes"
	"io"
	"net/http"
	"os"

	"github.com/nbio/httpcontext"
	"github.com/tamasd/ab/lib/log"
)

const logKey = "ablog"
const logBufKey = "ablogbuf"

func DefaultLoggerMiddleware(level log.LogLevel) func(http.Handler) http.Handler {
	return LoggerMiddleware(
		level,
		log.UserLogFactory,
		log.VerboseLogFactory,
		log.TraceLogFactory,
		os.Stdout,
	)
}

func LoggerMiddleware(level log.LogLevel, userLogFactory, verboseLogFactory, traceLogFactory func(w io.Writer) log.Logger, lw io.Writer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := bytes.NewBuffer(nil)
			mw := io.MultiWriter(buf, lw)
			l := log.NewLogger(
				userLogFactory(mw),
				verboseLogFactory(mw),
				traceLogFactory(mw),
			)
			l.Level = level

			httpcontext.Set(r, logKey, l)
			httpcontext.Set(r, logBufKey, buf)

			next.ServeHTTP(w, r)
		})
	}
}

func RequestLogs(r *http.Request) string {
	return httpcontext.Get(r, logBufKey).(*bytes.Buffer).String()
}

func logFromContext(r *http.Request) *log.Log {
	return httpcontext.Get(r, logKey).(*log.Log)
}

func LogUser(r *http.Request) log.Logger {
	return logFromContext(r).User()
}

func LogVerbose(r *http.Request) log.Logger {
	return logFromContext(r).Verbose()
}

func LogTrace(r *http.Request) log.Logger {
	return logFromContext(r).Trace()
}
