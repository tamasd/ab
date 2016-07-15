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
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"runtime"
	"strings"

	"github.com/tamasd/ab/util"
)

// Color codes for HTML error pages
var (
	OtherForegroundColor   = "fdf6e3"
	WarningForegroundColor = "fdf6e3"
	ErrorForegroundColor   = "fdf6e3"
	OtherBackgroundColor   = "268bd2"
	WarningBackgroundColor = "b58900"
	ErrorBackgroundColor   = "dc322f"
)

type VerboseError interface {
	// Error that is displayed in the logs and debug messages. Should contain diagnostical information.
	Error() string
	// Error that is displayed to the end user.
	VerboseError() string
}

var _ VerboseError = errorWrapper{}

type errorWrapper struct {
	error
	verboseMessage string
}

func (ew errorWrapper) VerboseError() string {
	return ew.verboseMessage
}

func WrapError(err error, verboseMessage string) VerboseError {
	return errorWrapper{
		error:          err,
		verboseMessage: verboseMessage,
	}
}

// Creates a new verbose error message.
//
// If err is an empty string, then verboseMessage will be used it instead.
func NewVerboseError(err, verboseMessage string) VerboseError {
	if err == "" {
		err = verboseMessage
	}

	return WrapError(errors.New(err), verboseMessage)
}

var _ VerboseError = Panic{}

// Custom panic data structure for the ErrorHandler
type Panic struct {
	Code          int
	Err           error
	StackTrace    string
	displayErrors bool
}

func (p Panic) Error() string {
	return p.Err.Error()
}

func (p Panic) String() string {
	return p.Err.Error()
}

func (p Panic) VerboseError() string {
	if ve, ok := p.Err.(VerboseError); ok {
		return ve.VerboseError()
	}

	return ""
}

// Outputs the error to the HTTP response.
//
// It can render the error in 3 formats: HTML, JSON and text, depending on the Accept header. The default is HTML.
func (p Panic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rd := NewRenderer().SetCode(p.Code)

	pageData := ErrorPageData{
		BackgroundColor: p.backgroundColor(),
		ForegroundColor: p.foregroundColor(),
		Code:            p.Code,
		Message:         "",
	}

	if p.displayErrors && p.Err != nil {
		pageData.Message = p.Error()
	} else {
		if ve := p.VerboseError(); ve != "" {
			pageData.Message = ve
		} else {
			pageData.Message = http.StatusText(p.Code)
		}
	}

	logs := ""
	if p.displayErrors {
		logs = p.StackTrace + "\n\n" + util.StripTerminalColorCodes(RequestLogs(r))
	}

	pageData.Logs = logs

	if p.Err != nil {
		LogVerbose(r).Println(p.Err)
		LogTrace(r).Println(p.StackTrace)
	}

	jsonMap := map[string]string{"message": pageData.Message}
	text := pageData.Message
	if p.displayErrors {
		jsonMap["logs"] = logs
		text += "\n\n" + logs
	}

	rd.
		HTML(ErrorPage, pageData).
		JSON(jsonMap).
		Text(text)

	rd.Render(w, r)
}

func (p Panic) backgroundColor() string {
	return decideColor(p.Code, OtherBackgroundColor, WarningBackgroundColor, ErrorBackgroundColor)
}

func (p Panic) foregroundColor() string {
	return decideColor(p.Code, OtherForegroundColor, WarningForegroundColor, ErrorForegroundColor)
}

func decideColor(code int, other, warn, err string) string {
	if code >= 500 && code <= 599 {
		return err
	}
	if code >= 400 && code <= 499 {
		return warn
	}
	return other
}

// Error handler middleware. This middleware injects an ErrorHandler to the request context, and then recovers if the ErrorHandler paniced.
//
// The caller of the function should also supply a logger that will log the errors. The displayErrors sends the error messages to the user. This is useful in a development environment.
//
// This middleware is automatically added to the Server with PetBunny.
func ErrorHandlerMiddleware(displayErrors bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}

				stackTrace := make([]byte, 8192)
				runtime.Stack(stackTrace, false)

				p, ok := rec.(Panic)
				if !ok {
					err, ok := rec.(error)
					if !ok {
						err = errors.New(fmt.Sprint(rec))
					}
					p = Panic{
						Code: http.StatusInternalServerError,
						Err:  err,
					}
				}

				p.displayErrors = displayErrors
				p.StackTrace = strings.TrimRight(string(stackTrace), "\x00")

				p.ServeHTTP(w, r)
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// Calls HandleError on the Error object inside the request context.
func Fail(code int, err error) {
	panic(Panic{
		Code: code,
		Err:  err,
	})
}

// Calls Fail() if err is not nil and not any of excludedErrors.
func MaybeFail(code int, err error, excludedErrors ...error) {
	if err == nil {
		return
	}

	for _, e := range excludedErrors {
		if e == err {
			return
		}
	}

	Fail(code, err)
}

// Data for the ErrorPage template.
type ErrorPageData struct {
	BackgroundColor string
	ForegroundColor string
	Code            int
	Message         string
	Logs            string
}

// HTML template for the standard HTML error page.
var ErrorPage = template.Must(template.New("ErrorPage").Parse(`<!DOCTYPE HTML>
<html>
<head>
	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
	<meta charset="utf8" />
	<title>Error</title>
	<style type="text/css">
		body {
			background-color: #{{.BackgroundColor}};
			color: #{{.ForegroundColor}};
		}
	</style>
</head>
	<body>
		<h1>HTTP Error {{.Code}}</h1>
		<p>{{.Message}}</p>
		<hr/>
		<pre>{{.Logs}}</pre>
	</body>
</html>
`))
