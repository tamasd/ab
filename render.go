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
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"html/template"
	"io"
	"net/http"

	"github.com/golang/gddo/httputil"
	"github.com/nbio/httpcontext"
)

const renderKey = "abrender"

// Global switch for the ")]}',\n" JSON response prefix.
//
// This prefix increases security for browser-based applications, but requires extra support on the client side.
var JSONPrefix = true

// Middleware for the Render API.
//
// This middleware is automatically added with PetBunny.
//
// This changes the behavior of the ResponseWriter in the following middlewares and the page handler. The ResponseWriter's WriteHeader() method will not write the headers, just sets the Code attribute of the Renderer struct in the page context. This hack is necessary, because else a middleware could write the headers before the Renderer. Given the default configuration, the session middleware comes after the RendererMiddleware (so the session middleware has a chance to set its session cookie), and the session middleware always calls WriteHeader(). See the rendererResponseWriter.WriteHeader() method's documentation for more details.
func RendererMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderer := NewRenderer()
		httpcontext.Set(r, renderKey, renderer)
		next.ServeHTTP(&rendererResponseWriter{
			ResponseWriter: w,
			Renderer:       renderer,
		}, r)
		renderer.Render(w, r)
	})
}

// Gets the Renderer struct from the request context.
func Render(r *http.Request) *Renderer {
	return httpcontext.Get(r, renderKey).(*Renderer)
}

// A per-request struct for the Render API.
//
// The Render API handles content negotiation with the client. The server's preference is the order how the offers are added by either the AddOffer() low-level method or the JSON()/HTML()/Text() higher level methods.
//
// A quick example how to use the Render API:
//
//     func pageHandler(w http.ResponseWriter, r *http.Request) {
//         ...
//         ab.Render(r).
//             HTML(pageTemplate, data).
//             JSON(data)
//     }
//
// In this example, the server prefers rendering an HTML page / fragment, but it can render a JSON if that's the client's preference. The default is HTML, because that is the first offer.
type Renderer struct {
	handlers map[string]func(w http.ResponseWriter)
	offers   []string
	rendered bool
	Code     int // HTTP status code.
}

// Creates a new Renderer.
func NewRenderer() *Renderer {
	return &Renderer{
		handlers: make(map[string]func(w http.ResponseWriter)),
		offers:   make([]string, 0),
		rendered: false,
		Code:     0,
	}
}

// Sets the HTTP status code.
func (r *Renderer) SetCode(code int) *Renderer {
	r.Code = code
	return r
}

// Adds an offer for the content negotiation.
//
// See the Render() method for more information. The mediaType is the content type, the handler renders the data to the ResponseWriter.
// You probably want to use the JSON(), HTML(), Text() methods instead of this.
func (r *Renderer) AddOffer(mediaType string, handler func(w http.ResponseWriter)) *Renderer {
	r.offers = append(r.offers, mediaType)
	r.handlers[mediaType] = handler

	return r
}

// Adds a binary file offer for the Renderer struct.
//
// If reader is an io.ReadCloser, it will be closed automatically.
func (r *Renderer) Binary(mediaType, filename string, reader io.Reader) *Renderer {
	return r.AddOffer(mediaType, func(w http.ResponseWriter) {
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		io.Copy(w, reader)
		if rc, ok := reader.(io.ReadCloser); ok {
			rc.Close()
		}
	})
}

// Adds a JSON offer for the Renderer struct.
func (r *Renderer) JSON(v interface{}) *Renderer {
	return r.AddOffer("application/json", func(w http.ResponseWriter) {
		if JSONPrefix {
			w.Write([]byte(")]}',\n"))
		}
		json.NewEncoder(w).Encode(v)
	})
}

// Adds an HTML offer for the Renderer struct.
func (r *Renderer) HTML(t *template.Template, v interface{}) *Renderer {
	return r.AddOffer("text/html", func(w http.ResponseWriter) {
		t.Execute(w, v)
	})
}

// Adds a plain text offer for the Renderer struct.
func (r *Renderer) Text(t string) *Renderer {
	return r.AddOffer("text/plain", func(w http.ResponseWriter) {
		w.Write([]byte(t))
	})
}

// Adds XML offer for the Renderer object.
//
// If pretty is set, the XML will be indented.
// Also text/xml content type header will be sent instead of application/xml.
func (r *Renderer) XML(v interface{}, pretty bool) *Renderer {
	mt := "application/xml"
	if pretty {
		mt = "text/xml"
	}

	return r.AddOffer(mt, func(w http.ResponseWriter) {
		e := xml.NewEncoder(w)
		if pretty {
			e.Indent("", "\t")
		}
		e.Encode(v)
	})
}

// Adds a CSV offer for the Renderer object.
//
// Use this function for smaller CSV responses.
func (r *Renderer) CSV(records [][]string) *Renderer {
	return r.AddOffer("text/csv", func(w http.ResponseWriter) {
		csv.NewWriter(w).WriteAll(records)
	})
}

// Adds a CSV offer for the Renderer object.
//
// The records are streamed through a channel.
func (r *Renderer) CSVChannel(records <-chan []string) *Renderer {
	return r.AddOffer("text/csv", func(w http.ResponseWriter) {
		csvw := csv.NewWriter(w)
		for record := range records {
			csvw.Write(record)
		}
	})
}

// Adds a CSV offer for the Renderer object.
//
// The records are generated with a generator function. If the function
// returns an error, the streaming to the output stops.
func (r *Renderer) CSVGenerator(recgen func(http.Flusher) ([]string, err)) *Renderer {
	return r.AddOffer("text/csv", func(w http.ResponseWriter) {
		csvw := csv.NewWriter(w)
		for {
			record, err := recgen(csvw)
			if err != nil {
				return
			}
			csvw.Write(record)
		}
	})
}

// Renders best offer to the ResponseWriter according to the client's content type preferences.
func (rr *Renderer) Render(w http.ResponseWriter, r *http.Request) {
	if rr.rendered {
		return
	}

	defer func() {
		rr.rendered = true
	}()

	if len(rr.offers) == 0 {
		if rr.Code == 0 || rr.Code == http.StatusOK {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(rr.Code)
		}
		return
	}

	ct := rr.offers[0]
	if len(rr.offers) > 1 {
		ct = httputil.NegotiateContentType(r, rr.offers, ct)
	}

	w.Header().Add("Content-Type", ct)

	if rr.Code > 0 {
		w.WriteHeader(rr.Code)
	}

	rr.handlers[ct](w)
}

type rendererResponseWriter struct {
	http.ResponseWriter
	*Renderer
}

func (r *rendererResponseWriter) Write(b []byte) (int, error) {
	if !r.Renderer.rendered {
		r.ResponseWriter.WriteHeader(r.Renderer.Code)
		r.Renderer.rendered = true
	}
	return r.ResponseWriter.Write(b)
}

// Overwrite of the WriteHeader function of the http.ResponseWriter interface.
//
// The reason why this method does not write the headers is that it allows the Renderer
// middleware to output the response code along with the HTTP headers.
// Without this hack, middlewares could output the headers before the
// Renderer would. With the default settings, the session middleware always
// calls WriteHeader(), prohibiting the Renderer to work properly.
//
// However this method overwrites the Renderer's status code if the code is not set or the new code is not 200 or 0.
func (r *rendererResponseWriter) WriteHeader(code int) {
	if r.Renderer.Code == 0 || (code != http.StatusOK && code != 0) {
		r.Renderer.SetCode(code)
	}
}
