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
	"crypto/tls"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/nbio/hitch"
	"github.com/tamasd/hitch-requestlogger"
	"github.com/tamasd/hitch-session"
)

// The service is a concept than an actual distinction from regular endpoints. A service is an unit of functionality. It probably has database objects, that will be checked an installed when the service is added to the server.
type Service interface {
	// Register the Service endpoints
	Register(*hitch.Hitch) error
	// Checks if the schema is installed
	SchemaInstalled(db DB) bool
	// Construct SQL string to install the schema
	SchemaSQL() string
}

// Contains configuration options for PetBunny.
type ServerConfig struct {
	AssetsDir string // Asssets directory path.
	PublicDir string // Public directory path.

	// Disables the automatic GZIP compression.
	DisableGzip bool

	// Prefix for the session cookie.
	CookiePrefix string
	// Secret for the session cookie's signature. This must not be empty.
	CookieSecret session.SecretKey

	// Connection string for the database.
	PGConnectString string
	// Number of maximum open connections.
	DBMaxOpenConn int
	// Number of maximum idle connections.
	DBMaxIdleConn int

	// Enables verbose logging, and logging to the HTML output.
	DevelopmentMode bool

	// The server's error handler. Defaults to HandleError().
	ErrorHandler ErrorHandler

	// Logger for the server.
	Logger *log.Logger

	// Enables HSTS (RFC 6797). Strongly recommended for HTTPS websites.
	HSTS *HSTSConfig
}

// Sets up a Server with recommended middlewares.
func PetBunny(cfg ServerConfig, topMiddlewares ...func(http.Handler) http.Handler) *Server {
	if cfg.CookieSecret == nil {
		panic("secret key must not be empty")
	}

	m, conn := DBMiddleware(cfg.PGConnectString, cfg.DBMaxIdleConn, cfg.DBMaxOpenConn)

	s := NewServer(conn)

	if cfg.Logger != nil {
		s.Logger = cfg.Logger
	}

	if len(topMiddlewares) > 0 {
		s.Use(topMiddlewares...)
	}

	if cfg.DevelopmentMode {
		logger := log.New(os.Stdout, "", 0)
		s.Use(requestlogger.HitchRequestLogger(logger))
	}

	if cfg.HSTS != nil {
		s.Use(HTSTMiddleware(*cfg.HSTS))
	}

	if !cfg.DisableGzip {
		s.Use(gziphandler.GzipHandler)
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = ErrorHandlerFunc(HandleError)
	}
	s.Use(ErrorHandlerMiddleware(cfg.ErrorHandler, s.Logger, cfg.DevelopmentMode))

	s.Use(RendererMiddleware)

	s.Use(session.HitchSession(cfg.CookiePrefix, cfg.CookieSecret, time.Hour*24*365))

	s.Use(CSRFCookieMiddleware(cfg.CookiePrefix, time.Hour*24*365))

	s.Use(CSRFMiddleware)
	s.Get("/api/token", http.HandlerFunc(CSRFTokenHandler))

	s.Use(m)

	if cfg.AssetsDir == "" {
		cfg.AssetsDir = "assets"
	}

	if cfg.PublicDir == "" {
		cfg.PublicDir = "public"
	}

	if cfg.AssetsDir != "-" {
		s.AddLocalDir("/assets", cfg.AssetsDir)
	}
	if cfg.PublicDir != "-" {
		s.AddLocalDir("/public", cfg.PublicDir)
	}

	s.AddFile("/", cfg.AssetsDir+"/index.html")

	return s
}

// The main server struct.
type Server struct {
	*hitch.Hitch
	conn *sql.DB

	// Logger for the server.
	Logger *log.Logger

	TLSConfig *tls.Config
}

// Creates a new server with a given cookie secret.
func NewServer(conn *sql.DB) *Server {
	s := &Server{
		Hitch:  hitch.New(),
		Logger: log.New(os.Stderr, "", log.LstdFlags),
		conn:   conn,
	}

	return s
}

// Returns the server's DB connection if there's any.
func (s *Server) GetDBConnection() DB {
	return s.conn
}

// Adds a local directory to the router.
func (s *Server) AddLocalDir(prefix, path string) *Server {
	s.Hitch.Router.ServeFiles(prefix+"/*filepath", http.Dir(path))

	return s
}

// Adds a local file to the router.
func (s *Server) AddFile(path, file string) *Server {
	s.Get(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, file)
	}))

	return s
}

// Registers a service on the server.
//
// See the Service interface for more information.
func (s *Server) RegisterService(svc Service) {
	svc.Register(s.Hitch)
	if s.conn != nil && !svc.SchemaInstalled(s.conn) {
		sql := svc.SchemaSQL()
		_, err := s.conn.Exec(sql)
		if err != nil {
			panic(err.Error() + "\n" + sql)
		}
	}
}

// Starts an HTTPS server.
func (s *Server) StartHTTPS(addr, certFile, keyFile string) {
	srv := &http.Server{
		Addr:      addr,
		Handler:   s.Hitch.Handler(),
		ErrorLog:  s.Logger,
		TLSConfig: s.TLSConfig,
	}

	s.Logger.Printf("Starting server on %s\n", addr)

	var err error
	if certFile != "" && keyFile != "" {
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = srv.ListenAndServe()
	}

	log.Fatal(err)
}

// Starts an HTTP server.
func (s *Server) StartHTTP(addr string) {
	s.StartHTTPS(addr, "", "")
}

// Redirects HTTP requests to HTTPS.
//
// httpsAddr and httpAddr must be host:port format, where the port can be omitted.
func HTTPSRedirectServer(httpsAddr, httpAddr string) error {
	srv := &http.Server{
		Addr: httpAddr,
	}

	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+httpsAddr+"/"+r.RequestURI, http.StatusMovedPermanently)
	})

	return srv.ListenAndServe()
}
