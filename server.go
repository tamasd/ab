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
	"encoding/hex"
	"errors"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/julienschmidt/httprouter"
	"github.com/spf13/viper"
	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/util"
)

const paramKey = "abparam"

// A service is an unit of functionality. It probably has database objects, that will be checked an installed when the service is added to the server.
type Service interface {
	// Register the Service endpoints
	Register(*Server) error
	// Checks if the schema is installed
	SchemaInstalled(db DB) bool
	// Construct SQL string to install the schema
	SchemaSQL() string
}

// Sets up and starts a server.
//
// This function is a wrapper around PetBunny().
//
// Extra viper values:
//
// - secret: sets util.SetKey(). Must be hex.
func Hop(configure func(cfg *viper.Viper, s *Server) error, topMiddlewares ...func(http.Handler) http.Handler) {
	logger := log.DefaultOSLogger()
	cfg := viper.New()
	cfg.SetConfigName("config")
	cfg.AddConfigPath(".")
	cfg.AutomaticEnv()

	if err := cfg.ReadInConfig(); err != nil {
		logger.Verbose().Println(err)
	}

	secret, err := hex.DecodeString(cfg.GetString("secret"))
	if err != nil {
		logger.Fatalln(err)
	}
	if err := util.SetKey(secret); err != nil {
		logger.Fatalln(err)
	}

	s, err := PetBunny(cfg, logger, nil, topMiddlewares...)

	if err != nil {
		logger.Fatalln(err)
	}

	if err := configure(cfg, s); err != nil {
		logger.Fatalln(err)
	}

	cfg.SetDefault("host", "localhost")
	cfg.SetDefault("port", "8080")

	addr := cfg.GetString("host") + ":" + cfg.GetString("port")
	certFile := cfg.GetString("certfile")
	keyFile := cfg.GetString("keyfile")

	if err := s.StartHTTPS(addr, certFile, keyFile); err != nil {
		logger.Fatalln(err)
	}
}

// Sets up a Server with recommended middlewares.
//
// The parameters logger and eh can be nil, defaults will be log.DefaultOSLogger() and HandleErrors().
//
// topMiddlewares are middlewares that gets applied right after the logger middlewares, but before anything else.
//
// Viper has to be set up, and it has to contain a few values:
//
// - CookieSecret string: hex representation of the key bytes. Must be set.
//
// - PGConnectString string: connection string to Postgres. Must be set.
//
// - DBMaxIdleConn int: max idle connections. Defaults to 0 (no open connections are retained).
//
// - DBMaxOpenConn int: max open connections. Defaults to 0 (unlimited).
//
// - LogLevel int: log level for the logger. Use the numeric values of the log.LOG_* constants.
//
// - hsts (hsts.maxage float, hsts.includesubdomains bool, hsts.hostblacklist []string): configuration values for the HSTS middleware. See HSTSConfig structure
//
// - gzip bool: enabled the gzip middleware. Default is true.
//
// - CookiePrefix string: prefix for the session and the csrf cookies.
//
// - CookieURL string: domain and path configuration for the cookies.
//
// - assetsDir string: assets directory. The value - skips setting it up.
//
// - publicDir string: public directory. The value - skips setting it up.
//
// - root bool: sets / to serve assetsDir/index.html. Default is true.
func PetBunny(cfg *viper.Viper, logger *log.Log, eh ErrorHandler, topMiddlewares ...func(http.Handler) http.Handler) (*Server, error) {
	cookieSecret := cfg.GetString("CookieSecret")
	if cookieSecret == "" {
		return nil, errors.New("secret key must not be empty")
	}
	cookieSecretBytes, err := hex.DecodeString(cookieSecret)
	if err != nil {
		return nil, err
	}

	m, conn := DBMiddleware(cfg.GetString("PGConnectString"), cfg.GetInt("DBMaxIdleConn"), cfg.GetInt("DBMaxOpenConn"))

	s := NewServer(conn)

	if logger != nil {
		s.Logger = logger
	}

	s.Logger.Level = log.LogLevel(cfg.GetInt("LogLevel"))

	if len(topMiddlewares) > 0 {
		s.Use(topMiddlewares...)
	}

	requestLoggerOut := ioutil.Discard
	if s.Logger.Level > log.LOG_USER {
		requestLoggerOut = os.Stdout
	}

	s.Use(RequestLoggerMiddleware(requestLoggerOut))

	s.Use(DefaultLoggerMiddleware(s.Logger.Level))

	if cfg.IsSet("hsts") {
		hsts := &HSTSConfig{}
		cfg.UnmarshalKey("hsts", hsts)
		s.Use(HSTSMiddleware(*hsts))
	}

	cfg.SetDefault("gzip", true)
	if cfg.GetBool("gzip") {
		s.Use(gziphandler.GzipHandler)
	}

	if eh == nil {
		eh = ErrorHandlerFunc(HandleError)
	}
	s.Use(ErrorHandlerMiddleware(eh, s.Logger.Level > log.LOG_USER))

	s.Use(RendererMiddleware)

	cookiePrefix := cfg.GetString("CookiePrefix")
	var cookieURL *url.URL = nil
	if cfg.IsSet("CookieURL") {
		cookieURL, err = url.Parse(cfg.GetString("CookieURL"))
	}

	s.Use(SessionMiddleware(cookiePrefix, SecretKey(cookieSecretBytes), cookieURL, time.Hour*24*365))

	s.Use(CSRFCookieMiddleware(cookiePrefix, time.Hour*24*365, cookieURL))

	s.Use(CSRFMiddleware)
	s.Get("/api/token", http.HandlerFunc(CSRFTokenHandler))

	s.Use(m)

	cfg.SetDefault("assetsDir", "assets")
	cfg.SetDefault("publicDir", "public")

	assetsDir := cfg.GetString("assetsDir")
	publicDir := cfg.GetString("publicDir")

	if assetsDir != "-" {
		s.AddLocalDir("/assets", assetsDir)
	}
	if publicDir != "-" {
		s.AddLocalDir("/public", publicDir)
	}

	cfg.SetDefault("root", true)
	if cfg.GetBool("root") {
		s.AddFile("/", assetsDir+"/index.html")
	}

	return s, nil
}

// The main server struct.
type Server struct {
	*httprouter.Router
	conn        *sql.DB
	middlewares []func(http.Handler) http.Handler
	Logger      *log.Log
	TLSConfig   *tls.Config
}

// Creates a new server with a given cookie secret.
func NewServer(conn *sql.DB) *Server {
	router := httprouter.New()
	router.HandleMethodNotAllowed = false
	s := &Server{
		Router: router,
		conn:   conn,
		Logger: log.DefaultOSLogger(),
	}

	return s
}

func (s *Server) Use(middleware ...func(http.Handler) http.Handler) {
	s.middlewares = append(s.middlewares, middleware...)
}

func (s *Server) UseHandler(h http.Handler) {
	s.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
			next.ServeHTTP(w, r)
		})
	})
}

func (s *Server) Handler() http.Handler {
	return wrapHandler(s.Router, s.middlewares...)
}

func wrapHandler(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	return handler
}

func (s *Server) Handle(method, path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) {
	handler = wrapHandler(handler, middlewares...)
	s.Router.Handle(method, path, httprouter.Handle(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		r = SetContext(r, paramKey, p)
		handler.ServeHTTP(w, r)
	}))
}

func (s *Server) Head(path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("HEAD", path, handler, middlewares...)
}

func (s *Server) Get(path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("GET", path, handler, middlewares...)
}

func (s *Server) Post(path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("POST", path, handler, middlewares...)
}

func (s *Server) Put(path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("PUT", path, handler, middlewares...)
}

func (s *Server) Delete(path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("DELETE", path, handler, middlewares...)
}

func (s *Server) Patch(path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("PATCH", path, handler, middlewares...)
}

func (s *Server) Options(path string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("OPTIONS", path, handler, middlewares...)
}

func (s *Server) HeadF(path string, handler http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("HEAD", path, handler, middlewares...)
}

func (s *Server) GetF(path string, handler http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("GET", path, handler, middlewares...)
}

func (s *Server) PostF(path string, handler http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("POST", path, handler, middlewares...)
}

func (s *Server) PutF(path string, handler http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("PUT", path, handler, middlewares...)
}

func (s *Server) DeleteF(path string, handler http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("DELETE", path, handler, middlewares...)
}

func (s *Server) PatchF(path string, handler http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("PATCH", path, handler, middlewares...)
}

func (s *Server) OptionsF(path string, handler http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) {
	s.Handle("OPTIONS", path, handler, middlewares...)
}

func GetParams(r *http.Request) httprouter.Params {
	return r.Context().Value(paramKey).(httprouter.Params)
}

// Returns the server's DB connection if there's any.
func (s *Server) GetDBConnection() DB {
	return s.conn
}

// Adds a local directory to the router.
func (s *Server) AddLocalDir(prefix, path string) *Server {
	s.ServeFiles(prefix+"/*filepath", http.Dir(path))

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
	svc.Register(s)
	if s.conn != nil && !svc.SchemaInstalled(s.conn) {
		sql := svc.SchemaSQL()
		_, err := s.conn.Exec(sql)
		if err != nil {
			panic(err.Error() + "\n" + sql)
		}
	}
}

// Starts an HTTPS server.
func (s *Server) StartHTTPS(addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:      addr,
		Handler:   s.Handler(),
		TLSConfig: s.TLSConfig,
	}

	s.Logger.User().Printf("Starting server on %s\n", addr)

	if stdlogger, ok := s.Logger.User().(*stdlog.Logger); ok {
		srv.ErrorLog = stdlogger
	}

	var err error
	if certFile != "" && keyFile != "" {
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = srv.ListenAndServe()
	}

	return err
}

// Starts an HTTP server.
func (s *Server) StartHTTP(addr string) error {
	return s.StartHTTPS(addr, "", "")
}

// Redirects HTTP requests to HTTPS.
//
// httpsAddr and httpAddr must be host:port format, where the port can be omitted.
func HTTPSRedirectServer(httpsAddr, httpAddr string) error {
	srv := &http.Server{
		Addr: httpAddr,
	}

	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newUrl := "https://" + httpsAddr + "/" + r.RequestURI
		LogTrace(r).Printf("Redirecting %s to %s via HTTPSRedirectServer\n", r.URL.String(), newUrl)
		http.Redirect(w, r, newUrl, http.StatusMovedPermanently)
	})

	return srv.ListenAndServe()
}

func RedirectServer(addr, redirectAddr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr: addr,
	}

	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}
		newUrl := proto + "://" + redirectAddr + "/" + r.RequestURI

		LogTrace(r).Printf("Redirecting %s to %s via RedirectServer\n", r.URL.String(), newUrl)

		http.Redirect(w, r, newUrl, http.StatusMovedPermanently)
	})

	if certFile != "" && keyFile != "" {
		return srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		return srv.ListenAndServe()
	}
}
