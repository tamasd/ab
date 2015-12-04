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

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/tamasd/ab/lib/log"
)

type LockProxy struct {
	sync.Locker
	Address            string
	ProxyAddress       string
	CertFile           string
	KeyFile            string
	SelfSigned         bool
	InsecureSkipVerify bool
	listener           net.Listener
	Logger             *log.Log
}

func NewLockProxy(l sync.Locker, addr, proxyAddr string) *LockProxy {
	return &LockProxy{
		Locker:       l,
		Address:      addr,
		ProxyAddress: proxyAddr,
		Logger:       log.DefaultOSLogger(),
	}
}

func (lp *LockProxy) IsHTTPS() bool {
	return lp.CertFile != "" && lp.KeyFile != ""
}

func (lp *LockProxy) director(r *http.Request) {
	lp.Lock()
	defer lp.Unlock()

	r.URL.Host = lp.ProxyAddress
	if r.TLS != nil {
		r.URL.Scheme = "https"
	} else {
		r.URL.Scheme = "http"
	}
}

func (lp *LockProxy) createTransport(tlsConfig *tls.Config) http.RoundTripper {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
	}
}

func (lp *LockProxy) createSelfSignedTransport() http.RoundTripper {
	pemData, err := ioutil.ReadFile(lp.CertFile)
	if err != nil {
		lp.Logger.User().Println(err)
		return nil
	}
	lp.Logger.Trace().Printf("read certificate:\n%s\n", string(pemData))

	tlsConfig := &tls.Config{
		RootCAs: x509.NewCertPool(),
	}

	if !tlsConfig.RootCAs.AppendCertsFromPEM(pemData) {
		lp.Logger.User().Printf("Failed to add self-signed certificate to the reverse proxy: %s\n", lp.CertFile)
		return nil
	}

	lp.Logger.Trace().Println("using custom transport with self-signed certificate")

	return lp.createTransport(tlsConfig)
}

func (lp *LockProxy) createInsecureTransport() http.RoundTripper {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	lp.Logger.Trace().Println("using insecure transport")

	return lp.createTransport(tlsConfig)
}

func (lp *LockProxy) transport() http.RoundTripper {
	var rt http.RoundTripper

	if lp.SelfSigned {
		rt = lp.createSelfSignedTransport()
		if rt != nil {
			return rt
		}
	}

	if lp.InsecureSkipVerify {
		return lp.createInsecureTransport()
	}

	lp.Logger.Trace().Println("using default transport")
	return nil
}

func (lp *LockProxy) reverseProxy() http.Handler {
	var logger *stdlog.Logger = nil
	if l, ok := lp.Logger.Verbose().(*stdlog.Logger); ok {
		logger = l
	}

	return &httputil.ReverseProxy{
		Director:  lp.director,
		ErrorLog:  logger,
		Transport: lp.transport(),
	}
}

func (lp *LockProxy) Start() error {
	s := &http.Server{
		Addr:    lp.Address,
		Handler: lp.reverseProxy(),
	}

	s.SetKeepAlivesEnabled(false)

	if lp.IsHTTPS() {
		return s.ListenAndServeTLS(lp.CertFile, lp.KeyFile)
	} else {
		return s.ListenAndServe()
	}
}
