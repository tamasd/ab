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

package watchcmd

import (
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/lib/proxy"
	"github.com/tamasd/ab/lib/runner"
	"github.com/tamasd/ab/lib/watcher"
)

type runConfig struct {
	Package    string
	WaitOutput bool
	Addrs      []*addrConfig
	Ignore     []string
}

func (rc *runConfig) String() string {
	rc.ensureAddrConfig()

	str := "Package: " + rc.Package

	if rc.WaitOutput {
		str += "\nWaiting for a line"
	}

	for _, a := range rc.Addrs {
		str += "\n" + a.String()
	}

	return str
}

func (rc *runConfig) env() []string {
	rc.ensureAddrConfig()

	env := []string{}

	for _, a := range rc.Addrs {
		env = append(env, a.env()...)
	}

	return env
}

func (rc *runConfig) ensureAddrConfig() {
	if len(rc.Addrs) > 0 {
		return
	}

	rc.Addrs = []*addrConfig{
		&addrConfig{
			Host:    "localhost",
			Port:    8080,
			HostEnv: "HOST",
			PortEnv: "PORT",
		},
	}
}

type addrConfig struct {
	Host               string
	Port               uint16
	HostEnv            string
	PortEnv            string
	AddrEnv            string
	ProxyHost          string
	ProxyPort          uint16
	CertFile           string
	KeyFile            string
	SelfSigned         bool
	InsecureSkipVerify bool
}

func (ac *addrConfig) String() string {
	ac.ensureProxySettings()

	envs := ""
	if ac.AddrEnv != "" {
		envs = ac.AddrEnv
	} else {
		envs = ac.HostEnv + " " + ac.PortEnv
	}

	https := ""
	if ac.CertFile != "" && ac.KeyFile != "" {
		https = " cert=" + ac.CertFile + " key=" + ac.KeyFile
		if ac.SelfSigned {
			https += " self signed"
		}
		if ac.InsecureSkipVerify {
			https += " InsecureSkipVerify"
		}
	}

	return fmt.Sprintf("%s:%d -> %s:%d env: %s%s",
		ac.Host, ac.Port,
		ac.ProxyHost, ac.ProxyPort,
		envs, https,
	)
}

func (ac *addrConfig) ensureProxySettings() {
	if ac.ProxyHost == "" {
		ac.ProxyHost = "localhost"
	}

	if ac.ProxyPort == 0 {
		ac.ProxyPort = uint16(rand.Intn(30000) + 10000)
	}
}

func (ac *addrConfig) addr() string {
	ac.ensureProxySettings()

	return fmt.Sprintf("%s:%d", ac.Host, ac.Port)
}

func (ac *addrConfig) proxyAddr() string {
	ac.ensureProxySettings()

	return fmt.Sprintf("%s:%d", ac.ProxyHost, ac.ProxyPort)
}

func (ac *addrConfig) env() []string {
	ac.ensureProxySettings()

	env := []string{}

	if ac.AddrEnv != "" {
		e := fmt.Sprintf("%s=%s:%d", ac.AddrEnv, ac.ProxyHost, ac.ProxyPort)
		env = append(env, e)
	} else {
		if ac.HostEnv != "" {
			env = append(env, ac.HostEnv+"="+ac.ProxyHost)
		}
		if ac.PortEnv != "" {
			env = append(env, fmt.Sprintf("%s=%d", ac.PortEnv, ac.ProxyPort))
		}
	}

	return env
}

func CreateWatchCmd(logger *log.Log) *cobra.Command {
	watchCmd := &cobra.Command{
		Use:   "watch",
		Short: "restarts app on file changes",
	}

	watchCmd.Run = func(cmd *cobra.Command, args []string) {
		var rwmtx sync.RWMutex
		var wg sync.WaitGroup

		cfg := viper.New()
		cfg.SetConfigName("abtwatch")
		cfg.AddConfigPath(".")
		cfg.AutomaticEnv()
		if err := cfg.ReadInConfig(); err != nil {
			logger.Fatalln(err)
		}

		cfg.SetDefault("Package", ".")

		rc := &runConfig{}
		if err := cfg.Unmarshal(rc); err != nil {
			logger.Fatalln(err)
		}

		rc.ensureAddrConfig()

		logger.Verbose().Println(rc.String())

		w := watcher.NewWatcher()
		w.Logger = logger
		w.Ignores = setupIgnores(rc.Ignore, logger)

		r := runner.NewRunner(rc.Package, rc.WaitOutput)
		r.Logger = logger
		r.Env = rc.env()
		r.EnvPassthrough = true
		defer r.Stop()

		r.OnStart = func() {
			logger.Verbose().Println("Unlocking proxies")
			rwmtx.Unlock()
		}

		r.OnStop = func(success bool) {
			logger.Verbose().Println("Locking proxies")
			rwmtx.Lock()
		}

		w.Action = func(s string) {
			r.Rerun()
		}

		w.Error = func(err error) {
			logger.User().Println(err)
		}

		rwmtx.Lock() // Lock the proxy until the first build completes

		for _, a := range rc.Addrs {
			p := proxy.NewLockProxy(rwmtx.RLocker(), a.addr(), a.proxyAddr())
			p.Logger = logger
			p.CertFile, p.KeyFile = a.CertFile, a.KeyFile
			p.SelfSigned, p.InsecureSkipVerify = a.SelfSigned, a.InsecureSkipVerify

			wg.Add(1)
			go func() {
				defer wg.Done()
				logger.User().Println(p.Start())
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.User().Println(w.Watch("."))
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.User().Println(r.Start())
		}()

		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt)
			for _ = range c {
				r.Stop()
				w.Close()
				os.Exit(1) // TODO better error code
			}
		}()

		wg.Wait()
	}

	return watchCmd
}

func setupIgnores(ignoreConfig []string, logger *log.Log) []watcher.Ignorer {
	ignores := []watcher.Ignorer{}
	ignoreLines := []string{}

	for _, line := range ignoreConfig {
		if len(line) > 0 {
			ignores = append(ignores, watcher.NewStringIgnorer(line)) // TODO support for gitignore style ignores
			ignoreLines = append(ignoreLines, line)
		}
	}

	if len(ignoreLines) > 0 {
		logger.Verbose().Println("Ignoring: " + strings.Join(ignoreLines, ", "))
	}

	return ignores
}
