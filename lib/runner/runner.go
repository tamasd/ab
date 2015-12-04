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

package runner

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/util"
)

type Runner struct {
	Package        string
	Env            []string
	WaitOutput     bool
	OnStart        func()
	OnStop         func(bool)
	OnKill         func()
	Logger         *log.Log
	EnvPassthrough bool

	strgen func(int) string

	rerunch chan bool
	waitch  chan bool

	cmdMtx sync.Mutex
	out    io.ReadCloser
	cmd    *exec.Cmd

	quit chan struct{}
}

func NewRunner(pkg string, waitOutput bool) *Runner {
	return &Runner{
		Package:    pkg,
		WaitOutput: waitOutput,
		Logger:     log.DefaultOSLogger(),
		rerunch:    make(chan bool),
		waitch:     make(chan bool),
		quit:       make(chan struct{}),
		strgen:     util.RandomStringGenerator(),
	}
}

func (r *Runner) Start() error {
	defer r.kill()

	for {
		if r.shouldQuit() {
			r.kill()
			r.Logger.Trace().Println("quitting runner")
			return nil
		}

		r.Logger.Trace().Println("starting app")
		r.run()
		r.Logger.Trace().Println("done")

		if r.OnStart != nil {
			r.Logger.Trace().Println("running OnStart callback")
			r.OnStart()
			r.Logger.Trace().Println("done")
		}

		<-r.rerunch
		r.consumeRebuilds()

		r.Logger.Verbose().Println("Relaunching app")

		r.Logger.Trace().Println("killing app")
		r.kill()

		<-r.waitch
	}

	return nil
}

func (r *Runner) consumeRebuilds() {
	for {
		select {
		case <-r.rerunch:
		default:
			return
		}
	}
}

func (r *Runner) kill() {
	r.cmdMtx.Lock()
	defer r.cmdMtx.Unlock()

	if r.cmd != nil && r.cmd.Process != nil {
		r.Logger.Verbose().Printf("Killing process %d\n", r.cmd.Process.Pid)
		if err := r.cmd.Process.Kill(); err != nil {
			r.Logger.User().Println(err)
		} else {
			r.Logger.Trace().Println("killed app")
		}
	}

	if r.OnKill != nil {
		r.Logger.Trace().Println("running OnKill callback")
		r.OnKill()
		r.Logger.Trace().Println("done")
	}
}

func (r *Runner) Stop() {
	close(r.quit)
}

func (r *Runner) shouldQuit() bool {
	select {
	case <-r.quit:
		return true
	default:
	}

	return false
}

func (r *Runner) run() {
	if err := r.buildAndRun(); err != nil {
		r.Logger.User().Println(err)
		return
	}

	go r.wait()

	if r.WaitOutput {
		br := bufio.NewReader(r.out)
		line, _ := br.ReadString('\n')
		if len(line) > 1 {
			fmt.Print(line)
		}
	}

	go r.copyOutput()
}

func (r *Runner) build() (string, error) {
	name := os.TempDir() + "/" + r.strgen(8)
	out, err := exec.Command("go", "build", "-o", name, r.Package).CombinedOutput()
	if err != nil {
		r.Logger.Verbose().Println(string(out))
		return "", err
	}

	finfo, err := os.Stat(name)
	if err != nil {
		return "", err
	}

	mode := finfo.Mode()

	if err = os.Chmod(name, (mode&0000)|0700); err != nil {
		return "", err
	}

	return name, nil
}

func (r *Runner) buildAndRun() error {
	defer r.cmdMtx.Unlock()
	r.cmdMtx.Lock()

	artifact, err := r.build()
	if err != nil {
		return err
	}

	r.cmd = exec.Command(artifact)
	r.cmd.Env = []string{}
	if r.EnvPassthrough {
		r.cmd.Env = append(r.cmd.Env, os.Environ()...)
	}
	r.cmd.Env = append(r.cmd.Env, r.Env...)

	rd, rw := io.Pipe()
	r.out = rd

	r.cmd.Stdout = rw
	r.cmd.Stderr = rw

	return r.cmd.Start()
}

func (r *Runner) copyOutput() {
	br := bufio.NewReader(r.out)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			r.Logger.Verbose().Println(err)
			return
		}

		fmt.Print(line)
	}
}

func (r *Runner) wait() {
	err := r.cmd.Wait()
	r.Logger.Verbose().Println(err)
	r.Logger.Trace().Println("app finished")
	r.out.Close()

	if r.OnStop != nil {
		r.Logger.Trace().Println("running OnStop callback")
		r.OnStop(err != nil)
		r.Logger.Trace().Println("done")
	}

	if err = os.Remove(r.cmd.Path); err != nil {
		r.Logger.Verbose().Println(err)
	}

	r.waitch <- true
}

func (r *Runner) Rerun() {
	go func() {
		r.rerunch <- true
	}()
}
