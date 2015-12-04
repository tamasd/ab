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

package watcher

import (
	"io"
	"os"
	"path"
	"strings"

	"github.com/tamasd/ab/lib/log"
	"gopkg.in/fsnotify.v1"
)

type Watcher struct {
	Ignores []Ignorer
	Logger  *log.Log
	watcher *fsnotify.Watcher
	stop    chan struct{}
	Action  func(string)
	Error   func(error)
}

func NewWatcher() *Watcher {
	return &Watcher{
		stop:   make(chan struct{}),
		Logger: log.DefaultOSLogger(),
	}
}

func (w *Watcher) Watch(dir string) error {
	var err error
	w.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	if err = w.watch(dir); err != nil {
		w.watcher.Close()
		return err
	}

	return w.listen()
}

func (w *Watcher) listen() error {
	for {
		select {
		case event := <-w.watcher.Events:
			if event.Op&fsnotify.Create > 0 {
				err := w.watch(event.Name)
				if err != nil {
					w.Logger.Verbose().Println(err)
				}
			}
			if event.Op&fsnotify.Chmod == 0 {
				w.Logger.Verbose().Println(event)
				if w.Action != nil {
					w.Action(event.Name)
				}
			}
		case err := <-w.watcher.Errors:
			if err != nil {
				w.Logger.Verbose().Println(err)
				if w.Error != nil {
					w.Error(err)
				}
			}
		}
	}

	return nil
}

func (w *Watcher) Close() error {
	return w.watcher.Close()
}

func (w *Watcher) watch(name string) error {
	if w.ignored(name) {
		return nil
	}

	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	if stat.IsDir() {
		return w.watchDir(name, f)
	} else {
		f.Close()
		return w.watchFile(name)
	}
}

func (w *Watcher) watchDir(path string, dir *os.File) error {
	if err := w.watcher.Add(path); err != nil {
		return err
	}

	names, err := dir.Readdirnames(0)
	dir.Close()
	if err != nil {
		if err == io.EOF {
			return nil
		}

		return err
	}

	w.Logger.Verbose().Printf("Watching directory %s\n", path)

	for _, name := range names {
		if err = w.watch(path + string(os.PathSeparator) + name); err != nil {
			return err
		}
	}

	return nil
}

func (w *Watcher) watchFile(name string) error {
	w.Logger.Verbose().Printf("Watching file %s\n", name)
	return w.watcher.Add(name)
}

func (w *Watcher) ignored(name string) bool {
	base := path.Base(name)
	for _, i := range w.Ignores {
		if i.Ignored(base) {
			return true
		}
	}

	return false
}

func isGoFile(path string) bool {
	return strings.HasSuffix(path, ".go")
}
