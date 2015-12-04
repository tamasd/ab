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

package log

import (
	"io"
	"log"
	"os"

	"github.com/agtorre/gocolorize"
)

type LogLevel int8

const (
	LOG_USER LogLevel = iota
	LOG_VERBOSE
	LOG_TRACE
	LOG_OFF = -1
)

type Logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

var (
	userPrefix    = ""
	verbosePrefix = gocolorize.NewColor("white+b:magenta").Paint("DEBUG") + " "
	tracePrefix   = gocolorize.NewColor("black+b:white").Paint("TRACE") + " "
)

func UserLogFactory(w io.Writer) Logger {
	return log.New(w, userPrefix, log.LstdFlags)
}

func VerboseLogFactory(w io.Writer) Logger {
	return log.New(w, verbosePrefix, log.Lshortfile)
}

func TraceLogFactory(w io.Writer) Logger {
	return log.New(w, tracePrefix, log.Ltime|log.Lmicroseconds|log.Lshortfile)
}

type Log struct {
	Level   LogLevel
	user    Logger
	verbose Logger
	trace   Logger
	empty   Logger
}

func NewLogger(user, verbose, trace Logger) *Log {
	return &Log{
		user:    user,
		verbose: verbose,
		trace:   trace,
		empty:   emptyLogger{},
	}
}

func DefaultLogger(w io.Writer) *Log {
	return NewLogger(
		UserLogFactory(w),
		VerboseLogFactory(w),
		TraceLogFactory(w),
	)
}

func DefaultOSLogger() *Log {
	return DefaultLogger(os.Stdout)
}

func (l *Log) User() Logger {
	if l.Level >= LOG_USER {
		return l.user
	}
	return l.empty
}

func (l *Log) Verbose() Logger {
	if l.Level >= LOG_VERBOSE {
		return l.verbose
	}

	return l.empty
}

func (l *Log) Trace() Logger {
	if l.Level >= LOG_TRACE {
		return l.trace
	}

	return l.empty
}

func (l *Log) Fatal(v ...interface{}) {
	l.User().Print(v...)
	os.Exit(1)
}

func (l *Log) Fatalln(v ...interface{}) {
	l.User().Println(v...)
	os.Exit(1)
}

func (l *Log) Fatalf(format string, v ...interface{}) {
	l.User().Printf(format, v...)
	os.Exit(1)
}

var _ Logger = emptyLogger{}

type emptyLogger struct{}

func (e emptyLogger) Print(v ...interface{}) {
}

func (e emptyLogger) Printf(format string, v ...interface{}) {
}

func (e emptyLogger) Println(v ...interface{}) {
}
