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

package main

import (
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand"

	"github.com/spf13/cobra"
	"github.com/tamasd/ab/lib/log"
	"github.com/tamasd/ab/tools/entity"
	"github.com/tamasd/ab/tools/gensecret"
	"github.com/tamasd/ab/tools/watch"
)

func main() {
	seedRandom()

	logger := log.DefaultOSLogger()

	abtCmd := &cobra.Command{
		Use:   "abt",
		Short: "abt is a command line helper for the Alien Bunny kit",
	}

	var (
		verbose = abtCmd.PersistentFlags().Bool("verbose", false, "Turns on verbose mode")
		trace   = abtCmd.PersistentFlags().Bool("trace", false, "Turns on tracing and debug mode")
	)

	abtCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if *trace {
			logger.Level = log.LOG_TRACE
		} else if *verbose {
			logger.Level = log.LOG_VERBOSE
		}
	}

	abtCmd.AddCommand(
		entitycmd.CreateEntityCmd(logger),
		watchcmd.CreateWatchCmd(logger),
		gensecretcmd.CreateGenSecretCMD(logger),
	)

	abtCmd.Execute()
}

func seedRandom() {
	b := make([]byte, 8)
	crand.Read(b)
	s := binary.BigEndian.Uint64(b)
	mrand.Seed(int64(s))
}
