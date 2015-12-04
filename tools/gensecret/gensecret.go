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

package gensecretcmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/tamasd/ab/lib/log"
)

func CreateGenSecretCMD(logger *log.Log) *cobra.Command {
	gscmd := &cobra.Command{
		Use:   "gensecret",
		Short: "generates a secret value",
	}

	length := gscmd.Flags().Uint64("length", 32, "length of the secret value")

	gscmd.Run = func(c *cobra.Command, args []string) {
		buf := make([]byte, *length)
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			logger.User().Println(err)
			return
		}

		fmt.Println(hex.EncodeToString(buf))
	}

	return gscmd
}
