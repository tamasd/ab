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

package util

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestEncDec(t *testing.T) {
	Convey("Given a random key", t, func() {
		key := make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, key)
		So(err, ShouldBeNil)
		So(SetKey(key), ShouldBeNil)

		Convey("A secret message should be encrypted and decrypted", func() {
			rawmsg := make([]byte, 4096)
			_, err := io.ReadFull(rand.Reader, rawmsg)
			So(err, ShouldBeNil)
			msg := hex.EncodeToString(rawmsg)

			encrypted := EncryptString(msg)
			So(encrypted, ShouldNotEqual, "")

			decrypted := DecryptString(encrypted)
			So(decrypted, ShouldEqual, msg)
		})
	})
}

func TestGeneratePlaceholders(t *testing.T) {
	Convey("Given placeholder intervals", t, func() {
		intervals := map[string]string{
			"1...1": "",
			"1...2": "$1",
			"1...5": "$1, $2, $3, $4",
		}

		for interval, value := range intervals {
			Convey(interval+" must generate "+value, func() {
				bounds := strings.Split(interval, "...")
				start, _ := strconv.Atoi(bounds[0])
				end, _ := strconv.Atoi(bounds[1])
				result := GeneratePlaceholders(uint(start), uint(end))
				So(result, ShouldEqual, value)
			})
		}
	})
}
