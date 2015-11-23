// +build gofuzz

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
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
)

var key SecretKey

func init() {
	key = make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatal(err)
	}
}

func Fuzz(data []byte) int {
	signature := key.sign(data)
	cookieValue := hex.EncodeToString(signature) + hex.EncodeToString(data)

	if _, err := readCookie(cookieValue, key); err != nil {
		return 0
	}

	return 1
}
