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

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"

	"github.com/tamasd/ab"
)

// Generates and saves a new token.
func CreateToken(db ab.DB, uuid, category string, expires *time.Time) (string, error) {
	buf := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", err
	}

	token := hex.EncodeToString(buf)

	return token, setToken(db, uuid, category, token, expires)
}

func setToken(db ab.DB, uuid, category, token string, expires *time.Time) error {
	_, err := db.Exec("INSERT INTO token(uuid, category, token, expires) VALUES($1, $2, $3, $4)",
		uuid,
		category,
		token,
		expires,
	)
	return err
}

// Consumes a saved token.
//
// This function deletes the token from the database.
func ConsumeToken(db ab.DB, uuid, category, token string) (bool, error) {
	res, err := db.Exec("DELETE FROM token WHERE uuid = $1 AND category = $2 AND token = $3 AND (expires IS NULL OR expires > $4)", uuid, category, token, time.Now())

	if err != nil {
		return false, err
	}

	aff, err := res.RowsAffected()

	return aff > 0, err
}

// Removes all expired tokens from the dataabase.
func RemoveExpiredTokens(db ab.DB) error {
	_, err := db.Exec("DELETE FROM token WHERE expires < $1", time.Now())
	return err
}
