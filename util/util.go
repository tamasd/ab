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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// Generates placeholders from start to end for an SQL query.
func GeneratePlaceholders(start, end uint) string {
	ret := ""
	if start == end {
		return ret
	}
	for i := start; i < end; i++ {
		ret += ", $" + strconv.Itoa(int(i))
	}

	return ret[2:]
}

// Converts a string slice into an interface{} slice.
func StringSliceToInterfaceSlice(s []string) []interface{} {
	is := make([]interface{}, len(s))
	for i, d := range s {
		is[i] = d
	}

	return is
}

// Reads the whole response body and converts it to a string.
func ResponseBodyToString(r *http.Response) string {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		return ""
	}

	return string(b)
}

const keySize = 2048

// Generates an RSA key (2048 bit) and encodes it using PEM.
func GenerateKey() string {
	prikey, _ := rsa.GenerateKey(rand.Reader, keySize)

	marshalled := x509.MarshalPKCS1PrivateKey(prikey)

	prikeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   marshalled,
	})

	return string(prikeyPEM)
}

// Parses a PEM private key. Returns nil on failure.
func ParsePrivateKey(key string) *rsa.PrivateKey {
	marshaled, _ := pem.Decode([]byte(key))
	prikey, err := x509.ParsePKCS1PrivateKey(marshaled.Bytes)
	if err != nil {
		return nil
	}

	return prikey
}

// Gets the public part of a private key in OpenSSL format.
func GetPublicKey(key *rsa.PrivateKey) string {
	pkey, _ := ssh.NewPublicKey(&key.PublicKey)
	marshalled := pkey.Marshal()

	return "ssh-rsa " + base64.StdEncoding.EncodeToString(marshalled) + "\n"
}

var aesgcm cipher.AEAD

// Sets the package global secret. The size of the secret should be 32 bytes. See Encrypt() and Decrypt()
func SetKey(key []byte) error {
	aescipcher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err = cipher.NewGCM(aescipcher)
	if err != nil {
		return err
	}

	return nil
}

// Encrypts a message with RSA using the package global key.
func Encrypt(msg []byte) []byte {
	nonce := make([]byte, aesgcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	buf := bytes.NewBuffer(nil)
	buf.Write(nonce)

	encrypted := aesgcm.Seal(nil, nonce, msg, nil)
	buf.Write(encrypted)

	return buf.Bytes()
}

// Decrypts a message with RSA using the package global key.
func Decrypt(msg []byte) []byte {
	noncelen := aesgcm.NonceSize()
	nonce := msg[:noncelen]
	encrypted := msg[noncelen:]

	data, err := aesgcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		log.Println(err)
		return []byte{}
	}

	return data
}

// Encrypts a string using the package global key.
func EncryptString(msg string) string {
	if msg == "" {
		return ""
	}

	return base64.StdEncoding.EncodeToString(Encrypt([]byte(msg)))
}

// Decrypts a string using the package global key.
func DecryptString(msg string) string {
	if msg == "" {
		return ""
	}

	decoded, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		panic(err)
	}

	return string(Decrypt(decoded))
}

var colorCodeRegex = regexp.MustCompile(`\[[0-9;]+m`)

func StripTerminalColorCodes(s string) string {
	return colorCodeRegex.ReplaceAllString(s, "")
}
