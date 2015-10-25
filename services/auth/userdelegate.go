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
	"net/http"

	"github.com/tamasd/ab"
	"github.com/tamasd/hitch-session"
)

// Delegate interface for user management. This decouples the user management from the auth service.
type UserDelegate interface {
	IsLoggedIn(r *http.Request) bool
	CurrentUser(r *http.Request) string
	LoginUser(r *http.Request, uuid string)
}

var _ UserDelegate = &SessionUserDelegate{}

// A session-based user delegate, that stores the current user's UUID in the "uid" key of the session.
//
// The DB value is optional. If provided, the delegate assumes that a table named "user" exists, and it has a UUID field which is its primary key.
type SessionUserDelegate struct {
	DB         ab.DB
	TableName  string // Name of the user table, defaults to "user"
	UUIDColumn string // Name of the uuid column, defaults to "uuid"
}

func (ud *SessionUserDelegate) IsLoggedIn(r *http.Request) bool {
	uid := session.GetSession(r)["uid"]

	if uid == "" {
		return false
	}

	if ud.DB != nil {
		count := 0
		tableName := ud.TableName
		if tableName == "" {
			tableName = "user"
		}
		uuidColumn := ud.UUIDColumn
		if uuidColumn == "" {
			uuidColumn = "uuid"
		}
		err := ud.DB.QueryRow("SELECT COUNT("+uuidColumn+") FROM \""+tableName+"\" WHERE "+uuidColumn+" = $1", uid).Scan(&count)
		if err != nil {
			panic(err)
		}
		return count > 0
	}

	return true
}

func (ud *SessionUserDelegate) CurrentUser(r *http.Request) string {
	return session.GetSession(r)["uid"]
}

func (ud *SessionUserDelegate) LoginUser(r *http.Request, uuid string) {
	session.GetSession(r)["uid"] = uuid
}

var _ UserDelegate = &MultiUserDelegate{}

// This user delegate allows using multiple user delegats as if they were one.
//
// The LoginUserDelegate decides which delegates should perform the login; if left empty, then all delegates will login.
type MultiUserDelegate struct {
	delegates         []UserDelegate
	LoginUserDelegate func([]UserDelegate) []UserDelegate
}

func NewMultiUserDelegate(delegates ...UserDelegate) *MultiUserDelegate {
	return &MultiUserDelegate{
		delegates: delegates,
	}
}

func (mud *MultiUserDelegate) IsLoggedIn(r *http.Request) bool {
	for _, d := range mud.delegates {
		if d.IsLoggedIn(r) {
			return true
		}
	}

	return false
}

func (mud *MultiUserDelegate) CurrentUser(r *http.Request) string {
	for _, d := range mud.delegates {
		if u := d.CurrentUser(r); u != "" {
			return u
		}
	}

	return ""
}

func (mud *MultiUserDelegate) LoginUser(r *http.Request, uuid string) {
	loginDelegates := mud.delegates
	if mud.LoginUserDelegate != nil {
		loginDelegates = mud.LoginUserDelegate(mud.delegates)
	}

	for _, d := range loginDelegates {
		d.LoginUser(r, uuid)
	}
}
