// Copyright 2016 Tamás Demeter-Haludka
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
	"encoding/json"
	"net/http"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
)

func init() {
	ServerSetups = append(ServerSetups, func(cfg *viper.Viper, s *Server) error {
		ec := NewEntityController(s.GetDBConnection())
		ec.Add(&TestEntity{}, nil)
		res := EntityResource(ec, &TestEntity{}, EntityResourceConfig{})
		s.RegisterService(res)

		return nil
	})
}

var _ Entity = &TestEntity{}

type TestEntityJSON struct {
	A int
	B string
}

type TestEntity struct {
	UUID    string `dbtype:"uuid" dbdefault:"uuid_generate_v4()"`
	Mail    string
	Created time.Time `dbdefault:"now()"`
	JS      TestEntityJSON
}

func (t *TestEntity) GetID() string {
	return t.UUID
}

var _ Entity = &simpleEntity{}

type simpleEntity struct {
	UUID    string `dbtype:"uuid" dbdefault:"uuid_generate_v4()"`
	Mail    string
	Created time.Time
	Owner   string `dbtype:"uuid" dbforeign:"user.uuid,owner"`
}

const simpleEntityTable = `CREATE TABLE "simpleentity"(
	"uuid" uuid NOT NULL DEFAULT uuid_generate_v4(),
	"mail" character varying NOT NULL,
	"created" timestamp with time zone NOT NULL,
	"owner" uuid NOT NULL,

	CONSTRAINT simpleentity_uuid_fkey FOREIGN KEY ("owner") REFERENCES "user"("uuid") MATCH SIMPLE ON UPDATE CASCADE ON DELETE CASCADE,
	CONSTRAINT simpleentity_pkey PRIMARY KEY ("uuid")
);
`

func (se *simpleEntity) GetID() string {
	return se.UUID
}

func TestEntityControllerSQL(t *testing.T) {
	Convey("Given an entity controller", t, func() {
		ec := NewEntityController(nil)
		ec.Add(&simpleEntity{}, nil)
		name, data := ec.getData(&simpleEntity{})
		So(name, ShouldEqual, "simpleentity")
		Convey("Schema SQL should match", func() {
			schema := ec.SchemaSQL(&simpleEntity{})
			So(schema, ShouldEqual, simpleEntityTable)
		})
		Convey("Query SQL statements should match", func() {
			So(data.Queries.Select, ShouldEqual, `SELECT s.uuid, s.mail, s.created, s.owner FROM "simpleentity" s WHERE "uuid" = $1`)
			So(data.Queries.Insert, ShouldEqual, `INSERT INTO "simpleentity"("mail", "created", "owner") VALUES($1, $2, $3) RETURNING "uuid"`)
			So(data.Queries.Update, ShouldEqual, `UPDATE "simpleentity" SET "mail" = $1, "created" = $2, "owner" = $3 WHERE "uuid" = $4`)
			So(data.Queries.Delete, ShouldEqual, `DELETE FROM "simpleentity" WHERE "uuid" = $1`)
		})
	})
}

func TestEntityCRUD(t *testing.T) {
	Convey("Given a test entity service", t, func() {
		tc := NewTestClientWithToken(base)

		Convey("It should save an entity", func() {
			t := &TestEntity{
				Mail: "test@example.com",
				JS: TestEntityJSON{
					A: 5,
					B: "asdf",
				},
			}
			tc.Request("POST", "/api/testentity", tc.JSONBuffer(t), nil, func(resp *http.Response) {
				t2 := &TestEntity{}
				tc.ConsumePrefix(resp)
				So(json.NewDecoder(resp.Body).Decode(t2), ShouldBeNil)
				So(t2.UUID, ShouldNotEqual, "")
				So(t2.Created.String(), ShouldNotEqual, "")
				t = t2
			}, http.StatusCreated)

			Convey("It should find the entity", func() {
				tc.Request("GET", "/api/testentity/"+t.UUID, nil, nil, func(resp *http.Response) {
					tc.AssertJSON(resp, &TestEntity{}, t)
				}, http.StatusOK)

				Convey("It should be the only entity in the listing", func() {
					tc.Request("GET", "/api/testentity", nil, nil, func(resp *http.Response) {
						tc.AssertJSON(resp, &[]*TestEntity{}, &[]*TestEntity{t})
					}, http.StatusOK)

					Convey("It should be edited", func() {
						t.Mail = "test2@example.com"
						tc.Request("PUT", "/api/testentity/"+t.UUID, tc.JSONBuffer(t), nil, func(resp *http.Response) {
							tc.AssertJSON(resp, &TestEntity{}, t)
						}, http.StatusOK)

						Convey("The edit should be saved", func() {
							tc.Request("GET", "/api/testentity/"+t.UUID, nil, nil, func(resp *http.Response) {
								tc.AssertJSON(resp, &TestEntity{}, t)
							}, http.StatusOK)

							Convey("It should be deleted", func() {
								tc.Request("DELETE", "/api/testentity/"+t.UUID, nil, nil, nil, http.StatusNoContent)

								Convey("The content listing should be empty", func() {
									tc.Request("GET", "/api/testentity", nil, nil, func(resp *http.Response) {
										tc.AssertJSON(resp, &[]*TestEntity{}, &[]*TestEntity{})
									}, http.StatusOK)
								})
							})
						})
					})
				})
			})
		})
	})
}
